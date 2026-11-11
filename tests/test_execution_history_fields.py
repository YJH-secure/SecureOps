"""승인된 최상위 승인 ID·시각의 정상 반환 경로와 저장 호환성 검증."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
import unittest

from remediation import ExecutionHistoryStore
from remediation.__main__ import _run_demo
import test_remediation_execution_history as scenarios


class ExecutionHistoryFieldTests(unittest.TestCase):
    @staticmethod
    def demo(**kwargs):
        options = dict(dry_run=False, fail_at=None, deny=False, skip=False, result_version="1.2")
        options.update(kwargs)
        return _run_demo(**options)

    def assert_times(self, result):
        start = datetime.fromisoformat(result["started_at"])
        finish = datetime.fromisoformat(result["finished_at"])
        self.assertIsNotNone(start.utcoffset())
        self.assertIsNotNone(finish.utcoffset())
        self.assertLessEqual(start, finish)

    def test_metadata_on_every_normal_return(self):
        cases = [dict(), dict(dry_run=True), dict(deny=True), dict(skip=True)]
        cases += [dict(fail_at=stage) for stage in ("backup", "apply", "validate", "recheck", "verify_service")]
        for options in cases:
            with self.subTest(options=options):
                result = self.demo(**options)
                self.assert_times(result)
                expected = result["approval"]["approval_id"] if result["approval"] else None
                self.assertEqual(result["approval_id"], expected)
                if result["outcome"] in {"planned", "rejected", "skipped"}:
                    self.assertIsNone(result["approval_id"])

    def test_unverified_approval_id_is_null(self):
        case = scenarios.ExecutionHistoryTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        result = case.run_mock(approval=None)
        self.assertEqual(result["outcome"], "rejected")
        self.assertIsNone(result["approval_id"])
        self.assert_times(result)
        case.engine.verify_approval = lambda approval: False
        result = case.run_mock()
        self.assertIsNone(result["approval_id"])
        self.assert_times(result)
        def fail(approval):
            raise RuntimeError("MOCK: approval lookup failed")
        case.engine.verify_approval = fail
        result = case.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertIsNone(result["approval_id"])
        self.assert_times(result)

    def test_audit_time_is_independent_from_approval_clock(self):
        case = scenarios.ExecutionHistoryTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        approval_clock = datetime(2000, 1, 1, tzinfo=timezone.utc)
        result = case.run_mock(now=approval_clock)
        self.assert_times(result)
        self.assertNotEqual(datetime.fromisoformat(result["started_at"]), approval_clock)
        self.assertEqual(result["approval_id"], case.approval.approval_id)

    def test_fields_do_not_modify_diagnosis_contracts(self):
        for version in ("1.1", "1.2"):
            with self.subTest(version=version):
                result = self.demo(result_version=version)
                self.assertEqual(result["after_report"]["schema_version"], version)
                self.assertNotIn("schema_version", result)
                for key in ("approval_id", "started_at", "finished_at"):
                    self.assertIn(key, result)
                    self.assertNotIn(key, result["after_report"])

    def test_store_round_trip_preserves_metadata(self):
        with TemporaryDirectory(prefix="secureops-e-fields-") as directory:
            for options in ({}, {"deny": True}, {"fail_at": "apply"}, {"dry_run": True}):
                result = self.demo(**options)
                ExecutionHistoryStore(directory).save(result)
                loaded = ExecutionHistoryStore(directory).load(result["execution_id"])
                for key in ("approval_id", "started_at", "finished_at"):
                    self.assertEqual(loaded[key], result[key])
                self.assert_times(loaded)

    def test_legacy_stored_records_remain_readable(self):
        record = self.demo()
        for key in ("approval_id", "started_at", "finished_at"):
            del record[key]
        with TemporaryDirectory(prefix="secureops-e-legacy-") as directory:
            ExecutionHistoryStore(directory).save(record)
            loaded = ExecutionHistoryStore(directory).load(record["execution_id"])
            self.assertEqual(loaded, record)
            self.assertNotIn("started_at", loaded)
            self.assertNotIn("approval_id", loaded)

    def test_bad_or_incomplete_times_are_rejected(self):
        original = self.demo()
        for change in ({"started_at": "2026-11-11T00:00:00"}, {"finished_at": None},
                       {"started_at": None}, {"finished_at": "2000-01-01T00:00:00Z"}):
            with self.subTest(change=change), TemporaryDirectory(prefix="secureops-e-invalid-time-") as directory:
                with self.assertRaises(ValueError):
                    ExecutionHistoryStore(directory).save(dict(original, **change))
        with TemporaryDirectory(prefix="secureops-e-incomplete-time-") as directory:
            record = deepcopy(original)
            del record["finished_at"]
            with self.assertRaises(ValueError):
                ExecutionHistoryStore(directory).save(record)

    def test_mismatched_top_level_approval_id_is_rejected(self):
        for value in ("unverified-MOCK", None):
            with self.subTest(value=value), TemporaryDirectory(prefix="secureops-e-approval-id-") as directory:
                record = self.demo()
                record["approval_id"] = value
                with self.assertRaises(ValueError):
                    ExecutionHistoryStore(directory).save(record)

    def test_schema_version_is_not_inferred(self):
        record = self.demo()
        self.assertNotIn("schema_version", record)
        with TemporaryDirectory(prefix="secureops-e-deferred-version-") as directory:
            record["schema_version"] = "1.2"
            with self.assertRaises(ValueError):
                ExecutionHistoryStore(directory).save(record)

    def test_different_valid_timezones_compare_correctly(self):
        record = self.demo()
        local_zone = timezone(timedelta(hours=9))
        record["started_at"] = datetime.fromisoformat(record["started_at"]).astimezone(local_zone).isoformat()
        with TemporaryDirectory(prefix="secureops-e-timezones-") as directory:
            ExecutionHistoryStore(directory).save(record)
            loaded = ExecutionHistoryStore(directory).load(record["execution_id"])
            self.assert_times(loaded)
            self.assertEqual(loaded["started_at"], record["started_at"])


if __name__ == "__main__":
    unittest.main()
