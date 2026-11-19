"""E 이력 1.0과 실제 D 진단 1.1/1.2의 분리·저장·과거 기록 호환성 검증."""

from copy import deepcopy
import json
from tempfile import TemporaryDirectory
import unittest

from remediation import ExecutionHistoryStore
from remediation.__main__ import _run_demo
from remediation.contract import validate_report


class ExecutionHistoryVersionTests(unittest.TestCase):
    @staticmethod
    def demo(version="1.2", **kwargs):
        options = dict(dry_run=False, fail_at=None, deny=False, skip=False, result_version=version)
        options.update(kwargs)
        return _run_demo(**options)

    def test_actual_d_input_version_is_used_for_both_supported_versions(self):
        for version in ("1.1", "1.2"):
            with self.subTest(version=version):
                result = self.demo(version)
                self.assertEqual(result["schema_version"], "1.0")
                self.assertEqual(result["diagnosis_schema_version"], version)
                self.assertEqual(result["after_report"]["schema_version"], version)
                validate_report(result["after_report"])
                self.assertNotIn("diagnosis_schema_version", result["after_report"])
                self.assertNotIn("execution_id", result["after_report"])

    def test_versions_are_recorded_on_every_normal_outcome(self):
        for version in ("1.1", "1.2"):
            for options in ({"dry_run": True}, {"deny": True}, {"skip": True},
                            {"fail_at": "backup"}, {"fail_at": "apply"}, {"fail_at": "recheck"}):
                with self.subTest(version=version, options=options):
                    result = self.demo(version, **options)
                    self.assertEqual(result["schema_version"], "1.0")
                    self.assertEqual(result["diagnosis_schema_version"], version)

    def test_new_history_versions_round_trip_without_changing_input(self):
        with TemporaryDirectory(prefix="secureops-e-version-") as directory:
            for version in ("1.1", "1.2"):
                result = self.demo(version)
                original = deepcopy(result)
                ExecutionHistoryStore(directory).save(result)
                loaded = ExecutionHistoryStore(directory).load(result["execution_id"])
                self.assertEqual(loaded, original)
                self.assertEqual(result, original)

    def test_legacy_record_without_versions_is_loaded_without_rewrite(self):
        record = self.demo()
        del record["schema_version"]
        del record["diagnosis_schema_version"]
        with TemporaryDirectory(prefix="secureops-e-legacy-version-") as directory:
            path = ExecutionHistoryStore(directory).save(record)
            raw = path.read_bytes()
            loaded = ExecutionHistoryStore(directory).load(record["execution_id"])
            self.assertEqual(loaded, record)
            self.assertNotIn("schema_version", loaded)
            self.assertNotIn("diagnosis_schema_version", loaded)
            self.assertEqual(path.read_bytes(), raw)

    def test_invalid_execution_version_values_and_types_are_rejected(self):
        for value in (None, True, 1.0, [], {}, "", "1.1", "1.2", "2.0"):
            with self.subTest(value=value), TemporaryDirectory(prefix="secureops-e-invalid-version-") as directory:
                record = self.demo()
                record["schema_version"] = value
                with self.assertRaises((ValueError, TypeError)):
                    ExecutionHistoryStore(directory).save(record)

    def test_invalid_diagnosis_version_values_and_types_are_rejected(self):
        for value in (None, False, 1.2, [], {}, "", "1.0", "2.0"):
            with self.subTest(value=value), TemporaryDirectory(prefix="secureops-e-invalid-d-version-") as directory:
                record = self.demo()
                record["diagnosis_schema_version"] = value
                with self.assertRaises((ValueError, TypeError)):
                    ExecutionHistoryStore(directory).save(record)

    def test_partial_version_pair_is_rejected(self):
        for key in ("schema_version", "diagnosis_schema_version"):
            with self.subTest(key=key), TemporaryDirectory(prefix="secureops-e-partial-version-") as directory:
                record = self.demo()
                del record[key]
                with self.assertRaises(ValueError):
                    ExecutionHistoryStore(directory).save(record)

    def test_d_diagnosis_reports_are_still_rejected(self):
        for version in ("1.1", "1.2"):
            with self.subTest(version=version), TemporaryDirectory(prefix="secureops-e-not-d-report-") as directory:
                report = self.demo(version)["after_report"]
                validate_report(report)
                with self.assertRaises(ValueError):
                    ExecutionHistoryStore(directory).save(report)

    def test_corrupted_stored_versions_are_rejected_on_load(self):
        for change in ({"schema_version": "1.2"}, {"diagnosis_schema_version": None}):
            with self.subTest(change=change), TemporaryDirectory(prefix="secureops-e-corrupt-version-") as directory:
                record = self.demo()
                store = ExecutionHistoryStore(directory)
                path = store.save(record)
                changed = dict(record, **change)
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises((ValueError, TypeError)):
                    ExecutionHistoryStore(directory).load(record["execution_id"])

    def test_diagnosis_snapshot_cannot_disagree_with_diagnosis_version(self):
        record = self.demo("1.2")
        record["diagnosis_schema_version"] = "1.1"
        with TemporaryDirectory(prefix="secureops-e-snapshot-version-") as directory:
            with self.assertRaises(ValueError):
                ExecutionHistoryStore(directory).save(record)


if __name__ == "__main__":
    unittest.main()
