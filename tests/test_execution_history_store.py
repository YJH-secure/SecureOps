"""E 실행 이력의 독립 영속 조회·중복 거부·오류 처리를 임시 디렉터리에서 검증."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from remediation import ExecutionHistoryStore
from remediation.__main__ import _run_demo
import test_remediation_execution_history as execution_scenarios


class ExecutionHistoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="secureops-e-history-store-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = ExecutionHistoryStore(self.root)
        self.result = self.demo()

    @staticmethod
    def demo(**kwargs):
        options = dict(dry_run=False, fail_at=None, deny=False, skip=False, result_version="1.2")
        options.update(kwargs)
        return _run_demo(**options)

    def test_new_instance_loads_completed_execution(self):
        original = deepcopy(self.result)
        path = self.store.save(self.result)
        self.assertTrue(path.is_file())
        del self.store
        loaded = ExecutionHistoryStore(self.root).load(self.result["execution_id"])
        self.assertEqual(loaded, original)
        self.assertEqual(self.result, original)

    def test_new_python_process_loads_by_execution_id(self):
        self.store.save(self.result)
        code = "import json,sys; from remediation import ExecutionHistoryStore; print(json.dumps(ExecutionHistoryStore(sys.argv[1]).load(sys.argv[2])))"
        output = subprocess.check_output([sys.executable, "-B", "-c", code,
                                          str(self.root), self.result["execution_id"]],
                                         cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(json.loads(output), self.result)

    def test_duplicate_execution_does_not_overwrite(self):
        path = self.store.save(self.result)
        raw = path.read_bytes()
        changed = deepcopy(self.result)
        changed["outcome"] = "failed"
        with self.assertRaises(FileExistsError):
            self.store.save(changed)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(self.store.load(self.result["execution_id"]), self.result)
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_concurrent_duplicate_has_exactly_one_winner(self):
        def save():
            try:
                ExecutionHistoryStore(self.root).save(self.result)
                return "saved"
            except FileExistsError:
                return "duplicate"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: save(), range(2)))
        self.assertCountEqual(outcomes, ["saved", "duplicate"])
        self.assertEqual(self.store.load(self.result["execution_id"]), self.result)

    def test_failed_rejected_skipped_and_rollback_results_are_preserved(self):
        cases = [dict(fail_at="apply"), dict(fail_at="verify_service"),
                 dict(fail_at="backup"), dict(fail_at="recheck"),
                 dict(deny=True), dict(skip=True), dict(dry_run=True)]
        for options in cases:
            with self.subTest(options=options):
                result = self.demo(**options)
                self.store.save(result)
                loaded = ExecutionHistoryStore(self.root).load(result["execution_id"])
                self.assertEqual(loaded, json.loads(json.dumps(result)))
                self.assertEqual(loaded["rollback"], result["rollback"])
                self.assertEqual(loaded["final_security_verified"], result["final_security_verified"])

    def test_saved_record_and_loaded_records_are_independent_snapshots(self):
        original = deepcopy(self.result)
        self.store.save(self.result)
        self.result["outcome"] = "failed"
        loaded = self.store.load(original["execution_id"])
        loaded["completed_steps"].clear()
        self.assertEqual(self.store.load(original["execution_id"]), original)

    def test_missing_record_is_reported(self):
        with self.assertRaises(FileNotFoundError):
            self.store.load(str(uuid4()))

    def test_invalid_execution_ids_are_rejected(self):
        for invalid in (None, "", "  ", 42):
            with self.subTest(value=invalid):
                with self.assertRaises(ValueError):
                    self.store.load(invalid)

    def test_malformed_saved_json_is_rejected(self):
        path = self.store.save(self.result)
        path.write_text("{not-json", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.load(self.result["execution_id"])

    def test_mismatched_saved_execution_id_is_rejected(self):
        path = self.store.save(self.result)
        changed = deepcopy(self.result)
        changed["execution_id"] = str(uuid4())
        path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.load(self.result["execution_id"])

    def test_duplicate_json_keys_are_rejected(self):
        path = self.store.save(self.result)
        text = json.dumps(self.result)
        text = text.replace('"execution_id":', '"execution_id": "other", "execution_id":', 1)
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.load(self.result["execution_id"])

    def test_publish_io_failure_does_not_change_execution_result(self):
        original = deepcopy(self.result)
        with patch("remediation.history.os.link", side_effect=PermissionError("MOCK: denied")):
            with self.assertRaises(PermissionError):
                self.store.save(self.result)
        self.assertEqual(self.result, original)
        self.assertEqual(self.result["outcome"], "success")
        self.assertEqual(list(self.root.iterdir()), [])
        with self.assertRaises(FileNotFoundError):
            self.store.load(self.result["execution_id"])

    def test_temporary_write_open_failure_is_reported(self):
        with patch("remediation.history.tempfile.NamedTemporaryFile", side_effect=OSError("MOCK: disk unavailable")):
            with self.assertRaises(OSError):
                self.store.save(self.result)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_read_io_failure_is_reported_without_mutating_saved_record(self):
        self.store.save(self.result)
        with patch("remediation.history.Path.read_text", side_effect=PermissionError("MOCK: read denied")):
            with self.assertRaises(PermissionError):
                self.store.load(self.result["execution_id"])
        self.assertEqual(self.store.load(self.result["execution_id"]), self.result)

    def test_non_json_and_invalid_execution_records_are_not_saved(self):
        for change in ({"extra": float("nan")}, {"extra": {1, 2}},
                       {"outcome": "unknown"}, {"rollback": "unknown"}, {"after_scan_id": 1}):
            with self.subTest(change=str(change)):
                record = dict(self.result, **change)
                with self.assertRaises((ValueError, TypeError)):
                    self.store.save(record)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_d_report_is_not_accepted_as_execution_history(self):
        with self.assertRaises(ValueError):
            self.store.save(self.result["after_report"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_execution_id_cannot_escape_history_directory(self):
        record = deepcopy(self.result)
        record["execution_id"] = "../outside-history-MOCK"
        path = self.store.save(record)
        self.assertEqual(path.parent, self.root)
        self.assertEqual(self.store.load(record["execution_id"]), record)

    def test_d_load_failure_scan_link_survives_new_history_store_instance(self):
        scenario = execution_scenarios.ExecutionHistoryTests()
        scenario.setUp()
        self.addCleanup(scenario.doCleanups)
        with patch.object(scenario.store, "load", side_effect=OSError("MOCK: load unavailable")):
            result = scenario.run_mock()
        self.store.save(result)
        loaded = ExecutionHistoryStore(self.root).load(result["execution_id"])
        self.assertEqual(loaded["outcome"], "failed")
        self.assertEqual(loaded["rollback"], "verified")
        self.assertEqual(loaded["recheck_attempts"][0]["save_status"], "success")
        self.assertEqual(loaded["recheck_attempts"][0]["load_status"], "failed")
        diagnosis = scenario.store.load(loaded["target_id"], loaded["after_scan_id"])
        self.assertEqual(diagnosis["results"][0]["status"], "pass")
        self.assertIsNone(loaded["final_security_status"])
        self.assertFalse(loaded["final_security_verified"])


if __name__ == "__main__":
    unittest.main()
