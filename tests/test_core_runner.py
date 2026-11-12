import copy
from functools import partial
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from core.runner import RunFailed, run_target
from core.storage import ReportStore


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.account = {"check_id": "SSH-01", "status": "vulnerable", "severity": "high",
                        "evidence": "MOCK: root login", "recommendation": "MOCK: review"}
        self.system = {"check_id": "FILE-01", "status": "needs_review", "severity": "high",
                       "evidence": "MOCK: pending", "recommendation": "MOCK: policy review",
                       "details": {"files": [{"path": "/etc/shadow", "mode": "0640"}]}}

    def run_mock(self, **overrides):
        arguments = dict(account_checks=[lambda: self.account], system_checks=[lambda: self.system],
                         target_id="mock-server", os="ubuntu-24.04", output_root=self.root,
                         mode="mock", scan_id="mock-run", scanned_at="2026-11-09T10:00:00+09:00")
        return run_target(**{**arguments, **overrides})

    def test_success_saved_and_separated(self):
        result = self.run_mock()
        self.assertEqual(result.mode, "mock")
        self.assertEqual(result.path.parent, self.root / "mock")
        self.assertEqual(result.report["results"], [self.account, self.system])
        self.assertNotIn("mode", result.report)
        self.assertEqual(result.summary["metrics"]["pass_rate"], "0.0%")
        self.assertEqual(ReportStore(self.root / "mock").load("mock-server", "mock-run"), result.report)
        self.assertFalse((self.root / "real").exists())

    def test_original_preservation(self):
        original = copy.deepcopy([self.account, self.system])
        result = self.run_mock()
        self.assertEqual([self.account, self.system], original)
        result.report["results"][1]["details"]["files"].clear()
        self.assertEqual([self.account, self.system], original)
        saved = ReportStore(self.root / "mock").load("mock-server", "mock-run")
        self.assertEqual(saved["results"], original)

    def test_partial_failure_on_either_area(self):
        for area in ("account_checks", "system_checks"):
            cause = TimeoutError("MOCK: timed out")
            with self.subTest(area=area), self.assertRaises(RunFailed) as caught:
                self.run_mock(**{area: [Mock(side_effect=cause)]})
            self.assertIs(caught.exception.failures[0].cause, cause)
            successful = "system" if area == "account_checks" else "account"
            self.assertEqual(len(caught.exception.partial_results[successful]), 1)
            self.assertFalse((self.root / "mock").exists())

    def test_failure_does_not_skip_later_calls(self):
        later = Mock(return_value=self.account)
        with self.assertRaises(RunFailed) as caught:
            self.run_mock(account_checks=[Mock(side_effect=RuntimeError("secret raw message")), later])
        later.assert_called_once_with()
        self.assertEqual(len(caught.exception.partial_results["account"]), 1)
        self.assertNotIn("secret raw message", str(caught.exception))

    def test_invalid_return_values(self):
        for value in (None, [], "result", {}, {**self.account, "status": "PASS"},
                      {**self.account, "details": []}):
            with self.subTest(value=value), self.assertRaises(RunFailed):
                self.run_mock(account_checks=[Mock(return_value=value)])
        self.assertFalse((self.root / "mock").exists())

    def test_duplicate_rejected_without_save(self):
        self.system["check_id"] = "SSH-01"
        with self.assertRaisesRegex(ValueError, "중복 check_id"):
            self.run_mock()
        self.assertFalse((self.root / "mock").exists())

    def test_error_status_preserved(self):
        self.account["status"] = "error"
        result = self.run_mock()
        self.assertEqual([r["status"] for r in result.report["results"]], ["error", "needs_review"])
        self.assertEqual(result.summary["metrics"]["pass_count"], 0)
        self.assertEqual(result.summary["metrics"]["pass_rate"], "N/A (계산 불가)")

    def test_storage_failure_propagated(self):
        cause = OSError("MOCK: disk failure")
        with patch("core.runner.ReportStore.save", side_effect=cause):
            with self.assertRaises(OSError) as caught:
                self.run_mock()
        self.assertIs(caught.exception, cause)
        self.assertEqual(list((self.root / "mock").glob("*.json")), [])

    def test_duplicate_scan_preserves_saved_report(self):
        first = self.run_mock()
        original = first.path.read_bytes()
        with self.assertRaises(FileExistsError):
            self.run_mock()
        self.assertEqual(first.path.read_bytes(), original)

    def test_real_and_invalid_configuration_rejected_before_calls(self):
        callback = Mock(return_value=self.account)
        for overrides in ({"mode": "real"}, {"target_id": None}, {"os": ""},
                          {"scanned_at": "2026-11-09T10:00:00"}, {"scan_id": ""},
                          {"system_checks": [None]}, {"system_checks": {}}):
            with self.subTest(overrides=overrides), self.assertRaises((ValueError, TypeError)):
                self.run_mock(account_checks=[callback], **overrides)
        callback.assert_not_called()

    def test_empty_and_single_area(self):
        with self.assertRaises(ValueError):
            self.run_mock(account_checks=[], system_checks=[])
        result = self.run_mock(system_checks=[])
        self.assertEqual(result.report["results"], [self.account])

    def test_bound_arguments_and_new_execution_ids(self):
        def supplied_function(prefix, *, result):
            self.assertEqual(prefix, "MOCK")
            return result
        callback = partial(supplied_function, "MOCK", result=self.account)
        first = self.run_mock(account_checks=[callback], scan_id=None, scanned_at=None)
        second = self.run_mock(scan_id=None, scanned_at=None)
        self.assertNotEqual(first.report["scan_id"], second.report["scan_id"])
        self.assertNotEqual(first.path, second.path)


if __name__ == "__main__":
    unittest.main()
