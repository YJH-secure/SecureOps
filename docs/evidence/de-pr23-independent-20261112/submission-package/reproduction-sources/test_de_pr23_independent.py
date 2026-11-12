"""D-owned assertions using E's existing fixture, adapter and public stores."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core.main import DiagnosisAggregator
from core.storage import ReportStore
from remediation import ExecutionHistoryStore
from remediation.__main__ import _run_demo
import test_remediation_execution_history as e_cases

RECORDS = []


class DIndependentEReview(unittest.TestCase):
    def scenario(self):
        case = e_cases.ExecutionHistoryTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        for name in ("subprocess.Popen", "os.system", "socket.socket"):
            guard = patch(name, side_effect=AssertionError("Real process/network forbidden"))
            blocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(blocked.assert_not_called)
        return case

    def preserve(self, label, case, result, before_bytes):
        path = case.store._path(case.before["scan_id"])
        self.assertEqual(path.read_bytes(), before_bytes)
        self.assertEqual(case.before, case.store.load(case.before["target_id"], case.before["scan_id"]))
        self.assertEqual(result["before_scan_id"], case.before["scan_id"])
        self.assertEqual(result["plan_id"], case.plan.plan_id)
        self.assertEqual(result["schema_version"], "1.0")
        self.assertEqual(result["diagnosis_schema_version"], "1.2")
        self.assertEqual(result["approval_id"], case.approval.approval_id if result["approval"] else None)
        reports = case.store.history(case.before["target_id"])
        for report in reports:
            self.assertEqual(report["schema_version"], "1.2")
            self.assertNotIn("execution_id", report)
            self.assertEqual(report["target_id"], result["target_id"])
            for item in report["results"]:
                self.assertEqual(item["check_id"], "SSH-01")
                self.assertIsNone(item["cvss"]["base_score"])
        RECORDS.append({"case": label, "e_execution": copy.deepcopy(result),
                        "d_reports": copy.deepcopy(reports), "before_bytes_preserved": True,
                        "summaries": [DiagnosisAggregator.from_results(r["results"], [], target_id=r["target_id"],
                            os=r["os"], scan_id=r["scan_id"], scanned_at=r["scanned_at"], schema_version=r["schema_version"]).aggregate_results()
                            for r in reports]})

    def test_plan_approval_callback_and_history_links(self):
        case = self.scenario()
        before_bytes = case.store._path(case.before["scan_id"]).read_bytes()
        result = case.run_mock()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["approval_id"], case.approval.approval_id)
        self.assertNotEqual(result["before_scan_id"], result["after_scan_id"])
        self.assertEqual(result["after_scan_id"], result["after_report"]["scan_id"])
        attempt = result["recheck_attempts"][0]
        self.assertEqual(attempt["execution_id"], result["execution_id"])
        self.assertEqual((attempt["save_status"], attempt["load_status"]), ("success", "success"))
        self.assertTrue(attempt["report_verified"])
        self.assertEqual(result["final_security_status"], "pass")
        self.assertTrue(result["final_security_verified"])
        self.preserve("success", case, result, before_bytes)

    def test_denial_and_dry_run_do_not_diagnose(self):
        for label, options in (("denied", {"approval": None}), ("dry-run", {"dry_run": True})):
            with self.subTest(case=label):
                case = self.scenario()
                original = case.store._path(case.before["scan_id"]).read_bytes()
                result = case.run_mock(**options)
                self.assertIn(result["outcome"], {"rejected", "planned"})
                self.assertIsNone(result["approval_id"])
                self.assertEqual(result["recheck_attempts"], [])
                self.assertEqual(case.calls, [])
                self.preserve(label, case, result, original)

    def test_rollback_without_new_diagnosis_remains_unknown(self):
        case = self.scenario()
        original = case.store._path(case.before["scan_id"]).read_bytes()
        case.outputs = ["vulnerable"]
        result = case.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertIsNone(result["post_rollback_scan_id"])
        self.assertIsNone(result["final_security_status"])
        self.assertFalse(result["final_security_verified"])
        self.preserve("rollback-unknown", case, result, original)

    def test_post_rollback_fresh_scan_does_not_erase_action_failure(self):
        case = self.scenario()
        original = case.store._path(case.before["scan_id"]).read_bytes()
        case.outputs = ["vulnerable", "pass"]
        result = case.run_mock(post_rollback_recheck=True)
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(len({result[k] for k in ("before_scan_id", "after_scan_id", "post_rollback_scan_id")}), 3)
        self.assertEqual(result["post_rollback_scan_id"], result["post_rollback_report"]["scan_id"])
        self.assertEqual(result["final_security_status"], "pass")
        self.assertTrue(result["final_security_verified"])
        self.assertTrue(all(a["execution_id"] == result["execution_id"] for a in result["recheck_attempts"]))
        self.preserve("post-rollback-pass-action-failed", case, result, original)

    def test_save_success_load_failure_retains_after_id_and_unknown_state(self):
        case = self.scenario()
        original = case.store._path(case.before["scan_id"]).read_bytes()
        with patch.object(case.store, "load", side_effect=OSError("MOCK temporary read failure")):
            result = case.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertIsNotNone(result["after_scan_id"])
        attempt = result["recheck_attempts"][0]
        self.assertEqual((attempt["save_status"], attempt["load_status"]), ("success", "failed"))
        self.assertEqual(attempt["failure_stage"], "load")
        later = case.store.load(result["target_id"], result["after_scan_id"])
        self.assertEqual(later["results"][0]["status"], "pass")
        self.assertIsNone(result["final_security_status"])
        self.assertFalse(result["final_security_verified"])
        self.preserve("saved-but-load-failed", case, result, original)

    def test_post_rollback_load_failure_preserves_link_without_security_claim(self):
        case = self.scenario()
        original = case.store._path(case.before["scan_id"]).read_bytes()
        case.outputs = ["vulnerable"]
        load = case.store.load
        calls = []
        def fail_second(target, scan):
            calls.append(scan)
            if len(calls) == 2:
                raise OSError("MOCK second read failure")
            return load(target, scan)
        with patch.object(case.store, "load", side_effect=fail_second):
            result = case.run_mock(post_rollback_recheck=True)
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["post_rollback_scan_id"], calls[-1])
        self.assertEqual(result["recheck_attempts"][-1]["load_status"], "failed")
        self.assertIsNone(result["final_security_status"])
        self.assertFalse(result["final_security_verified"])
        self.assertEqual(case.store.load(result["target_id"], result["post_rollback_scan_id"])["scan_id"], calls[-1])
        self.preserve("post-rollback-load-failed", case, result, original)

    def test_e_history_and_d_reports_use_distinct_versions_and_stores(self):
        for version in ("1.1", "1.2"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as folder:
                result = _run_demo(dry_run=False, fail_at=None, deny=False, skip=False, result_version=version)
                self.assertEqual(result["schema_version"], "1.0")
                self.assertEqual(result["diagnosis_schema_version"], version)
                report = result["after_report"]
                self.assertEqual(report["schema_version"], version)
                d_store = ReportStore(Path(folder) / "d")
                e_store = ExecutionHistoryStore(Path(folder) / "e")
                d_store.save(report)
                self.assertEqual(d_store.load(report["target_id"], report["scan_id"]), report)
                e_store.save(result)
                self.assertEqual(ExecutionHistoryStore(Path(folder) / "e").load(result["execution_id"]), result)
                with self.assertRaises(ValueError):
                    e_store.save(report)
                with self.assertRaises((KeyError, ValueError)):
                    d_store.save(result)
                RECORDS.append({"case": "version-" + version, "e_execution": result,
                                "d_reports": [report], "before_bytes_preserved": None})

    def test_both_execution_and_scan_duplicates_preserve_originals(self):
        case = self.scenario()
        original = case.store._path(case.before["scan_id"]).read_bytes()
        result = case.run_mock()
        with tempfile.TemporaryDirectory() as folder:
            history = ExecutionHistoryStore(folder)
            path = history.save(result)
            raw = path.read_bytes()
            with self.assertRaises(FileExistsError):
                history.save(result)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(history.load(result["execution_id"]), result)
        with self.assertRaises(FileExistsError):
            case.store.save(case.before)
        self.assertEqual(case.store._path(case.before["scan_id"]).read_bytes(), original)
