"""E 실행 ID와 D scan_id 연결, 저장·조회 실패 및 복구 후 최종 보안 상태 검증."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from core.main import DiagnosisAggregator
from core.storage import ReportStore
from remediation import Approval, MockBackend, Remediator, build_plan
from remediation.recheck import MockRecheckAdapter
from test_remediation_execution_integration import synthetic_result


class ExecutionHistoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="secureops-history-mock-")
        self.addCleanup(self.directory.cleanup)
        self.store = ReportStore(self.directory.name)
        self.before = DiagnosisAggregator.from_results(
            [synthetic_result("SSH-01", "vulnerable")], [], target_id="history-MOCK",
            os="ubuntu-24.04", schema_version="1.2", scanned_at="2026-11-01T00:00:00Z",
        ).get_report()
        self.store.save(self.before)
        self.plan = build_plan(self.before, "SSH-01")
        self.approval = Approval("history-approval", "admin-MOCK", self.plan.target_id,
                                self.plan.scan_id, self.plan.plan_id, "2099-01-01T00:00:00Z", True)
        self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={"SSH-01"},
                                verify_approval=lambda approval: approval == self.approval)
        self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os, files={},
                                   access_verified=True, snapshot_verified=True, include_verified=True)
        self.calls = []
        self.outputs = []
        self.transform = None
        self.adapter = MockRecheckAdapter(self.diagnose, self.store)

    def diagnose(self, request, state):
        self.calls.append(deepcopy(request))
        status = self.outputs.pop(0) if self.outputs else ("pass" if state["root_login"] == "no" else "vulnerable")
        report = DiagnosisAggregator.from_results(
            [synthetic_result("SSH-01", status)], [], target_id=request["target_id"],
            os=request["os"], schema_version=request["schema_version"],
        ).get_report()
        if self.transform:
            self.transform(report)
        return report

    def run_mock(self, **kwargs):
        options = dict(backend=self.backend, approval=self.approval, dry_run=False,
                       recheck_adapter=self.adapter)
        options.update(kwargs)
        return self.engine.run(self.before, self.plan, **options)

    def test_success_links_report_scan_id_not_save_path(self):
        original_save = self.store.save
        paths = []
        def save(report):
            path = original_save(report)
            paths.append(path)
            return path
        with patch.object(self.store, "save", side_effect=save):
            result = self.run_mock()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["before_scan_id"], self.before["scan_id"])
        self.assertEqual(result["after_scan_id"], result["after_report"]["scan_id"])
        self.assertNotEqual(result["after_scan_id"], str(paths[0]))
        self.assertIsInstance(paths[0], Path)
        attempt = result["recheck_attempts"][0]
        self.assertEqual(attempt["execution_id"], result["execution_id"])
        self.assertEqual(attempt["scan_id"], result["after_scan_id"])
        self.assertEqual((attempt["save_status"], attempt["load_status"]), ("success", "success"))
        self.assertTrue(attempt["report_verified"])
        self.assertEqual(result["final_security_status"], "pass")
        self.assertTrue(result["final_security_verified"])
        self.assertNotIn("rollback_status", result)
        json.dumps(result, allow_nan=False)

    def test_scan_id_is_retained_when_save_raises(self):
        with patch.object(self.store, "save", side_effect=OSError("MOCK: private path failure")):
            result = self.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertIsNotNone(result["after_scan_id"])
        attempt = result["recheck_attempts"][0]
        self.assertEqual((attempt["save_status"], attempt["load_status"]), ("failed", "not_attempted"))
        self.assertEqual(attempt["failure_stage"], "save")
        self.assertNotIn("private path", json.dumps(result))
        self.assertEqual(result["rollback"], "verified")
        self.assertFalse(result["final_security_verified"])

    def test_saved_report_can_be_loaded_by_same_id_after_load_failure(self):
        with patch.object(self.store, "load", side_effect=OSError("MOCK: temporary load failure")):
            result = self.run_mock()
        attempt = result["recheck_attempts"][0]
        self.assertEqual((attempt["save_status"], attempt["load_status"]), ("success", "failed"))
        loaded = self.store.load(result["target_id"], result["after_scan_id"])
        self.assertEqual(loaded["scan_id"], result["after_scan_id"])
        self.assertEqual(loaded["results"][0]["status"], "pass")
        # 이 pass는 복구 전 진단이다. 나중에 읽어도 복구 후 상태로 승격하지 않는다.
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertIsNone(result["final_security_status"])
        self.assertFalse(result["final_security_verified"])
        self.assertIsNone(result["post_rollback_scan_id"])

    def test_rollback_without_security_recheck_remains_unknown(self):
        for status in ("vulnerable", "error", "needs_review"):
            with self.subTest(status=status):
                self.setUp()
                self.outputs = [status]
                result = self.run_mock()
                self.assertEqual(result["rollback"], "verified")
                self.assertIsNotNone(result["after_scan_id"])
                self.assertIsNone(result["final_security_status"])
                self.assertFalse(result["final_security_verified"])
                self.assertIsNone(result["post_rollback_scan_id"])
                self.assertEqual(len(self.calls), 1)

    def test_post_rollback_diagnosis_uses_fresh_id_and_detects_vulnerability(self):
        self.outputs = ["vulnerable"]
        result = self.run_mock(post_rollback_recheck=True)
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertEqual(len({result["before_scan_id"], result["after_scan_id"], result["post_rollback_scan_id"]}), 3)
        self.assertEqual(result["post_rollback_scan_id"], result["post_rollback_report"]["scan_id"])
        self.assertEqual(result["final_security_status"], "vulnerable")
        self.assertTrue(result["final_security_verified"])
        self.assertEqual([a["phase"] for a in result["recheck_attempts"]], ["after", "post_rollback"])
        self.assertTrue(all(a["execution_id"] == result["execution_id"] for a in result["recheck_attempts"]))
        self.assertEqual(len(self.store.history(result["target_id"])), 3)
        matched = self.store.match_results(result["target_id"], result["after_scan_id"], result["post_rollback_scan_id"])
        self.assertEqual(matched["SSH-01"]["after"]["status"], "vulnerable")

    def test_post_rollback_pass_does_not_turn_failed_action_into_success(self):
        # 합성 시나리오: 복구 후 별도 진단에서 pass. 원래 조치 실패는 유지한다.
        self.outputs = ["vulnerable", "pass"]
        result = self.run_mock(post_rollback_recheck=True)
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["final_security_status"], "pass")
        self.assertTrue(result["final_security_verified"])

    def test_post_rollback_load_failure_keeps_post_scan_id(self):
        self.outputs = ["vulnerable"]
        load = self.store.load
        calls = []
        def flaky(target_id, scan_id):
            calls.append(scan_id)
            if len(calls) == 2:
                raise OSError("MOCK: second load failed")
            return load(target_id, scan_id)
        with patch.object(self.store, "load", side_effect=flaky):
            result = self.run_mock(post_rollback_recheck=True)
        attempt = result["recheck_attempts"][-1]
        self.assertEqual(attempt["phase"], "post_rollback")
        self.assertEqual((attempt["save_status"], attempt["load_status"]), ("success", "failed"))
        self.assertEqual(self.store.load(result["target_id"], result["post_rollback_scan_id"])["scan_id"], calls[-1])
        self.assertIsNone(result["final_security_status"])
        self.assertFalse(result["final_security_verified"])
        self.assertEqual(result["rollback"], "verified")

    def test_post_rollback_save_failure_keeps_post_scan_id(self):
        self.outputs = ["vulnerable"]
        save = self.store.save
        calls = []
        def flaky(report):
            calls.append(report["scan_id"])
            if len(calls) == 2:
                raise OSError("MOCK: second save failed")
            return save(report)
        with patch.object(self.store, "save", side_effect=flaky):
            result = self.run_mock(post_rollback_recheck=True)
        self.assertEqual(result["post_rollback_scan_id"], calls[-1])
        self.assertEqual(result["recheck_attempts"][-1]["save_status"], "failed")
        self.assertFalse(result["final_security_verified"])

    def test_post_rollback_diagnosis_exception_keeps_unknown_state(self):
        self.outputs = ["vulnerable"]
        def fail_second(report):
            if len(self.calls) == 2:
                raise RuntimeError("MOCK: diagnosis unavailable")
        self.transform = fail_second
        result = self.run_mock(post_rollback_recheck=True)
        self.assertIsNone(result["post_rollback_scan_id"])
        self.assertIsNone(result["final_security_status"])
        self.assertFalse(result["final_security_verified"])
        self.assertEqual(result["recheck_attempts"][-1]["failure_stage"], "diagnose")

    def test_post_rollback_nondefinitive_diagnoses_are_not_security_verified(self):
        for status in ("error", "needs_review", "not_applicable"):
            with self.subTest(status=status):
                self.setUp()
                self.outputs = ["vulnerable", status]
                result = self.run_mock(post_rollback_recheck=True)
                self.assertEqual(result["final_security_status"], status)
                self.assertFalse(result["final_security_verified"])
                self.assertEqual(result["outcome"], "failed")

    def test_reused_post_rollback_scan_id_is_rejected_before_save(self):
        self.outputs = ["vulnerable"]
        ids = []
        def reuse(report):
            if ids:
                report["scan_id"] = ids[0]
            ids.append(report["scan_id"])
        self.transform = reuse
        result = self.run_mock(post_rollback_recheck=True)
        self.assertIsNone(result["post_rollback_scan_id"])
        self.assertEqual(result["recheck_attempts"][-1]["failure_stage"], "validate")
        self.assertEqual(len(self.store.history(result["target_id"])), 2)
        self.assertFalse(result["final_security_verified"])

    def test_invalid_context_or_cvss_never_reaches_save(self):
        for field in ("target_id", "schema_version", "check_id", "scan_id", "cvss", "scanned_at"):
            with self.subTest(field=field):
                self.setUp()
                def corrupt(report):
                    if field == "check_id": report["results"][0]["check_id"] = "OTHER-01"
                    elif field == "cvss": report["results"][0]["cvss"]["base_score"] = 9.8
                    elif field == "scan_id": report["scan_id"] = self.before["scan_id"]
                    elif field == "scanned_at": report["scanned_at"] = "2000-01-01T00:00:00Z"
                    else: report[field] = "other"
                self.transform = corrupt
                result = self.run_mock()
                self.assertIsNone(result["after_scan_id"])
                self.assertEqual(result["recheck_attempts"][0]["save_status"], "not_attempted")
                self.assertEqual(result["rollback"], "verified")

    def test_loaded_report_content_must_match_saved_candidate(self):
        load = self.store.load
        def changed(target_id, scan_id):
            report = load(target_id, scan_id)
            report["results"][0]["evidence"] += " changed"
            return report
        with patch.object(self.store, "load", side_effect=changed):
            result = self.run_mock()
        attempt = result["recheck_attempts"][0]
        self.assertEqual(attempt["load_status"], "success")
        self.assertFalse(attempt["report_verified"])
        self.assertEqual(attempt["failure_stage"], "validate_loaded")
        self.assertEqual(result["outcome"], "failed")

    def test_denial_dry_run_and_skipping_do_not_create_scan_attempts(self):
        for options in ({"dry_run": True}, {"approval": replace(self.approval, approved=False)}):
            with self.subTest(options=list(options)):
                result = self.run_mock(**options)
                self.assertEqual(result["recheck_attempts"], [])
                self.assertIsNone(result["after_scan_id"])
                self.assertFalse(result["final_security_verified"])
        self.engine.allowed_targets = frozenset()
        self.assertEqual(self.run_mock()["recheck_attempts"], [])
        self.assertEqual(self.calls, [])

    def test_real_backend_and_conflicting_callbacks_are_rejected(self):
        with self.assertRaises(PermissionError):
            self.run_mock(backend=object())
        with self.assertRaises(ValueError):
            self.run_mock(recheck_report=lambda request, state: {})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.backend.events, [])

    def test_post_recheck_is_not_run_after_failed_restore(self):
        self.outputs = ["vulnerable"]
        self.backend.fail_at = {"restore"}
        result = self.run_mock(post_rollback_recheck=True)
        self.assertEqual(result["rollback"], "failed")
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(result["final_security_verified"])

    def test_apply_failure_can_request_a_new_post_rollback_diagnosis(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                self.setUp()
                self.backend.fail_at = {"apply"}
                result = self.run_mock(post_rollback_recheck=enabled)
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["rollback"], "verified")
                self.assertIsNone(result["after_scan_id"])
                if enabled:
                    self.assertIsNotNone(result["post_rollback_scan_id"])
                    self.assertEqual(result["final_security_status"], "vulnerable")
                else:
                    self.assertIsNone(result["post_rollback_scan_id"])
                    self.assertFalse(result["final_security_verified"])

    def test_post_rollback_diagnosis_cannot_precede_previous_scan(self):
        self.outputs = ["vulnerable"]
        times = []
        def old_time(report):
            if times:
                report["scanned_at"] = (datetime.fromisoformat(times[0]) - timedelta(seconds=1)).isoformat()
            times.append(report["scanned_at"])
        self.transform = old_time
        result = self.run_mock(post_rollback_recheck=True)
        self.assertIsNone(result["post_rollback_scan_id"])
        self.assertEqual(result["recheck_attempts"][-1]["failure_stage"], "validate")
        self.assertFalse(result["final_security_verified"])

    def test_execution_ids_are_generated_by_e_per_run(self):
        one = self.run_mock(dry_run=True)
        two = self.run_mock(dry_run=True)
        self.assertNotEqual(one["execution_id"], two["execution_id"])
        self.assertNotEqual(one["execution_id"], self.before["scan_id"])

    def test_legacy_error_report_scan_id_is_preserved_without_adapter(self):
        self.backend.recheck_callback = lambda *args: synthetic_result("SSH-01", "error")
        result = self.run_mock(recheck_adapter=None)
        self.assertEqual(result["outcome"], "failed")
        self.assertIsNone(result["after_report"])
        self.assertIsNotNone(result["after_scan_id"])
        self.assertFalse(result["final_security_verified"])


if __name__ == "__main__":
    unittest.main()
