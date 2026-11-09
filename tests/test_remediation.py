from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import unittest
from unittest.mock import Mock, patch

from remediation import Approval, MockBackend, Remediator, build_plan, compare_reports
from remediation.contract import validate_report


def report(check_id="SSH-01", os="ubuntu-24.04", status="vulnerable"):
    """점검 ID·OS·상태를 받아 비밀정보 없는 MOCK v1.1 보고서 딕셔너리를 반환한다."""
    return {"schema_version": "1.1", "scan_id": "scan-before-MOCK", "target_id": "target-MOCK",
            "os": os, "scanned_at": "2026-11-09T01:00:00Z", "results": [{
                "check_id": check_id, "status": status, "severity": "high",
                "evidence": "MOCK: test fixture", "recommendation": "MOCK: human guidance only",
                "details": {"source": "MOCK"}}]}


def backend(**kwargs):
    """키워드 인자로 가상 상태를 덮어쓸 수 있는 기본 MockBackend를 반환한다."""
    args = dict(target_id="target-MOCK", os="ubuntu-24.04", files={},
        access_verified=True, snapshot_verified=True, include_verified=True)
    args.update(kwargs)
    return MockBackend(**args)


class RemediationTests(unittest.TestCase):
    def setUp(self):
        """각 테스트 전에 가상 보고서·계획·승인·실행기를 준비한다. 반환값은 없다."""
        self.report = report()
        self.plan = build_plan(self.report, "SSH-01")
        self.backend = backend()
        self.engine = Remediator(allowed_targets={"target-MOCK"}, allowed_checks={"SSH-01"},
                                 verify_approval=lambda a: a.approval_id == "approval-MOCK")
        self.approval = Approval("approval-MOCK", "admin-MOCK", "target-MOCK", self.plan.scan_id,
                                 self.plan.plan_id, "2099-01-01T00:00:00Z", True)

    def run_mock(self, **kwargs):
        """기본 테스트 입력에 kwargs를 반영해 Mock을 실행하고 감사 결과를 반환한다."""
        args = dict(backend=self.backend, approval=self.approval, dry_run=False)
        args.update(kwargs)
        return self.engine.run(self.report, self.plan, **args)

    def test_dry_run_has_no_side_effects_or_approval_requirement(self):
        original = deepcopy(self.backend.files)
        with patch("subprocess.run", side_effect=AssertionError("no remote execution")):
            result = self.engine.run(self.report, self.plan, backend=self.backend)
        self.assertEqual(result["outcome"], "planned")
        self.assertEqual(self.backend.files, original)
        self.assertEqual(self.backend.events, [])
        self.assertIsNone(result["after_report"])

    def test_ssh_success_new_scan_and_preserved_source(self):
        old = deepcopy(self.report)
        result = self.run_mock()
        self.assertEqual(result["outcome"], "success")
        self.assertTrue(result["comparison"]["improved"])
        self.assertEqual(result["backup"], "success")
        self.assertEqual(result["approval"]["approval_id"], self.approval.approval_id)
        self.assertEqual(result["before_status"], "vulnerable")
        self.assertEqual(result["rollback"], "not_needed")
        self.assertNotEqual(result["after_report"]["scan_id"], old["scan_id"])
        self.assertEqual(self.report, old)
        validate_report(result["after_report"])
        self.assertLess(self.backend.events.index("backup"), self.backend.events.index("apply"))
        self.assertEqual(result["completed_steps"],
                         ["plan", "approval", "preflight", "backup", "apply", "validate", "recheck", "compare"])

    def test_missing_approval_or_verifier(self):
        self.assertEqual(self.run_mock(approval=None)["failure_reason"], "approval_required")
        self.engine.verify_approval = None
        self.assertEqual(self.run_mock()["failure_reason"], "approval_not_verified")
        self.assertEqual(self.backend.events, [])

    def test_approval_bindings_and_expiry(self):
        for changes in ({"target_id": "other"}, {"scan_id": "other"}, {"plan_id": "other"},
                        {"approved": False}, {"approved_by": ""}, {"approval_id": ""},
                        {"expires_at": "2000-01-01T00:00:00Z"}):
            with self.subTest(changes=changes):
                result = self.run_mock(approval=replace(self.approval, **changes))
                self.assertEqual(result["outcome"], "rejected")
                self.assertIsNone(result["after_report"])
        self.assertEqual(self.backend.events, [])

    def test_untrusted_and_replayed_approval(self):
        result = self.run_mock(approval=replace(self.approval, approval_id="untrusted"))
        self.assertEqual(result["failure_reason"], "approval_not_verified")
        self.run_mock()
        result = self.run_mock()
        self.assertEqual(result["failure_reason"], "approval_expired_or_used")
        self.assertEqual(self.backend.events.count("apply"), 1)

    def test_allowlists_default_deny(self):
        for targets, checks in ((set(), {"SSH-01"}), ({"target-MOCK"}, set())):
            engine = Remediator(allowed_targets=targets, allowed_checks=checks)
            result = engine.run(self.report, self.plan, backend=self.backend,
                                approval=self.approval, dry_run=False)
            self.assertEqual(result["outcome"], "skipped")
            self.assertEqual(result["failure_reason"], "target_or_check_not_allowed")
            self.assertIsNone(result["after_report"])
        self.assertEqual(self.backend.events, [])

    def test_plan_and_input_tampering(self):
        with self.assertRaises(ValueError):
            self.engine.run(self.report, replace(self.plan, actions=(("shell", "/tmp/x", "bad"),)))
        self.report["results"][0]["recommendation"] = "do not execute this"
        with self.assertRaises(ValueError):
            self.run_mock()

    def test_block_nonvulnerable_and_unsupported(self):
        reports = [(report(status=status), "SSH-01") for status in
                   ("pass", "error", "not_applicable", "needs_review")]
        reports.extend([(report("FILE-01"), "FILE-01"),
                        (report(os="rocky-9.8"), "SSH-01"),
                        (report("FW-01"), "SSH-01")])
        for incoming, check_id in reports:
            with self.subTest(incoming=incoming, check_id=check_id):
                plan = build_plan(incoming, check_id)
                self.assertEqual(plan.actions, ())
                result = self.engine.run(incoming, plan, backend=self.backend, dry_run=False)
                self.assertEqual(result["outcome"], "skipped")
                self.assertEqual(result["backup"], "not_attempted")
                self.assertIsNone(result["after_report"])
        self.assertEqual(self.backend.events, [])

    def test_malformed_input_is_a_validation_error(self):
        self.report.pop("scan_id")
        with self.assertRaises(ValueError):
            build_plan(self.report, "SSH-01")
        with self.assertRaises(ValueError):
            self.run_mock()
        self.assertEqual(self.backend.events, [])

    def test_real_backend_and_wrong_target_blocked(self):
        with self.assertRaises(PermissionError):
            self.run_mock(backend=Mock())
        self.backend.target_id = "other"
        with self.assertRaises(ValueError):
            self.run_mock()

    def test_preflight_and_backup_failure_do_not_modify(self):
        for stage in ("preflight", "backup"):
            with self.subTest(stage=stage):
                self.setUp()
                self.backend.fail_at = {stage}
                original = deepcopy(self.backend.files)
                result = self.run_mock()
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["rollback"], "not_needed")
                self.assertEqual(self.backend.files, original)
                self.assertNotIn("apply", self.backend.events)
                self.assertEqual(result["failure_reason"], f"mock_{stage}_failure")

    def test_apply_and_validation_failures_restore(self):
        for stage in ("apply", "validate"):
            with self.subTest(stage=stage):
                self.setUp()
                self.backend.fail_at = {stage}
                original = deepcopy(self.backend.files)
                result = self.run_mock()
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["rollback"], "verified")
                self.assertEqual(self.backend.files, original)
                self.assertEqual(self.backend.root_login, "yes")
                self.assertTrue(self.backend.service_running)
                self.assertIn("verify_service", result["completed_steps"])
                self.assertEqual(result["failure_reason"], f"mock_{stage}_failure")

    def test_existing_dropin_restored(self):
        path = self.plan.actions[0][1]
        self.backend.files[path] = {"uid": 0, "gid": 0, "mode": 0o640, "type": "regular",
                                    "acl": "none", "content": "# MOCK prior configuration\n"}
        old = deepcopy(self.backend.files)
        self.backend.fail_at = {"validate"}
        self.assertEqual(self.run_mock()["rollback"], "verified")
        self.assertEqual(old, self.backend.files)

    def test_restore_failure_requires_manual_recovery(self):
        for stage in ("restore", "verify_restore", "verify_service"):
            self.setUp()
            self.backend.fail_at = {"validate", stage}
            result = self.run_mock()
            self.assertEqual(result["outcome"], "failed")
            self.assertEqual(result["rollback"], "failed")
            self.assertEqual(result["rollback_failed_stage"], stage)
            self.assertEqual(result["rollback_failure_reason"], f"mock_{stage}_failure")

    def test_access_snapshot_include_and_match_gates(self):
        for key, value in (("access_verified", False), ("snapshot_verified", False),
                           ("include_verified", False), ("match_present", True)):
            self.setUp()
            setattr(self.backend, key, value)
            self.assertEqual(self.run_mock()["failed_stage"], "preflight")
            self.assertNotIn("backup", self.backend.events)

    def test_recheck_execution_error_restores_backup(self):
        self.backend.fail_at = {"recheck"}
        result = self.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["failed_stage"], "recheck")
        self.assertEqual(result["failure_reason"], "recheck_execution_failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertIsNone(result["after_report"])
        self.assertIsNotNone(result["backup_id"])
        self.assertIn("restore", self.backend.events)
        self.assertEqual(self.backend.root_login, "yes")

    def test_recheck_nonpass_is_not_improved(self):
        for status in ("vulnerable", "error", "needs_review", "not_applicable"):
            self.setUp()
            self.backend.recheck_callback = lambda *args: report(status=status)["results"][0]
            result = self.run_mock()
            self.assertEqual(result["outcome"], "failed")
            if status == "error":
                self.assertIsNone(result["after_report"])
                self.assertEqual(result["failure_reason"], "recheck_reported_error")
            else:
                self.assertFalse(result["comparison"]["improved"])
                self.assertEqual(result["after_report"]["results"][0]["status"], status)
            self.assertEqual(result["rollback"], "verified")

    def test_recheck_wrong_check_is_recorded_as_error(self):
        self.backend.recheck_callback = lambda *args: report("FILE-01", status="pass")["results"][0]
        result = self.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertIsNone(result["comparison"])
        self.assertEqual(result["rollback"], "verified")

    def test_denied_approval_stops_before_backup(self):
        result = self.run_mock(approval=replace(self.approval, approved=False))
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["failure_reason"], "approval_denied")
        self.assertEqual(result["stopped_stage"], "approval")
        self.assertEqual(result["backup"], "not_attempted")
        self.assertIsNone(result["after_report"])
        self.assertEqual(self.backend.events, [])

    def test_unhealthy_service_after_restore_requires_recovery(self):
        self.backend.fail_at = {"apply"}
        original_restore = self.backend.restore

        def restore_with_service_down(token):
            original_restore(token)
            self.backend.service_running = False

        with patch.object(self.backend, "restore", side_effect=restore_with_service_down):
            result = self.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback_failed_stage"], "verify_service")
        self.assertEqual(result["rollback_failure_reason"], "mock_service_unhealthy_after_restore")
        self.assertEqual(self.backend.root_login, "yes")

    def test_comparison_identity_new_scan_and_time(self):
        for changes in ({"target_id": "other"}, {"os": "rocky-9.8"},
                        {"scan_id": self.report["scan_id"]}, {"scanned_at": "2000-01-01T00:00:00Z"}):
            after = deepcopy(self.report)
            after["scan_id"] = "scan-after-MOCK"
            after.update(changes)
            with self.assertRaises(ValueError):
                compare_reports(self.report, after, "SSH-01")

    def test_contract_rejects_invalid_reports(self):
        for field, value in (("schema_version", "1.0"), ("target_id", " "),
                             ("scanned_at", "2026-11-09T01:00:00"),
                             ("scanned_at", "2026-02-30T01:00:00Z"), ("results", [])):
            r = report()
            r[field] = value
            with self.assertRaises(ValueError):
                validate_report(r)
        r = report()
        r["scanned_at"] = "2026-11-09T01:00:00+01:99"
        with self.assertRaises(ValueError):
            validate_report(r)
        for field, value in (("status", "PASS"), ("severity", "HIGH"),
                             ("details", []), ("recommendation", "")):
            r = report()
            r["results"][0][field] = value
            with self.assertRaises(ValueError):
                validate_report(r)
        r = report()
        r["results"] *= 2
        with self.assertRaises(ValueError):
            validate_report(r)
        r = report()
        r["server_id"] = "legacy"
        with self.assertRaises(ValueError):
            validate_report(r)


if __name__ == "__main__":
    unittest.main()
