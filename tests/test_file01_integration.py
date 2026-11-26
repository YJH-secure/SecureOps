"""F01~F18: 실제 E 엔진/어댑터/D 저장소 + 고정 C Bridge + D 호환 stub."""
from copy import deepcopy
from dataclasses import replace
import inspect
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from c_mock_bridge import diagnose
from core.main import DiagnosisAggregator
from core.storage import ReportStore
from remediation import Approval, MockBackend, Remediator, build_plan, ExecutionHistoryStore
from remediation.file01 import PATH, initial_snapshot
from remediation.recheck import MockRecheckAdapter
from file01_callback_stub import diagnose_file01_mock


class File01IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="secureops-file01-integration-")
        self.addCleanup(self.directory.cleanup)
        self.store = ReportStore(Path(self.directory.name) / "reports")
        wrapper = diagnose(initial_snapshot(), expected_identity=initial_snapshot())
        self.before = DiagnosisAggregator.from_results([], [wrapper["c_result"]],
            target_id="file01-MOCK", os="ubuntu-24.04", schema_version="1.2").get_report()
        self.store.save(self.before)
        self.before = self.store.load(self.before["target_id"], self.before["scan_id"])
        self.original = deepcopy(self.before)
        self.plan = build_plan(self.before, "FILE-01")
        self.approval = Approval("file01-approval", "mock-admin", self.plan.target_id,
            self.plan.scan_id, self.plan.plan_id, "2099-01-01T00:00:00Z", True)
        self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={"FILE-01"},
            verify_approval=lambda a: a == self.approval)
        self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os,
            files={PATH: initial_snapshot()}, access_verified=True, snapshot_verified=True)
        self.calls = []
        self.transform = None
        self.adapter = MockRecheckAdapter(self.callback, self.store)
        for name in ("os.chmod", "os.chown", "socket.create_connection"):
            guard = patch(name, side_effect=AssertionError("offline MOCK only"), create=True)
            guard.start()
            self.addCleanup(guard.stop)

    def callback(self, request, state):
        self.calls.append((deepcopy(request), deepcopy(state)))
        result = diagnose_file01_mock(request, state)
        if self.transform:
            self.transform(result, state["file01_context"]["phase"])
        return result

    def execute(self, **kwargs):
        options = dict(backend=self.backend, approval=self.approval, dry_run=False,
                       recheck_adapter=self.adapter)
        options.update(kwargs)
        result = self.engine.run(self.before, self.plan, **options)
        self.assertEqual(self.before, self.original)
        if os.environ.get("FILE01_INTEGRATION_EVIDENCE"):
            root = Path(os.environ["FILE01_INTEGRATION_EVIDENCE"])
            root.mkdir(parents=True, exist_ok=True)
            suffix = len(list(root.glob(self._testMethodName + "*.json")))
            (root / f"{self._testMethodName}-{suffix}.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return result

    def test_F01_normal_action_and_normal_restoration(self):
        result = self.execute()
        self.assertEqual(result["outcome"], "success")
        self.assertTrue(result["permission_improved"])
        self.assertEqual(result["after_report"]["results"][0]["status"], "needs_review")
        self.assertFalse(result["comparison"]["improved"])
        self.assertEqual(result["normal_restore_result"]["status"], "verified")
        self.assertEqual(result["rollback"], "not_needed")
        self.assertEqual(self.backend.files[PATH], initial_snapshot())
        self.assertEqual(result["final_security_status"], "vulnerable")
        self.assertTrue(result["final_state_verified"])
        self.assertNotEqual(result["normal_restore_scan_id"], result["after_scan_id"])

    def test_F02_needs_review_requires_vulnerable_permission_evidence(self):
        # 종합 needs_review + 취약 하위 근거의 승인 분기를 위한 합성 정책 사례.
        item = self.before["results"][0]
        item["status"] = "needs_review"
        item["cvss"].update(assessment_status="not_applicable", rationale="MOCK composite review")
        self.plan = build_plan(self.before, "FILE-01")
        self.assertIsNone(self.plan.skip_reason)
        untrusted = deepcopy(self.before)
        untrusted["results"][0]["details"] = {"trusted": True}
        self.assertIsNotNone(build_plan(untrusted, "FILE-01").skip_reason)
        self.approval = replace(self.approval, plan_id=self.plan.plan_id)
        self.original = deepcopy(self.before)
        result = self.execute()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["before_status"], "needs_review")
        self.assertEqual(result["after_report"]["results"][0]["status"], "needs_review")

    def test_F03_wrong_snapshot_identity_and_mode_stop_before_backup(self):
        for changes in ({"mode": "0644"}, {"uid": 1002}, {"content_sha256": "b" * 64},
                        {"inode": 102}, {"file_type": "symlink"}, {"extended_acl": True}):
            with self.subTest(changes=changes):
                engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={"FILE-01"},
                                   verify_approval=lambda a: a == self.approval)
                backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os,
                    files={PATH: dict(initial_snapshot(), **changes)}, access_verified=True, snapshot_verified=True)
                result = engine.run(self.before, self.plan, backend=backend, approval=self.approval,
                                    dry_run=False, recheck_adapter=self.adapter)
                self.assertEqual(result["failed_stage"], "preflight")
                self.assertNotIn("backup", backend.events)
                self.assertEqual(result["rollback"], "not_needed")
        # 승인 검증 도중 상태가 달라져도 실행 직전 snapshot 검사가 중단한다.
        def mutate_during_approval(approval):
            self.backend.files[PATH]["inode"] = 999
            return approval == self.approval
        self.engine.verify_approval = mutate_during_approval
        result = self.execute()
        self.assertEqual((result["outcome"], result["failed_stage"]), ("failed", "preflight"))
        self.assertNotIn("backup", self.backend.events)
        self.assertEqual(self.calls, [])

    def test_F04_untrusted_or_nonvulnerable_evidence_is_skipped(self):
        for mutation in ("missing", "safe", "path", "policy", "error"):
            report = deepcopy(self.before)
            item = report["results"][0]
            if mutation == "missing": item["details"].pop("files")
            elif mutation == "safe": item["details"]["files"][0]["checks"][1]["status"] = "pass"
            elif mutation == "path": item["details"]["files"][0]["path"] = "/etc/passwd"
            elif mutation == "policy": item["details"]["files"][0]["expected"]["allowed_permission_bits"] = "0777"
            else:
                item["status"] = "error"
                item["cvss"].update(assessment_status="not_applicable")
            item["details"]["trusted"] = True  # 자체 선언으로 신뢰 조건을 충족하지 못한다.
            self.assertIsNotNone(build_plan(report, "FILE-01").skip_reason)

    def test_F05_approval_denial_expiry_and_binding(self):
        for delta in ({"approved": False}, {"expires_at": "2000-01-01T00:00:00Z"},
                      {"target_id": "other"}, {"scan_id": "other"}, {"plan_id": "wrong"}):
            result = self.execute(approval=replace(self.approval, **delta))
            self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.backend.events, [])
        self.engine.verify_approval = lambda _: False
        self.assertEqual(self.execute()["outcome"], "rejected")
        def verification_error(_):
            raise OSError("MOCK approval verifier unavailable")
        self.engine.verify_approval = verification_error
        result = self.execute()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["failed_stage"], "approval")
        self.assertEqual(result["failure_reason"], "approval_verification_error")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.backend.events, [])

    def test_F06_modified_plan_is_rejected_without_execution(self):
        plan = replace(self.plan, actions=(("file01_mode_mock", PATH, "0777"),))
        with self.assertRaises(ValueError):
            self.engine.run(self.before, plan, backend=self.backend, approval=self.approval,
                            dry_run=False, recheck_adapter=self.adapter)
        self.assertEqual(self.backend.events, [])
        changed_before = deepcopy(self.before)
        changed_before["results"][0]["evidence"] = "changed after plan approval"
        with self.assertRaises(ValueError):
            self.engine.run(changed_before, self.plan, backend=self.backend, approval=self.approval,
                            dry_run=False, recheck_adapter=self.adapter)
        self.assertEqual(self.backend.events, [])

    def test_F07_partial_apply_failure_rolls_back_and_rechecks(self):
        self.backend.fail_at = {"apply"}
        result = self.execute()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertEqual(result["failure_rollback_result"]["status"], "verified")
        self.assertEqual(result["failure_rollback_result"]["before_snapshot"]["mode"], "0644")
        self.assertEqual(result["failure_rollback_result"]["after_snapshot"]["mode"], "0666")
        self.assertEqual(result["normal_restore_result"]["status"], "not_attempted")
        self.assertIsNotNone(result["post_rollback_scan_id"])
        self.assertEqual(self.backend.files[PATH], initial_snapshot())

    def test_F08_recheck_failure_preserves_apply_and_failure_outcome(self):
        def fail_after(report, phase):
            if phase == "after": raise ValueError("MOCK recheck failure")
        self.transform = fail_after
        result = self.execute()
        self.assertEqual(result["action_result"]["apply_status"], "success")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertTrue(result["final_state_verified"])

    def test_F09_token_cannot_cross_backend_or_target(self):
        result = self.execute()
        token = result["backup_id"]
        other = MockBackend(target_id="other", os=self.plan.os, files={PATH: initial_snapshot()})
        with self.assertRaises(KeyError): other.restore(token)
        # token 내용을 다른 backend로 복사해도 소유 인스턴스 바인딩이 거부한다.
        other = MockBackend(target_id=self.plan.target_id, os=self.plan.os, files={PATH: initial_snapshot()})
        other._backups[token] = deepcopy(self.backend._backups[token])
        other._backup_contexts[token] = dict(self.backend._backup_contexts[token])
        other._active_plan_id, other._active_check_id = self.plan.plan_id, self.plan.check_id
        with self.assertRaises(ValueError): other.restore(token)
        self.backend.target_id = "other"
        with self.assertRaises(ValueError): self.backend.restore(token)

    def test_F10_token_binds_check_plan_execution_and_approval(self):
        result = self.execute()
        token = result["backup_id"]
        for key, bad in (("_active_check_id", "SSH-01"), ("_active_plan_id", "other")):
            value = getattr(self.backend, key)
            setattr(self.backend, key, bad)
            with self.assertRaises(ValueError): self.backend.restore(token)
            setattr(self.backend, key, value)
        original = deepcopy(self.backend._file01_execution)
        self.backend._file01_execution["approval_id"] = "different"
        with self.assertRaises(ValueError): self.backend.restore(token)
        self.backend._file01_execution = original

    def test_F11_d_save_failure_preserves_attempt_id(self):
        save = self.store.save
        calls = []
        def flaky(report):
            calls.append(report["scan_id"])
            if len(calls) == 1: raise OSError("MOCK save failure")
            return save(report)
        with patch.object(self.store, "save", side_effect=flaky): result = self.execute()
        attempt = result["recheck_attempts"][0]
        self.assertEqual((attempt["save_status"], attempt["load_status"]), ("failed", "not_attempted"))
        self.assertEqual(result["after_scan_id"], calls[0])
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")

    def test_F12_d_load_failure_preserves_saved_report(self):
        load = self.store.load
        calls = []
        def flaky(target, scan):
            calls.append(scan)
            if len(calls) == 1: raise OSError("MOCK load failure")
            return load(target, scan)
        with patch.object(self.store, "load", side_effect=flaky): result = self.execute()
        self.assertEqual(result["after_scan_id"], calls[0])
        self.assertEqual(load(self.plan.target_id, calls[0])["results"][0]["status"], "needs_review")
        self.assertEqual(result["recheck_attempts"][0]["load_status"], "failed")
        self.assertEqual(result["outcome"], "failed")

    def test_F13_normal_restore_failure_never_claims_completion(self):
        self.backend.fail_at = {"normal_restore"}
        result = self.execute()
        self.assertEqual(result["outcome"], "failed")
        self.assertTrue(result["permission_improved"])
        self.assertFalse(result["final_security_verified"])
        self.assertIsNone(result["final_security_status"])
        self.assertEqual(result["rollback"], "not_needed")
        self.assertEqual(self.backend.events.count("normal_restore"), 1)

    def test_F14_failure_rollback_failure_stops(self):
        self.backend.fail_at = {"apply", "restore"}
        result = self.execute()
        self.assertEqual(result["rollback"], "failed")
        self.assertEqual(result["failure_rollback_result"]["status"], "failed")
        self.assertEqual(result["failure_rollback_result"]["before_snapshot"]["mode"], "0644")
        self.assertEqual(result["failure_rollback_result"]["after_snapshot"]["mode"], "0644")
        self.assertFalse(result["final_state_verified"])
        self.assertEqual(self.calls, [])

    def test_F15_restored_mode_without_c_verification_is_unknown(self):
        for failed_phase in ("post_restore", "post_rollback"):
            with self.subTest(phase=failed_phase):
                self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={"FILE-01"},
                    verify_approval=lambda a: a == self.approval)
                self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os,
                    files={PATH: initial_snapshot()}, access_verified=True, snapshot_verified=True,
                    fail_at={"apply"} if failed_phase == "post_rollback" else ())
                def fail_restore(report, phase):
                    if phase == failed_phase: raise ValueError("MOCK C validation failure")
                self.transform = fail_restore
                result = self.execute()
                self.assertEqual(self.backend.files[PATH]["mode"], "0666")
                self.assertFalse(result["final_state_verified"])
                self.assertIsNone(result["final_security_status"])
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["rollback"], "failed" if failed_phase == "post_rollback" else "not_needed")

    def test_F16_invalid_recheck_cvss_and_context_are_rejected(self):
        for mutation in ("target", "cvss", "schema", "missing_check"):
            with self.subTest(mutation=mutation):
                self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={"FILE-01"},
                    verify_approval=lambda a: a == self.approval)
                self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os,
                    files={PATH: initial_snapshot()}, access_verified=True, snapshot_verified=True)
                def corrupt(report, phase):
                    if phase != "after": return
                    if mutation == "target": report["target_id"] = "wrong"
                    elif mutation == "cvss": report["results"][0]["cvss"]["vector"] = "invalid"
                    elif mutation == "schema": report["schema_version"] = "1.1"
                    else: report["results"][0]["check_id"] = "OTHER"
                self.transform = corrupt
                result = self.execute()
                self.assertEqual(result["outcome"], "failed")
                self.assertFalse(result["recheck_attempts"][0]["report_verified"])
                self.assertIsNone(result["after_scan_id"])
                self.assertEqual(result["rollback"], "verified")

    def test_F17_callback_single_owner_and_execution_history_roundtrip(self):
        with patch.object(self.store, "save", wraps=self.store.save) as save, \
             patch.object(self.store, "load", wraps=self.store.load) as load:
            result = self.execute()
        self.assertEqual((save.call_count, load.call_count, len(self.calls)), (2, 2, 2))
        for request, state in self.calls:
            context = state["file01_context"]
            self.assertEqual(context["original_snapshot"], initial_snapshot())
            self.assertEqual(context["expected_identity"], initial_snapshot())
            self.assertEqual(context["plan_id"], result["plan_id"])
            self.assertEqual(context["execution_id"], result["execution_id"])
            self.assertEqual(context["approval_id"], self.approval.approval_id)
            self.assertEqual(context["backup_token"], result["backup_id"])
            self.assertIn("files", state)
            self.assertIn("root_login", state)
        root = Path(self.directory.name) / "history"
        ExecutionHistoryStore(root).save(result)
        self.assertEqual(ExecutionHistoryStore(root).load(result["execution_id"]), result)

    def test_F18_ssh01_api_and_original_success_behavior(self):
        from test_remediation import report, backend
        before = report()
        plan = build_plan(before, "SSH-01")
        approval = Approval("ssh-only", "mock-admin", plan.target_id, plan.scan_id,
                            plan.plan_id, "2099-01-01T00:00:00Z", True)
        engine = Remediator(allowed_targets={plan.target_id}, allowed_checks={"SSH-01"}, verify_approval=lambda a: a == approval)
        state = backend()
        result = engine.run(before, plan, backend=state, approval=approval, dry_run=False)
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["final_security_status"], "pass")
        self.assertTrue(result["final_security_verified"])
        self.assertEqual(state.root_login, "no")
        self.assertNotIn("normal_restore_result", result)
        self.assertEqual(str(inspect.signature(MockBackend.request_recheck)), "(self, plan, callback)")
