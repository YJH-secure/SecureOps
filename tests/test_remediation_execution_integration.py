"""공통 실행 계층 MOCK → B/C 합성 결과 → D 저장·조회 → E 판정 검증."""

from copy import deepcopy
from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from core.main import DiagnosisAggregator
from core.storage import ReportStore
from remediation import Approval, MockBackend, Remediator, build_plan


def synthetic_result(check_id, status):
    # 실제 서버나 CVSS 점수를 추정하지 않는 B/C 테스트 결과.
    return {"check_id": check_id, "status": status, "evidence": "MOCK: synthetic diagnosis",
            "recommendation": "MOCK: review diagnosis",
            "cvss": {"assessment_status": "pending" if status == "vulnerable" else "not_applicable",
                     "version": None, "vector": None, "base_score": None,
                     "rating": None, "source": None, "rationale": "MOCK: synthetic assessment"}}


class MockExecutionLayer:
    """테스트 전용 연결 코드. 최초 진단과 재진단 모두 execute를 사용한다."""
    def __init__(self, store):
        self.store = store
        self.calls = []
        self.status = None
        self.change_results = None

    def execute(self, request, mock_state):
        self.calls.append(deepcopy(request))
        status = self.status or ("pass" if mock_state["root_login"] == "no" else "vulnerable")
        account = [synthetic_result("SSH-01", status)]
        system = [synthetic_result("FILE-01", "pass")]
        if self.change_results:
            self.change_results(account, system)
        report = DiagnosisAggregator.from_results(
            account, system, target_id=request["target_id"], os=request["os"],
            schema_version=request["schema_version"],
        ).get_report()
        self.store.save(report)
        return self.store.load(request["target_id"], report["scan_id"])


class ExecutionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="secureops-execution-mock-")
        self.addCleanup(self.directory.cleanup)
        self.store = ReportStore(self.directory.name)
        self.layer = MockExecutionLayer(self.store)
        request = {"target_id": "execution-MOCK", "os": "ubuntu-24.04", "check_id": "SSH-01",
                   "before_scan_id": None, "schema_version": "1.2"}
        self.before = self.layer.execute(request, {"files": {}, "root_login": "yes"})
        self.plan = build_plan(self.before, "SSH-01")
        self.approval = Approval("execution-approval-MOCK", "admin-MOCK", self.plan.target_id,
                                 self.plan.scan_id, self.plan.plan_id, "2099-01-01T00:00:00Z", True)
        self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={"SSH-01"},
                                 verify_approval=lambda record: record == self.approval)
        self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os, files={},
                                   access_verified=True, snapshot_verified=True, include_verified=True)

    def run_mock(self, **kwargs):
        options = dict(backend=self.backend, approval=self.approval, dry_run=False,
                       recheck_report=self.layer.execute)
        options.update(kwargs)
        return self.engine.run(self.before, self.plan, **options)

    def assert_restored(self, result):
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertEqual(result["failed_stage"], "recheck")
        self.assertEqual(self.backend.root_login, "yes")
        self.assertEqual(self.backend.files, {})
        self.assertTrue(self.backend.service_running)

    def test_initial_and_recheck_share_the_execution_path(self):
        original = deepcopy(self.before)
        result = self.run_mock()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["rollback"], "not_needed")
        self.assertEqual(len(self.layer.calls), 2)
        self.assertEqual(self.layer.calls[-1], {
            "target_id": self.plan.target_id, "os": self.plan.os, "check_id": "SSH-01",
            "before_scan_id": self.plan.scan_id, "schema_version": "1.2"})
        after = result["after_report"]
        self.assertEqual(after, self.store.load(after["target_id"], after["scan_id"]))
        self.assertNotEqual(after["scan_id"], self.before["scan_id"])
        self.assertEqual([r["check_id"] for r in after["results"]], ["SSH-01", "FILE-01"])
        self.assertEqual(len(self.store.history(self.plan.target_id)), 2)
        match = self.store.match_results(self.plan.target_id, self.plan.scan_id, after["scan_id"])
        self.assertEqual(match["SSH-01"]["after"]["status"], "pass")
        self.assertTrue(result["comparison"]["improved"])
        self.assertEqual(self.before, original)
        self.assertLess(self.backend.events.index("validate"), self.backend.events.index("recheck"))

    def test_nonpass_diagnoses_restore_instead_of_succeeding(self):
        for status in ("vulnerable", "error", "needs_review", "not_applicable"):
            with self.subTest(status=status):
                self.setUp()
                self.layer.status = status
                result = self.run_mock()
                self.assert_restored(result)
                saved = self.store.history(self.plan.target_id)[-1]
                self.assertEqual(saved["results"][0]["status"], status)

    def test_other_check_error_does_not_replace_selected_check_status(self):
        self.layer.change_results = lambda account, system: system.__setitem__(
            0, synthetic_result("FILE-01", "error"))
        result = self.run_mock()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["comparison"]["after"]["check_id"], "SSH-01")
        self.assertEqual(result["after_report"]["results"][1]["status"], "error")

    def test_bad_individual_cvss_is_rejected_by_d(self):
        self.layer.change_results = lambda account, system: account[0]["cvss"].update(base_score=9.8)
        result = self.run_mock()
        self.assert_restored(result)
        self.assertEqual(len(self.store.history(self.plan.target_id)), 1)

    def test_bad_json_value_is_rejected_by_d(self):
        self.layer.change_results = lambda account, system: account[0].update(details={"bad": {1, 2}})
        self.assert_restored(self.run_mock())
        self.assertEqual(len(self.store.history(self.plan.target_id)), 1)

    def test_invalid_returned_report_is_revalidated_by_e(self):
        def callback(request, state):
            report = self.layer.execute(request, state)
            report["results"][0]["cvss"]["base_score"] = 1.0
            return report
        self.assert_restored(self.run_mock(recheck_report=callback))

    def test_mismatched_report_identity_is_rejected(self):
        for field, value in (("target_id", "other-MOCK"), ("os", "rocky-9"),
                             ("scan_id", "same-as-before"),
                             ("scanned_at", "2000-01-01T00:00:00Z")):
            with self.subTest(field=field):
                self.setUp()
                def callback(request, state):
                    report = self.layer.execute(request, state)
                    report[field] = self.before["scan_id"] if field == "scan_id" else value
                    return report
                self.assert_restored(self.run_mock(recheck_report=callback))

    def test_missing_requested_check_is_rejected(self):
        def callback(request, state):
            report = self.layer.execute(request, state)
            report["results"] = report["results"][1:]
            return report
        self.assert_restored(self.run_mock(recheck_report=callback))

    def test_mixed_schema_return_is_rejected(self):
        def callback(request, state):
            report = self.layer.execute(request, state)
            report["schema_version"] = "1.1"
            for item in report["results"]:
                del item["cvss"]
                item["severity"] = "high"
            return report
        self.assert_restored(self.run_mock(recheck_report=callback))

    def test_store_save_failure_restores(self):
        with patch.object(self.store, "save", side_effect=OSError("MOCK: save failed")):
            result = self.run_mock()
        self.assert_restored(result)
        self.assertIsNone(result["after_report"])
        self.assertEqual(len(self.store.history(self.plan.target_id)), 1)

    def test_store_load_failure_restores(self):
        with patch.object(self.store, "load", side_effect=OSError("MOCK: load failed")):
            result = self.run_mock()
        self.assert_restored(result)
        # 저장은 완료되었지만 조회 실패로 E의 성공 판정에는 사용하지 않는다.
        self.assertEqual(len(self.store.history(self.plan.target_id)), 2)

    def test_callback_exception_restores(self):
        def fail(request, state):
            raise RuntimeError("MOCK: diagnosis failed")
        self.assert_restored(self.run_mock(recheck_report=fail))

    def test_restore_failure_is_reported(self):
        self.backend.fail_at = {"restore"}
        self.layer.status = "vulnerable"
        result = self.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "failed")
        self.assertEqual(result["rollback_failed_stage"], "restore")

    def test_dry_run_denial_and_allowlist_never_call_execution_layer(self):
        result = self.run_mock(dry_run=True)
        self.assertEqual(result["outcome"], "planned")
        result = self.run_mock(approval=replace(self.approval, approved=False))
        self.assertEqual(result["outcome"], "rejected")
        self.engine.allowed_targets = frozenset()
        self.assertEqual(self.run_mock()["outcome"], "skipped")
        self.assertEqual(len(self.layer.calls), 1)
        self.assertEqual(self.backend.events, [])

    def test_precheck_and_backup_failure_never_call_execution_layer(self):
        for stage in ("preflight", "backup", "apply", "validate"):
            with self.subTest(stage=stage):
                self.setUp()
                self.backend.fail_at = {stage}
                self.assertEqual(self.run_mock()["outcome"], "failed")
                self.assertEqual(len(self.layer.calls), 1)

    def test_callback_receives_copies_not_backend_or_approval(self):
        def callback(request, state):
            report = self.layer.execute(request, state)
            self.assertEqual(set(state), {"files", "root_login"})
            request["target_id"] = "changed-MOCK"
            state["files"].clear()
            state["root_login"] = "yes"
            return report
        result = self.run_mock(recheck_report=callback)
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(self.backend.root_login, "no")
        self.assertTrue(self.backend.files)
        self.assertEqual(self.plan.target_id, "execution-MOCK")

    def test_real_or_subclass_backend_remains_forbidden(self):
        class DerivedMock(MockBackend):
            pass
        for backend in (object(), DerivedMock(target_id=self.plan.target_id, os=self.plan.os, files={})):
            with self.subTest(backend=type(backend).__name__):
                with self.assertRaises(PermissionError):
                    self.run_mock(backend=backend)
        self.assertEqual(len(self.layer.calls), 1)

    def test_invalid_callback_is_rejected_before_change(self):
        with self.assertRaises(ValueError):
            self.run_mock(recheck_report="not a function")
        self.assertEqual(self.backend.events, [])

    def test_callback_cannot_be_used_with_legacy_report(self):
        before = deepcopy(self.before)
        before["schema_version"] = "1.1"
        for item in before["results"]:
            del item["cvss"]
            item["severity"] = "high"
        plan = build_plan(before, "SSH-01")
        with self.assertRaises(ValueError):
            self.engine.run(before, plan, backend=self.backend, approval=self.approval,
                            dry_run=False, recheck_report=self.layer.execute)
        self.assertEqual(self.backend.events, [])


if __name__ == "__main__":
    unittest.main()
