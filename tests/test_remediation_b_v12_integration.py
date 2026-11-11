"""최신 main B SSH-01의 순수 판정·출력 함수와 D/E 계약을 오프라인 검증."""

from copy import deepcopy
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from checks.account import ssh_check as b
from core.main import DiagnosisAggregator
from core.storage import ReportStore
from remediation import Approval, MockBackend, Remediator, build_plan


class BContractIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.policy = b.load_policy()
        # 서버 수집 경로를 실수로 호출하면 테스트를 즉시 실패시킨다.
        for name in ("find_sshd", "get_sshd_output", "read_config_text"):
            guard = patch.object(b, name, side_effect=AssertionError("server collection is forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def b_result(self, output):
        legacy = b.check_ssh_01(self.policy, output, root_output=output)
        return b.to_result_v1_2(legacy, {"policy": self.policy, "sshd_output": output,
                                       "root_output": output, "config_text": ""})

    def report(self, item, store=None):
        report = DiagnosisAggregator.from_results(
            [item], [], target_id="b-contract-MOCK", os="ubuntu-24.04", schema_version="1.2",
        ).get_report()
        if store is not None:
            store.save(report)
            return store.load(report["target_id"], report["scan_id"])
        return report

    def test_b_v12_statuses_and_cvss_are_accepted_without_conversion(self):
        for output, expected in (("permitrootlogin yes", "vulnerable"),
                                 ("permitrootlogin no", "pass"),
                                 ("permitrootlogin strange", "needs_review"), ("", "error")):
            with self.subTest(status=expected):
                item = self.b_result(output)
                original = deepcopy(item)
                plan = build_plan(self.report(item), "SSH-01")
                self.assertEqual(item["status"], expected)
                self.assertEqual(bool(plan.actions), expected == "vulnerable")
                self.assertNotIn("severity", item)
                self.assertIsNone(item["cvss"]["base_score"])
                self.assertEqual(item["cvss"]["assessment_status"],
                                 "pending" if expected == "vulnerable" else "not_applicable")
                self.assertEqual(item, original)
        item = b.to_result_v1_2(b.make_result("not_applicable", "high", "MOCK: not applicable"),
                               {"policy": self.policy})
        self.assertFalse(build_plan(self.report(item), "SSH-01").actions)

    def test_b_legacy_output_still_builds_v11_plan(self):
        item = b.check_ssh_01(self.policy, "permitrootlogin yes", root_output="permitrootlogin yes")
        report = DiagnosisAggregator.from_results(
            [item], [], target_id="b-contract-MOCK", os="ubuntu-24.04",
        ).get_report()
        self.assertTrue(build_plan(report, "SSH-01").actions)
        self.assertEqual(item["severity"], "high")
        self.assertNotIn("cvss", item)

    def run_pipeline(self, forced_output=None):
        with TemporaryDirectory(prefix="secureops-b-e-mock-") as directory:
            store = ReportStore(directory)
            calls = []
            def execution(request, state):
                calls.append(request.copy())
                output = (forced_output if len(calls) > 1 and forced_output is not None
                          else "permitrootlogin " + state["root_login"])
                return self.report(self.b_result(output), store)
            request = {"target_id": "b-contract-MOCK", "check_id": "SSH-01", "schema_version": "1.2"}
            before = execution(request, {"root_login": "yes"})
            plan = build_plan(before, "SSH-01")
            approval = Approval("b-e-approval", "admin-MOCK", plan.target_id, plan.scan_id,
                                plan.plan_id, "2099-01-01T00:00:00Z", True)
            backend = MockBackend(target_id=plan.target_id, os=plan.os, files={},
                                  access_verified=True, snapshot_verified=True, include_verified=True)
            engine = Remediator(allowed_targets={plan.target_id}, allowed_checks={"SSH-01"},
                                verify_approval=lambda record: record == approval)
            result = engine.run(before, plan, backend=backend, approval=approval,
                                dry_run=False, recheck_report=execution)
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(store.history(plan.target_id)), 2)
            if result["after_report"]:
                after = result["after_report"]
                self.assertEqual(after, store.load(after["target_id"], after["scan_id"]))
                self.assertNotEqual(before["scan_id"], after["scan_id"])
            return result, backend

    def test_real_b_pure_output_through_d_e_callback_and_store(self):
        result, backend = self.run_pipeline()
        self.assertEqual(result["outcome"], "success")
        after = result["after_report"]["results"][0]
        self.assertEqual(after["status"], "pass")
        self.assertEqual(after["cvss"]["assessment_status"], "not_applicable")
        self.assertEqual(after["details"]["root_value"], "no")
        self.assertEqual(backend.root_login, "no")

    def test_real_b_nonpass_output_keeps_existing_mock_rollback(self):
        for output in ("permitrootlogin yes", "", "permitrootlogin strange"):
            with self.subTest(output=output):
                result, backend = self.run_pipeline(output)
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["rollback"], "verified")
                self.assertEqual(backend.root_login, "yes")


if __name__ == "__main__":
    unittest.main()
