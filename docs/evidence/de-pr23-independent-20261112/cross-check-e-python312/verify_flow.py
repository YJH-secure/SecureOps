"""Offline integration against the assembled PR #23 and main trees."""
from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path.cwd() / "tests"))
from core.main import DiagnosisAggregator
from core.storage import ReportStore
from remediation import Approval, ExecutionHistoryStore, MockBackend, Remediator, build_plan
from remediation.recheck import MockRecheckAdapter
import test_remediation_b_v12_integration as b_contract
from test_remediation_v12 import mock_report


class PipelineTests(unittest.TestCase):
    def pipeline(self, version="1.2", *, fail_after=False, post_rollback=False):
        directory = TemporaryDirectory(prefix="secureops-pr23-flow-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        d_path = root / "diagnoses"
        e_path = root / "executions"
        d = ReportStore(d_path)
        b = b_contract.BContractIntegrationTests()
        b.setUp()
        self.addCleanup(b.doCleanups)
        scored = mock_report()["results"][-1]
        statuses = []

        def report_for(root_login):
            output = f"permitrootlogin {root_login}"
            if version == "1.2":
                item = b.b_result(output)
                rows = [item, deepcopy(scored)]
            else:
                from checks.account import ssh_check
                rows = [ssh_check.check_ssh_01(b.policy, output, root_output=output)]
            statuses.append(rows[0]["status"])
            return DiagnosisAggregator.from_results(
                rows, [], target_id="pipeline-MOCK", os="ubuntu-24.04", schema_version=version,
            ).get_report()

        before = report_for("yes")
        d.save(before)
        incoming = ReportStore(d_path).load(before["target_id"], before["scan_id"])
        plan = build_plan(incoming, "SSH-01")
        approval = Approval("pipeline-approval", "admin-MOCK", plan.target_id, plan.scan_id,
                            plan.plan_id, "2099-01-01T00:00:00Z", True)
        backend = MockBackend(target_id=plan.target_id, os=plan.os, files={},
                              access_verified=True, snapshot_verified=True, include_verified=True)
        engine = Remediator(allowed_targets={plan.target_id}, allowed_checks={"SSH-01"},
                            verify_approval=lambda record: record == approval)

        def diagnose(request, state):
            self.assertEqual(request["target_id"], plan.target_id)
            self.assertEqual(request["check_id"], "SSH-01")
            return report_for("strange" if fail_after and len(statuses) == 1 else state["root_login"])

        options = {}
        if version == "1.2":
            options.update(recheck_adapter=MockRecheckAdapter(diagnose, d),
                           post_rollback_recheck=post_rollback)
        result = engine.run(incoming, plan, backend=backend, approval=approval, dry_run=False, **options)
        if version == "1.1":
            d.save(result["after_report"])

        ExecutionHistoryStore(e_path).save(result)
        history = ExecutionHistoryStore(e_path).load(result["execution_id"])
        self.assertEqual(history, result)
        self.assertEqual(history["approval_id"], approval.approval_id)
        self.assertEqual(history["schema_version"], "1.0")
        self.assertEqual(history["diagnosis_schema_version"], version)
        self.assertEqual(history["before_scan_id"], before["scan_id"])
        d = ReportStore(d_path)
        self.assertEqual(d.load(plan.target_id, history["before_scan_id"]), before)
        self.assertNotEqual(history["after_scan_id"], before["scan_id"])
        after = d.load(plan.target_id, history["after_scan_id"])
        self.assertEqual(after, history["after_report"])
        self.assertEqual(after["schema_version"], version)
        if version == "1.2":
            for report in (before, after):
                row = next(item for item in report["results"] if item["check_id"] == scored["check_id"])
                self.assertEqual(row, scored)
            self.assertEqual(history["recheck_attempts"][0]["load_status"], "success")
        return history, d, backend

    def test_v12_success_and_two_stores(self):
        record, store, backend = self.pipeline()
        self.assertEqual(record["outcome"], "success")
        self.assertEqual(record["final_security_status"], "pass")
        self.assertTrue(record["final_security_verified"])
        self.assertEqual(backend.root_login, "no")
        self.assertEqual(len(store.history(record["target_id"])), 2)
        after = next(row for row in record["after_report"]["results"] if row["check_id"] == "SSH-01")
        self.assertEqual(after["cvss"]["assessment_status"], "not_applicable")

    def test_rollback_with_new_d_scan_and_e_history(self):
        record, store, backend = self.pipeline(fail_after=True, post_rollback=True)
        self.assertEqual((record["outcome"], record["rollback"]), ("failed", "verified"))
        self.assertEqual(backend.root_login, "yes")
        self.assertEqual(len({record["before_scan_id"], record["after_scan_id"],
                              record["post_rollback_scan_id"]}), 3)
        self.assertEqual(store.load(record["target_id"], record["post_rollback_scan_id"]),
                         record["post_rollback_report"])
        self.assertEqual(record["final_security_status"], "vulnerable")
        self.assertTrue(record["final_security_verified"])

    def test_rollback_without_diagnosis_stays_unverified(self):
        record, store, _ = self.pipeline(fail_after=True)
        self.assertEqual((record["outcome"], record["rollback"]), ("failed", "verified"))
        self.assertIsNone(record["post_rollback_scan_id"])
        self.assertIsNone(record["final_security_status"])
        self.assertFalse(record["final_security_verified"])
        self.assertEqual(len(store.history(record["target_id"])), 2)

    def test_v11_success_and_two_stores(self):
        record, _, _ = self.pipeline(version="1.1")
        self.assertEqual(record["outcome"], "success")
        item = record["after_report"]["results"][0]
        self.assertEqual(item["severity"], "high")
        self.assertNotIn("cvss", item)


if __name__ == "__main__":
    unittest.main(verbosity=2)
