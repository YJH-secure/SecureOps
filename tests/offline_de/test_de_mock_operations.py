"""P01-P13 approved plan mapping; exact E35 objects and real D/B functions."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from checks.account import ssh_check as b
from core.main import DiagnosisAggregator
from core.remote_result import parse_result_json
from core.storage import ReportStore
from remediation.engine import Approval, Remediator, build_plan
from remediation.history import ExecutionHistoryStore
from remediation.mock import MockBackend
from remediation.recheck import MockRecheckAdapter
from orchestration.de_mock import (
    execute_mock_remediation, persist_mock_execution_history,
)


class DEMockOperationsTests(unittest.TestCase):
    @contextmanager
    def scenario(self, *, fail_at=(), check_id="SSH-01"):
        with TemporaryDirectory(prefix="secureops-de-operation-") as directory:
            root = Path(directory)
            store = ReportStore(root / "diagnoses")
            history = ExecutionHistoryStore(root / "executions")
            policy = b.load_policy()
            calls = []

            def item(value):
                output = "permitrootlogin " + value + "\n"
                raw = b.check_ssh_01(policy, output, config_text="", root_output=output)
                converted = b.to_result_v1_2(raw, {
                    "policy": policy, "sshd_output": output,
                    "root_output": output, "config_text": "",
                })
                return parse_result_json(json.dumps(converted), exit_code=0,
                                         execution_succeeded=True, schema_version="1.2")

            before_item = item("yes")
            if check_id != "SSH-01":
                # Synthetic unsupported check fixture, not a claimed C judgement.
                before_item = dict(before_item, check_id=check_id)
            before = DiagnosisAggregator.from_results(
                [before_item], [], target_id="de-operation-MOCK",
                os="ubuntu-24.04", schema_version="1.2",
            ).get_report()
            before_path = store.save(before)
            before_bytes = before_path.read_bytes()
            plan = build_plan(before, check_id)
            approval = Approval("approval-MOCK", "admin-MOCK", plan.target_id,
                                plan.scan_id, plan.plan_id, "2099-01-01T00:00:00Z", True)
            engine = Remediator(allowed_targets={plan.target_id},
                                allowed_checks={check_id},
                                verify_approval=lambda a: a == approval)
            backend = MockBackend(
                target_id=plan.target_id, os=plan.os, files={},
                fail_at=fail_at, access_verified=True,
                snapshot_verified=True, include_verified=True,
            )

            def diagnose(request, state):
                calls.append(deepcopy(request))
                return DiagnosisAggregator.from_results(
                    [item(state["root_login"])], [], target_id=request["target_id"],
                    os=request["os"], schema_version=request["schema_version"],
                ).get_report()

            adapter = MockRecheckAdapter(diagnose, store)
            options = dict(report_store=store, history_store=history,
                           remediator=engine, target_id=plan.target_id,
                           before_scan_id=plan.scan_id, check_id=check_id,
                           approval=approval, dry_run=False, backend=backend,
                           recheck_adapter=adapter)
            try:
                yield dict(options=options, store=store, history=history,
                           before=before, backend=backend, adapter=adapter,
                           engine=engine, calls=calls, approval=approval)
            finally:
                self.assertEqual(before_path.read_bytes(), before_bytes)
                self.assertEqual(store.load(plan.target_id, plan.scan_id), before)

    def test_P01_success_and_dry_run_history(self):
        for dry in (False, True):
            with self.subTest(dry_run=dry), self.scenario() as s:
                with patch.object(s["engine"], "run", wraps=s["engine"].run) as run:
                    out = execute_mock_remediation(**dict(s["options"], dry_run=dry))
                run.assert_called_once()
                self.assertFalse(run.call_args.kwargs["post_rollback_recheck"])
                self.assertEqual(out["outcome"], "planned" if dry else "success")
                self.assertEqual(out["integration_success"], not dry)
                self.assertTrue(out["history_saved"])
                self.assertTrue(out["history_verified"])
                self.assertEqual(s["history"].load(out["execution_id"]),
                                 json.loads(json.dumps(out["e_result"])))
                self.assertEqual(len(s["calls"]), 0 if dry else 1)
                if not dry:
                    attempt = out["recheck_attempts"][0]
                    self.assertTrue(attempt["report_verified"])
                    after = s["store"].load(out["target_id"], out["after_scan_id"])
                    self.assertEqual(after["results"][0]["status"], "pass")
                    self.assertEqual(after, out["e_result"]["after_report"])
                    self.assertIsNone(after["results"][0]["cvss"]["base_score"])

    def test_P02_approval_denied_expired_and_binding(self):
        for mode in ("denied", "expired", "binding"):
            with self.subTest(mode=mode), self.scenario() as s:
                changes = {"approved": False} if mode == "denied" else (
                    {"expires_at": "2000-01-01T00:00:00Z"} if mode == "expired"
                    else {"scan_id": "other-scan-MOCK"})
                out = execute_mock_remediation(**dict(
                    s["options"], approval=replace(s["approval"], **changes)))
                self.assertEqual(out["outcome"], "rejected")
                self.assertIsNone(out["e_result"]["approval_id"])
                self.assertEqual(out["recheck_attempts"], [])
                self.assertFalse(out["integration_success"])
                self.assertTrue(out["history_verified"])
                self.assertEqual(s["calls"], [])
                self.assertNotIn("apply", s["backend"].events)

    def test_P03_unsupported_check_is_skipped(self):
        # E43 now supports FILE-01; retain P03's unsupported-policy purpose.
        with self.scenario(check_id="SVC-01") as s:
            out = execute_mock_remediation(**s["options"])
            self.assertEqual(out["outcome"], "skipped")
            self.assertEqual(out["e_result"]["failure_reason"], "check_policy_not_allowed")
            self.assertEqual(out["recheck_attempts"], [])
            self.assertIsNone(out["after_scan_id"])
            self.assertTrue(out["history_verified"])
            self.assertEqual(s["backend"].events, [])
            self.assertFalse(out["integration_success"])

    def test_P04_action_failure_and_single_rollback(self):
        for stage in ("apply", "validate"):
            with self.subTest(stage=stage), self.scenario(fail_at={stage}) as s:
                out = execute_mock_remediation(**s["options"])
                self.assertEqual(out["outcome"], "failed")
                self.assertEqual(out["e_result"]["failed_stage"], stage)
                self.assertEqual(out["e_result"]["rollback"], "verified")
                self.assertEqual(s["backend"].events.count("restore"), 1)
                self.assertTrue(out["manual_recovery_required"])
                self.assertTrue(out["history_verified"])
                self.assertEqual(s["calls"], [])
                self.assertFalse(out["integration_success"])

    def test_P05_diagnosis_exception_and_invalid_candidate(self):
        for mode in ("exception", "cvss", "target"):
            with self.subTest(mode=mode), self.scenario() as s:
                original = s["adapter"].diagnose
                def invalid(request, state):
                    if mode == "exception":
                        raise RuntimeError("untrusted output must not be echoed")
                    report = original(request, state)
                    if mode == "target":
                        report["target_id"] = "wrong-target-MOCK"
                    else:
                        report["results"][0]["cvss"]["base_score"] = 0.0
                    return report
                with patch.object(s["adapter"], "diagnose", side_effect=invalid), patch.object(
                    s["store"], "save", wraps=s["store"].save) as save:
                    out = execute_mock_remediation(**s["options"])
                self.assertEqual(out["outcome"], "failed")
                self.assertEqual(out["e_result"]["failed_stage"], "recheck")
                self.assertTrue(out["manual_recovery_required"])
                self.assertFalse(out["recheck_attempts"][0]["report_verified"])
                self.assertIn(out["recheck_attempts"][0]["failure_stage"], {"diagnose", "validate"})
                save.assert_not_called()
                self.assertTrue(out["history_verified"])

    def test_P06_d_save_failure_keeps_candidate_id(self):
        with self.scenario() as s:
            with patch.object(s["store"], "save", side_effect=PermissionError("private path")) as save:
                out = execute_mock_remediation(**s["options"])
            save.assert_called_once()
            attempt = out["recheck_attempts"][0]
            self.assertEqual(attempt["save_status"], "failed")
            self.assertEqual(attempt["load_status"], "not_attempted")
            self.assertFalse(attempt["report_verified"])
            self.assertEqual(out["after_scan_id"], attempt["scan_id"])
            self.assertIsNotNone(out["after_scan_id"])
            self.assertFalse(out["integration_success"])
            self.assertTrue(out["history_verified"])

    def test_P07_d_load_failure_keeps_saved_report(self):
        with self.scenario() as s:
            load = s["store"].load
            def failed(target, scan_id):
                if scan_id == s["before"]["scan_id"]:
                    return load(target, scan_id)
                raise PermissionError("private path")
            with patch.object(s["store"], "load", side_effect=failed):
                out = execute_mock_remediation(**s["options"])
            attempt = out["recheck_attempts"][0]
            self.assertEqual((attempt["save_status"], attempt["load_status"]), ("success", "failed"))
            self.assertFalse(attempt["report_verified"])
            saved = load(out["target_id"], out["after_scan_id"])
            self.assertEqual(saved["scan_id"], out["after_scan_id"])
            self.assertFalse(out["integration_success"])
            self.assertTrue(out["history_verified"])

    def test_P08_history_save_failure_and_publication_probe(self):
        for published in (False, True):
            with self.subTest(published=published), self.scenario() as s:
                save = s["history"].save
                def failed(record):
                    if published:
                        save(record)
                    raise OSError("sensitive details must not escape")
                with patch.object(s["history"], "save", side_effect=failed) as history_save, patch.object(
                    s["engine"], "run", wraps=s["engine"].run) as run:
                    out = execute_mock_remediation(**s["options"])
                run.assert_called_once()
                history_save.assert_called_once()
                self.assertEqual(out["outcome"], "success")
                self.assertEqual(out["e_result"]["outcome"], "success")
                self.assertFalse(out["integration_success"])
                self.assertIsNone(out["history_saved"])
                self.assertFalse(out["history_verified"])
                self.assertTrue(out["manual_recovery_required"])
                self.assertEqual(out["history_probe"]["state"],
                                 "present_equal" if published else "not_found")
                self.assertNotIn("sensitive", json.dumps(out))
                self.assertEqual(len(s["calls"]), 1)

    def test_P09_duplicate_execution_id_never_runs_e_again(self):
        with self.scenario() as s:
            with patch.object(s["engine"], "run", wraps=s["engine"].run) as run:
                first = execute_mock_remediation(**s["options"])
                record = deepcopy(first["e_result"])
                previous = s["history"].load(first["execution_id"])
                duplicate = persist_mock_execution_history(record, history_store=s["history"])
            run.assert_called_once()
            self.assertEqual(duplicate["error_stage"], "history_conflict")
            self.assertEqual(duplicate["history_probe"]["state"], "present_equal")
            self.assertFalse(duplicate["integration_success"])
            self.assertTrue(duplicate["manual_recovery_required"])
            self.assertEqual(s["history"].load(first["execution_id"]), previous)
            self.assertEqual(duplicate["execution_id"], first["execution_id"])
            self.assertEqual(len(s["calls"]), 1)

    def test_P10_one_owner_for_recheck_and_d_persistence(self):
        with self.scenario() as s:
            with patch.object(s["engine"], "run", wraps=s["engine"].run) as run, patch.object(
                s["adapter"], "recheck", wraps=s["adapter"].recheck) as recheck, patch.object(
                s["store"], "save", wraps=s["store"].save) as save, patch.object(
                s["store"], "load", wraps=s["store"].load) as load:
                out = execute_mock_remediation(**s["options"])
            self.assertTrue(out["integration_success"])
            run.assert_called_once()
            recheck.assert_called_once()
            save.assert_called_once()
            self.assertEqual(load.call_count, 2)  # before + adapter after only
            self.assertEqual(len(s["calls"]), 1)
            self.assertNotIn("recheck_report", run.call_args.kwargs)
            self.assertFalse(run.call_args.kwargs["post_rollback_recheck"])

    def test_P11_after_id_without_verification_is_not_success(self):
        with self.scenario() as s:
            original = s["adapter"].recheck
            def unverified(request, state, attempt, **kwargs):
                report = original(request, state, attempt, **kwargs)
                # Inject inconsistent verification metadata at the trust boundary.
                attempt["report_verified"] = False
                return report
            with patch.object(s["adapter"], "recheck", side_effect=unverified):
                out = execute_mock_remediation(**s["options"])
            self.assertEqual(out["outcome"], "success")
            self.assertIsNotNone(out["after_scan_id"])
            self.assertFalse(out["recheck_attempts"][0]["report_verified"])
            self.assertTrue(out["history_verified"])
            self.assertFalse(out["integration_success"])
            self.assertEqual(out["error_stage"], "recheck_verification")

    def test_P12_history_load_and_content_failure(self):
        for mode in ("load", "content"):
            with self.subTest(mode=mode), self.scenario() as s:
                original = s["history"].load
                def bad(execution_id):
                    if mode == "load":
                        raise PermissionError("private path")
                    return dict(original(execution_id), outcome="failed")
                with patch.object(s["history"], "load", side_effect=bad), patch.object(
                    s["engine"], "run", wraps=s["engine"].run) as run:
                    out = execute_mock_remediation(**s["options"])
                run.assert_called_once()
                self.assertEqual(out["outcome"], "success")
                self.assertTrue(out["history_saved"])
                self.assertFalse(out["history_verified"])
                self.assertFalse(out["integration_success"])
                self.assertEqual(out["error_stage"], "history_load" if mode == "load" else "history_verify")
                self.assertEqual(original(out["execution_id"])["outcome"], "success")
                self.assertEqual(len(s["calls"]), 1)

    def test_P13_rollback_stays_unknown_without_authorized_recheck(self):
        with self.scenario(fail_at={"apply"}) as s:
            with patch.object(s["engine"], "run", wraps=s["engine"].run) as run:
                out = execute_mock_remediation(**s["options"])
            self.assertEqual(out["outcome"], "failed")
            self.assertEqual(out["e_result"]["rollback"], "verified")
            self.assertIsNone(out["e_result"]["final_security_status"])
            self.assertFalse(out["e_result"]["final_security_verified"])
            self.assertIsNone(out["e_result"]["post_rollback_scan_id"])
            self.assertEqual(s["calls"], [])
            self.assertFalse(run.call_args.kwargs["post_rollback_recheck"])
            with self.assertRaises(TypeError):
                execute_mock_remediation(**s["options"], post_rollback_recheck=True)
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
