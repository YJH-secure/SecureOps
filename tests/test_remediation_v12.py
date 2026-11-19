"""E v1.2 단위·CLI 및 현재 main의 D 저장소 연동 검증. 모든 조치는 MOCK."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from core.cvss_validation import validate_report as validate_d_report
from core.main import DiagnosisAggregator
from core.storage import ReportStore
from remediation import Approval, MockBackend, Remediator, build_plan, compare_reports
from remediation.contract import validate_report


ROOT = Path(__file__).resolve().parents[1]


def mock_report():
    return json.loads((ROOT / "tests/fixtures/sample-result-v1.2-MOCK.json").read_text(encoding="utf-8"))


class RemediationV12Tests(unittest.TestCase):
    def setUp(self):
        self.before = mock_report()
        self.plan = build_plan(self.before, "SSH-01")
        self.approval = Approval(
            "v12-approval-MOCK", "v12-admin-MOCK", self.plan.target_id,
            self.plan.scan_id, self.plan.plan_id, "2099-01-01T00:00:00Z", True,
        )
        self.engine = Remediator(
            allowed_targets={self.plan.target_id}, allowed_checks={"SSH-01"},
            verify_approval=lambda record: record == self.approval,
        )
        self.backend = MockBackend(
            target_id=self.plan.target_id, os=self.plan.os, files={},
            access_verified=True, snapshot_verified=True, include_verified=True,
        )

    def run_mock(self, **kwargs):
        options = dict(backend=self.backend, approval=self.approval, dry_run=False)
        options.update(kwargs)
        return self.engine.run(self.before, self.plan, **options)

    def test_pending_input_and_pass_recheck(self):
        original = deepcopy(self.before)
        result = self.run_mock()
        self.assertEqual(result["outcome"], "success")
        after = result["after_report"]
        validate_d_report(after)
        self.assertEqual(after["schema_version"], "1.2")
        self.assertEqual(after["target_id"], original["target_id"])
        self.assertNotEqual(after["scan_id"], original["scan_id"])
        item = after["results"][0]
        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["cvss"]["assessment_status"], "not_applicable")
        self.assertNotIn("severity", item)
        self.assertIsNone(item["cvss"]["base_score"])
        self.assertTrue(result["comparison"]["improved"])
        self.assertEqual(self.before, original)

    def test_scored_fixture_and_evidence_are_preserved(self):
        original = deepcopy(self.before)
        validate_report(self.before)
        self.run_mock()
        self.assertEqual(self.before, original)
        scored = self.before["results"][-1]
        self.assertEqual(scored["cvss"]["assessment_status"], "scored")
        self.assertEqual(scored["cvss"]["base_score"], 9.8)
        self.assertEqual(scored["cvss"], original["results"][-1]["cvss"])

    def test_unscored_vulnerable_item_is_still_eligible(self):
        incoming = deepcopy(self.before)
        incoming["results"][0]["cvss"]["assessment_status"] = "not_applicable"
        incoming["results"][0]["cvss"]["rationale"] = "MOCK: policy compliance finding"
        plan = build_plan(incoming, "SSH-01")
        self.assertTrue(plan.actions)
        self.assertIsNone(incoming["results"][0]["cvss"]["base_score"])

    def test_nonvulnerable_states_are_excluded(self):
        for status in ("pass", "error", "needs_review", "not_applicable"):
            with self.subTest(status=status):
                incoming = deepcopy(self.before)
                incoming["results"][0]["status"] = status
                incoming["results"][0]["cvss"]["assessment_status"] = "not_applicable"
                plan = build_plan(incoming, "SSH-01")
                result = self.engine.run(incoming, plan, backend=self.backend, dry_run=False)
                self.assertEqual(result["outcome"], "skipped")
                self.assertIsNone(result["after_report"])
        self.assertEqual(self.backend.events, [])

    def test_invalid_cvss_or_severity_is_rejected(self):
        for field, value in (("vector", "invalid"), ("base_score", 1.0),
                             ("base_score", True), ("rating", "low")):
            with self.subTest(field=field, value=value):
                incoming = deepcopy(self.before)
                incoming["results"][-1]["cvss"][field] = value
                with self.assertRaises((ValueError, TypeError)):
                    build_plan(incoming, "SSH-01")
        incoming = deepcopy(self.before)
        incoming["results"][0]["severity"] = "high"
        with self.assertRaises(ValueError):
            validate_report(incoming)

    def test_null_is_not_zero_and_scored_requires_a_score(self):
        incoming = deepcopy(self.before)
        incoming["results"][0]["cvss"]["base_score"] = 0.0
        with self.assertRaises(ValueError):
            validate_report(incoming)
        incoming = deepcopy(self.before)
        incoming["results"][-1]["cvss"]["base_score"] = None
        with self.assertRaises(TypeError):
            validate_report(incoming)
        self.assertIsNone(self.before["results"][0]["cvss"]["base_score"])

    def test_valid_zero_score_remains_distinct_from_null(self):
        incoming = deepcopy(self.before)
        cvss = incoming["results"][-1]["cvss"]
        # 영향이 모두 N인 계산기 검증용 합성 사례. 실제 SSH 점수를 배정하지 않는다.
        cvss.update(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    base_score=0.0, rating="none", rationale="MOCK: zero-impact calculator test")
        validate_report(incoming)
        self.assertEqual(cvss["base_score"], 0.0)
        self.assertIsNone(incoming["results"][0]["cvss"]["base_score"])
        self.assertEqual(build_plan(incoming, "CVSS-MOCK-01").actions, ())

    def test_cvss_update_requires_a_new_plan_and_approval(self):
        changed = deepcopy(self.before)
        changed["results"][0]["cvss"]["rationale"] += " MOCK: evidence updated"
        with self.assertRaisesRegex(ValueError, "stale"):
            self.engine.run(changed, self.plan, backend=self.backend,
                            approval=self.approval, dry_run=False)
        new_plan = build_plan(changed, "SSH-01")
        result = self.engine.run(changed, new_plan, backend=self.backend,
                                 approval=self.approval, dry_run=False)
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(result["failure_reason"], "approval_binding_mismatch")
        self.assertEqual(self.backend.events, [])

    def test_legacy_report_does_not_accept_cvss(self):
        legacy = deepcopy(self.before)
        legacy["schema_version"] = "1.1"
        legacy["results"] = [legacy["results"][0]]
        legacy["results"][0]["severity"] = "high"
        with self.assertRaises(ValueError):
            validate_report(legacy)

    def test_mixed_versions_cannot_be_compared(self):
        legacy_item = {"check_id": "SSH-01", "status": "vulnerable", "severity": "high",
                       "evidence": "MOCK", "recommendation": "MOCK"}
        legacy = DiagnosisAggregator.from_results(
            [legacy_item], [], target_id=self.before["target_id"], os=self.before["os"],
            scanned_at="2026-11-01T00:00:00Z",
        ).get_report()
        with self.assertRaisesRegex(ValueError, "schema version"):
            compare_reports(legacy, self.before, "SSH-01")
        with self.assertRaisesRegex(ValueError, "schema version"):
            compare_reports(self.before, legacy, "SSH-01")

    def test_high_scored_calculator_fixture_is_excluded(self):
        plan = build_plan(self.before, "CVSS-MOCK-01")
        result = self.engine.run(self.before, plan, backend=self.backend, dry_run=False)
        self.assertEqual(result["outcome"], "skipped")
        self.assertEqual(result["failure_reason"], "check_policy_not_allowed")
        self.assertEqual(self.backend.events, [])

    def test_approval_denial_and_failure_recovery(self):
        rejected = self.run_mock(approval=replace(self.approval, approved=False))
        self.assertEqual(rejected["outcome"], "rejected")
        self.assertEqual(self.backend.events, [])
        for failure, rollback in (("backup", "not_needed"), ("apply", "verified"),
                                  ("validate", "verified"), ("recheck", "verified")):
            with self.subTest(failure=failure):
                self.setUp()
                self.backend.fail_at = {failure}
                result = self.run_mock()
                self.assertEqual(result["outcome"], "failed")
                self.assertEqual(result["rollback"], rollback)
                self.assertEqual(result["failed_stage"], failure)
                self.assertIsNone(result["after_report"])
                self.assertEqual(self.backend.root_login, "yes")

    def test_callback_result_is_validated_and_keeps_details(self):
        def callback(target_id, check_id, files, root_login):
            item = deepcopy(self.before["results"][0])
            item.update(status="pass", evidence="MOCK: callback confirmed root login restriction")
            item["cvss"]["assessment_status"] = "not_applicable"
            item["cvss"]["rationale"] = "MOCK: recheck is pass"
            item["details"] = {"setting": "PermitRootLogin", "expected": "no", "root_value": root_login}
            return item
        self.backend.recheck_callback = callback
        result = self.run_mock()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["after_report"]["results"][0]["details"]["root_value"], "no")

    def test_wrong_version_callback_result_fails_and_restores(self):
        self.backend.recheck_callback = lambda *args: {
            "check_id": "SSH-01", "status": "pass", "severity": "high",
            "evidence": "MOCK", "recommendation": "MOCK",
        }
        result = self.run_mock()
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["rollback"], "verified")
        self.assertEqual(result["failure_reason"], "invalid_recheck_result")
        self.assertIsNone(result["after_report"])

    def test_d_v12_save_load_and_compare_round_trip(self):
        # 새 브랜치에 반영한 최신 main의 실제 D 구현을 사용한다.
        incoming = DiagnosisAggregator.from_results(
            self.before["results"], [], target_id=self.before["target_id"], os=self.before["os"],
            scanned_at=self.before["scanned_at"], schema_version="1.2",
        ).get_report()
        with TemporaryDirectory(prefix="secureops-e-v12-") as directory:
            store = ReportStore(directory)
            store.save(incoming)
            loaded = store.load(incoming["target_id"], incoming["scan_id"])
            plan = build_plan(loaded, "SSH-01")
            self.approval = replace(self.approval, scan_id=plan.scan_id, plan_id=plan.plan_id)
            result = self.engine.run(loaded, plan, backend=self.backend,
                                     approval=self.approval, dry_run=False)
            self.assertEqual(result["outcome"], "success")
            after = result["after_report"]
            store.save(after)
            self.assertEqual(store.load(after["target_id"], after["scan_id"]), after)
            matched = store.match_results(incoming["target_id"], incoming["scan_id"], after["scan_id"])
            self.assertEqual(matched["SSH-01"]["before"]["status"], "vulnerable")
            self.assertEqual(matched["SSH-01"]["after"]["status"], "pass")
            self.assertNotEqual(incoming["scan_id"], after["scan_id"])
            self.assertEqual(store.load(incoming["target_id"], incoming["scan_id"]), incoming)
            self.assertEqual(len(store.history(incoming["target_id"])), 2)

    def test_cli_v12_preview_and_mock(self):
        for args in (("--report", "tests/fixtures/sample-result-v1.2-MOCK.json"),
                     ("--mock", "--result-version", "1.2")):
            with self.subTest(args=args):
                output = subprocess.check_output([sys.executable, "-B", "-m", "remediation", *args], cwd=ROOT)
                result = json.loads(output)
                self.assertEqual(result["outcome"], "success" if "--mock" in args else "planned")
                if result["after_report"]:
                    self.assertEqual(result["after_report"]["schema_version"], "1.2")

    def test_cli_v12_denial_skip_and_failure_scenarios(self):
        scenarios = [(('--deny',), 'rejected'), (('--skip',), 'skipped')]
        scenarios += [(('--fail-at', stage), 'failed')
                      for stage in ('backup', 'apply', 'validate', 'recheck', 'verify_service')]
        for args, expected in scenarios:
            with self.subTest(args=args):
                output = subprocess.check_output(
                    [sys.executable, '-B', '-m', 'remediation', '--mock', '--result-version', '1.2', *args],
                    cwd=ROOT,
                )
                result = json.loads(output)
                self.assertEqual(result['outcome'], expected)
                self.assertIsNone(result['after_report'])

    def test_cli_rejects_duplicate_json_keys(self):
        text = json.dumps(self.before).replace('"schema_version": "1.2"',
                                                '"schema_version": "1.2", "schema_version": "1.2"', 1)
        with TemporaryDirectory(prefix="secureops-e-v12-json-") as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(text, encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", "-m", "remediation", "--report", str(path)],
                                    cwd=ROOT, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Duplicate JSON key", result.stderr)


if __name__ == "__main__":
    unittest.main()
