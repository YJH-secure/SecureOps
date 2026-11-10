"""Synthetic reviewed/unreviewed metric inputs, no collection or B/C inference."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core.cvss import METRICS
from core.cvss_assessment import assess_cvss
from core.main import DiagnosisAggregator
from core.runner import run_target
from core.storage import ReportStore


VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class CVSSAssessmentTests(unittest.TestCase):
    def setUp(self):
        # Only calculator fixtures: not approved facts about any real target.
        self.evidence = {name: f"MOCK reviewed premise for {name}" for name in METRICS}
        self.arguments = dict(status="vulnerable", cvss_applicable=True,
            rationale="MOCK calculator scenario; explicit synthetic review",
            source="MOCK evaluation record", vector=VECTOR,
            metric_evidence=self.evidence, evidence_sufficient=True)

    def assert_unscored(self, result, assessment):
        self.assertEqual(result["assessment_status"], assessment)
        for key in ("version", "vector", "base_score", "rating"):
            self.assertIsNone(result[key], key)
        self.assertTrue(result["rationale"].strip())

    def validate_item(self, status, cvss):
        return DiagnosisAggregator.from_results([{
            "check_id": "MOCK-01", "status": status, "evidence": "MOCK observation",
            "recommendation": "MOCK review", "cvss": cvss}], [],
            target_id="mock", os="ubuntu-24.04", schema_version="1.2")

    def test_reviewed_metrics_produce_official_score_and_preserve_evidence(self):
        before = copy.deepcopy(self.arguments)
        result = assess_cvss(**self.arguments)
        self.assertEqual((result["base_score"], result["rating"]), (9.8, "critical"))
        self.assertEqual(self.arguments, before)
        for name, evidence in self.evidence.items():
            self.assertIn(f"{name}: {evidence}", result["rationale"])
        self.validate_item("vulnerable", result)

    def test_every_missing_metric_reason_prevents_calculation(self):
        for name in METRICS:
            evidence = dict(self.evidence)
            del evidence[name]
            with self.subTest(metric=name), patch("core.cvss_assessment.base_score") as calculate:
                result = assess_cvss(**{**self.arguments, "metric_evidence": evidence})
                self.assert_unscored(result, "pending")
                self.assertIn(name, result["rationale"])
                calculate.assert_not_called()
                self.validate_item("vulnerable", result)

    def test_empty_metric_reasons_remain_pending(self):
        for reason in (None, "", " "):
            evidence = {**self.evidence, "AV": reason}
            self.assert_unscored(assess_cvss(**{**self.arguments, "metric_evidence": evidence}), "pending")

    def test_missing_vector_does_not_infer_metrics(self):
        with patch("core.cvss_assessment.base_score") as calculate:
            self.assert_unscored(assess_cvss(**{**self.arguments, "vector": None}), "pending")
            calculate.assert_not_called()

    def test_missing_source_remains_pending(self):
        self.assert_unscored(assess_cvss(**{**self.arguments, "source": None}), "pending")

    def test_present_text_does_not_imply_sufficient_evidence(self):
        arguments = dict(self.arguments)
        del arguments["evidence_sufficient"]
        with patch("core.cvss_assessment.base_score") as calculate:
            self.assert_unscored(assess_cvss(**arguments), "pending")
            calculate.assert_not_called()

    def test_policy_violation_and_nonvulnerable_states_are_not_applicable(self):
        for status in ("vulnerable", "pass", "error", "not_applicable", "needs_review"):
            with self.subTest(status=status), patch("core.cvss_assessment.base_score") as calculate:
                result = assess_cvss(status=status, cvss_applicable=False,
                    rationale="MOCK policy-only or nonvulnerable diagnosis")
                self.assert_unscored(result, "not_applicable")
                calculate.assert_not_called()
                self.validate_item(status, result)

    def test_no_evidence_and_no_metrics_still_valid_pending(self):
        result = assess_cvss(status="vulnerable", cvss_applicable=True,
                             rationale="MOCK attack premises not yet established")
        self.assert_unscored(result, "pending")
        self.validate_item("vulnerable", result)

    def test_malformed_supplied_vector_is_not_silently_downgraded(self):
        with self.assertRaises(ValueError):
            assess_cvss(**{**self.arguments, "vector": VECTOR.rsplit("/", 1)[0]})

    def test_invalid_classifications_and_evidence_are_rejected(self):
        for changes in ({"cvss_applicable": 1}, {"evidence_sufficient": "yes"},
                        {"status": "pass"}, {"rationale": " "}, {"source": ""},
                        {"metric_evidence": {"AV": True}}, {"metric_evidence": []},
                        {"metric_evidence": {"severity": "high"}}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                assess_cvss(**{**self.arguments, **changes})

    def test_nonapplicable_cannot_silently_discard_supplied_score_inputs(self):
        with self.assertRaises(ValueError):
            assess_cvss(**{**self.arguments, "cvss_applicable": False})

    def test_scored_zero_is_distinct_from_unassessed_null(self):
        vector = VECTOR.replace("C:H/I:H/A:H", "C:N/I:N/A:N")
        zero = assess_cvss(**{**self.arguments, "vector": vector})
        pending = assess_cvss(**{**self.arguments, "evidence_sufficient": False})
        self.assertEqual((zero["base_score"], zero["rating"]), (0.0, "none"))
        self.assert_unscored(pending, "pending")

    def test_assessments_to_runner_preserve_diagnosis_and_details(self):
        reviewed = assess_cvss(**self.arguments)
        pending = assess_cvss(**{**self.arguments, "evidence_sufficient": False})
        policy_only = assess_cvss(status="vulnerable", cvss_applicable=False,
                                  rationale="MOCK compliance issue outside CVSS scope")
        items = [dict(check_id=name, status="vulnerable", evidence="MOCK observation",
            recommendation="MOCK review", details={"files": [{"path": "/etc/shadow",
            "observations": ["MOCK original"]}]}, cvss=cvss)
            for name, cvss in zip(("MOCK-SCORED", "MOCK-PENDING", "FILE-01"),
                                  (reviewed, pending, policy_only))]
        before = copy.deepcopy(items)
        with tempfile.TemporaryDirectory() as directory:
            result = run_target(account_checks=[lambda: items[0]],
                system_checks=[lambda: items[1], lambda: items[2]],
                target_id="mock", os="ubuntu-24.04", output_root=directory,
                mode="mock", schema_version="1.2", scan_id="assessed")
            self.assertEqual(items, before)
            self.assertEqual(result.report["results"], before)
            self.assertEqual(result.summary["cvss_assessment_breakdown"],
                             {"scored": 1, "pending": 1, "not_applicable": 1})
            self.assertEqual(result.summary["cvss_rating_breakdown"]["critical"], 1)
            items[2]["details"]["files"].clear()
            saved = ReportStore(Path(directory) / "mock").load("mock", "assessed")
            self.assertEqual(saved["results"], before)


if __name__ == "__main__":
    unittest.main()
