import copy
import json
import unittest
from datetime import datetime, timezone
from uuid import UUID

from core.main import DiagnosisAggregator


class ResultIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.account = [{
            "check_id": "SSH-01", "status": "vulnerable", "severity": "high",
            "evidence": "MOCK: root login allowed",
            "recommendation": "MOCK: 승인된 SSH 정책 검토",
        }]
        self.system = [{
            "check_id": "FILE-01", "status": "needs_review", "severity": "high",
            "evidence": "MOCK: shadow policy pending",
            "recommendation": "MOCK: OS별 기준 승인 후 재진단",
            "details": {"files": [
                {"path": "/etc/passwd", "judgement": "pass"},
                {"path": "/etc/shadow", "judgement": "needs_review",
                 "acl": {"entries": ["MOCK"], "mode": "0640"}},
            ]},
        }]
        self.metadata = {
            "target_id": "ubuntu-mock", "os": "ubuntu-24.04",
            "scan_id": "mock-scan-001", "scanned_at": "2026-11-06T10:00:00+09:00",
        }

    def build(self, **metadata):
        return DiagnosisAggregator.from_results(
            self.account, self.system, **{**self.metadata, **metadata})

    def test_combined_report_and_json_roundtrip(self):
        aggregator = self.build()
        report = aggregator.get_report()
        self.assertEqual(report, {
            **self.metadata, "schema_version": "1.1",
            "results": self.account + self.system,
        })
        self.assertEqual(json.loads(aggregator.to_json()), report)
        self.assertNotIn("metrics", report)
        summary = aggregator.aggregate_results()
        self.assertEqual(summary["metrics"]["total_items"], 2)
        self.assertEqual(summary["metrics"]["pass_rate"], "0.0%")
        self.assertEqual(summary["metrics"]["needs_review_count"], 1)
        self.assertEqual(summary["severity_breakdown"]["high"], 1)

    def test_details_and_input_are_independent(self):
        expected = copy.deepcopy(self.account + self.system)
        aggregator = self.build()
        self.assertEqual(self.account + self.system, expected)
        self.system[0]["details"]["files"].clear()
        self.account[0]["status"] = "pass"
        self.assertEqual(aggregator.get_report()["results"], expected)

    def test_error_and_review_never_become_pass(self):
        self.account[0]["status"] = "error"
        aggregator = self.build()
        self.assertEqual([r["status"] for r in aggregator.get_report()["results"]],
                         ["error", "needs_review"])
        metrics = aggregator.aggregate_results()["metrics"]
        self.assertEqual(metrics["error_count"], 1)
        self.assertEqual(metrics["needs_review_count"], 1)
        self.assertEqual(metrics["pass_count"], 0)
        self.assertEqual(metrics["pass_rate"], "N/A (계산 불가)")

    def test_generated_execution_metadata(self):
        before = datetime.now(timezone.utc)
        first = self.build(scan_id=None, scanned_at=None).get_report()
        second = self.build(scan_id=None, scanned_at=None).get_report()
        after = datetime.now(timezone.utc)
        self.assertEqual(UUID(first["scan_id"]).version, 4)
        self.assertNotEqual(first["scan_id"], second["scan_id"])
        self.assertEqual(first["target_id"], second["target_id"])
        self.assertLessEqual(before, datetime.fromisoformat(first["scanned_at"]))
        self.assertLessEqual(datetime.fromisoformat(first["scanned_at"]), after)

    def test_duplicate_across_modules_rejected(self):
        self.system[0]["check_id"] = "SSH-01"
        with self.assertRaisesRegex(ValueError, "중복 check_id"):
            self.build()

    def test_invalid_groups(self):
        for invalid in (None, {}, "results", (), self.account[0]):
            for groups in ((invalid, self.system), (self.account, invalid)):
                with self.subTest(groups=groups), self.assertRaises(TypeError):
                    DiagnosisAggregator.from_results(*groups, **self.metadata)

    def test_empty_groups(self):
        with self.assertRaises(ValueError):
            DiagnosisAggregator.from_results([], [], **self.metadata)
        aggregator = DiagnosisAggregator.from_results([], self.system, **self.metadata)
        self.assertEqual(aggregator.get_report()["results"], self.system)

    def test_invalid_items(self):
        for invalid in (None, "result", {}, {**self.account[0], "severity": "HIGH"},
                        {**self.account[0], "status": "unknown"},
                        {**self.account[0], "details": []},
                        {**self.account[0], "guide": "legacy"}):
            with self.subTest(item=invalid), self.assertRaises((TypeError, ValueError, KeyError)):
                DiagnosisAggregator.from_results([invalid], self.system, **self.metadata)
        del self.account[0]["recommendation"]
        with self.assertRaises(KeyError):
            self.build()

    def test_invalid_metadata_not_replaced(self):
        for field, value in (("target_id", None), ("os", None), ("scan_id", ""),
                             ("scanned_at", ""), ("scanned_at", "2026-11-06T10:00:00")):
            with self.subTest(field=field), self.assertRaises((TypeError, ValueError)):
                self.build(**{field: value})

    def test_non_json_details_rejected(self):
        self.system[0]["details"] = {"invalid": {1, 2}}
        with self.assertRaises(TypeError):
            self.build()


if __name__ == "__main__":
    unittest.main()
