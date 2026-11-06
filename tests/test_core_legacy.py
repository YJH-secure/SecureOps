import copy
import json
from pathlib import Path
import tempfile
import unittest

from core.legacy import normalize_legacy_report
from core.main import DiagnosisAggregator


class LegacyNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "schema_version": "1.0", "scan_id": "old-scan-001",
            "server_id": "ubuntu-mock", "os_type": "ubuntu-24.04",
            "checked_at": "2026-11-06T10:00:00+09:00",
            "results": [{
                "check_id": "FILE-01", "status": "needs_review", "severity": "HIGH",
                "evidence": "MOCK: policy pending", "guide": "MOCK: 기준 승인 후 재진단",
                "checked_at": "2026-11-06T09:59:00+09:00",
                "details": {"files": [{"path": "/etc/shadow", "judgement": "needs_review"}]},
            }],
        }

    def test_normalization_and_existing_loader(self):
        report = normalize_legacy_report(self.data)
        self.assertEqual(report["schema_version"], "1.1")
        self.assertEqual(report["scan_id"], self.data["scan_id"])
        for old, new in (("server_id", "target_id"), ("os_type", "os"), ("checked_at", "scanned_at")):
            self.assertNotIn(old, report)
            self.assertEqual(report[new], self.data[old])
        item = report["results"][0]
        self.assertNotIn("guide", item)
        self.assertEqual(item["recommendation"], self.data["results"][0]["guide"])
        self.assertEqual(item["severity"], "high")
        for field in ("check_id", "status", "evidence", "details", "checked_at"):
            self.assertEqual(item[field], self.data["results"][0][field])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            aggregator = DiagnosisAggregator(str(path))
            self.assertEqual(json.loads(aggregator.to_json()), report)
            self.assertEqual(aggregator.aggregate_results()["metrics"]["needs_review_count"], 1)

    def test_original_preserved_and_nested_copy(self):
        original = copy.deepcopy(self.data)
        report = normalize_legacy_report(self.data)
        self.assertEqual(self.data, original)
        report["results"][0]["details"]["files"].clear()
        self.assertEqual(self.data, original)

    def test_all_field_conflicts_and_failure_preserves_input(self):
        for old, new in (("server_id", "target_id"), ("os_type", "os"),
                         ("checked_at", "scanned_at"), ("guide", "recommendation")):
            data = copy.deepcopy(self.data)
            target = data["results"][0] if old == "guide" else data
            target[new] = "different"
            before = copy.deepcopy(data)
            with self.subTest(field=old), self.assertRaisesRegex(ValueError, "충돌"):
                normalize_legacy_report(data)
            self.assertEqual(data, before)

    def test_equal_aliases_removed(self):
        for old, new in (("server_id", "target_id"), ("os_type", "os"), ("checked_at", "scanned_at")):
            self.data[new] = self.data[old]
        self.data["results"][0]["recommendation"] = self.data["results"][0]["guide"]
        report = normalize_legacy_report(self.data)
        self.assertNotIn("server_id", report)
        self.assertNotIn("guide", report["results"][0])

    def test_missing_information(self):
        for field in ("schema_version", "scan_id", "server_id", "os_type", "checked_at", "results"):
            data = copy.deepcopy(self.data)
            del data[field]
            with self.subTest(field=field), self.assertRaises(KeyError):
                normalize_legacy_report(data)
        del self.data["results"][0]["guide"]
        with self.assertRaisesRegex(KeyError, "recommendation"):
            normalize_legacy_report(self.data)

    def test_os_version_not_invented(self):
        for value in ("ubuntu", "rocky", "", "ubuntu-latest"):
            self.data["os_type"] = value
            with self.subTest(os=value), self.assertRaises(ValueError):
                normalize_legacy_report(self.data)

    def test_wrong_types(self):
        for field in ("schema_version", "scan_id", "server_id", "os_type", "checked_at", "results"):
            data = copy.deepcopy(self.data)
            data[field] = 123
            with self.subTest(field=field), self.assertRaises(TypeError):
                normalize_legacy_report(data)
        for field in ("guide", "severity", "evidence", "details"):
            data = copy.deepcopy(self.data)
            data["results"][0][field] = []
            with self.subTest(field=field), self.assertRaises(TypeError):
                normalize_legacy_report(data)
        for value in (None, [], "report"):
            with self.assertRaises(TypeError):
                normalize_legacy_report(value)
        self.data["results"] = [None]
        with self.assertRaises(TypeError):
            normalize_legacy_report(self.data)

    def test_states_unchanged_and_case_not_corrected(self):
        for status in ("pass", "vulnerable", "error", "not_applicable", "needs_review"):
            self.data["results"][0]["status"] = status
            self.assertEqual(normalize_legacy_report(self.data)["results"][0]["status"], status)
        self.data["results"][0]["status"] = "PASS"
        with self.assertRaises(ValueError):
            normalize_legacy_report(self.data)

    def test_severities_and_strict_final_validation(self):
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            self.data["results"][0]["severity"] = severity
            self.assertEqual(normalize_legacy_report(self.data)["results"][0]["severity"], severity.lower())
        for severity in ("urgent", " HIGH "):
            self.data["results"][0]["severity"] = severity
            with self.assertRaises(ValueError):
                normalize_legacy_report(self.data)

    def test_final_validator_rejects_duplicate_extra_empty_and_naive_time(self):
        for change in ("duplicate", "extra", "empty", "time"):
            data = copy.deepcopy(self.data)
            if change == "duplicate":
                data["results"].append(copy.deepcopy(data["results"][0]))
            elif change == "extra":
                data["unknown"] = "value"
            elif change == "empty":
                data["results"] = []
            else:
                data["checked_at"] = "2026-11-06T10:00:00"
            with self.subTest(change=change), self.assertRaises(ValueError):
                normalize_legacy_report(data)

    def test_modern_report_idempotent_and_unknown_version_rejected(self):
        report = normalize_legacy_report(self.data)
        self.assertEqual(normalize_legacy_report(report), report)
        self.data["schema_version"] = "9.0"
        with self.assertRaises(ValueError):
            normalize_legacy_report(self.data)


if __name__ == "__main__":
    unittest.main()
