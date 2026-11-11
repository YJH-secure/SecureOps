import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

from core.main import DiagnosisAggregator


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sample_diagnosis.json"


class DiagnosisAggregatorTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        # 집계 회귀 검증용 합성 v1.1 데이터. 기존 MOCK 파일은 변경하지 않는다.
        self.data.update(schema_version="1.1", scan_id="synthetic-scan-001", os="ubuntu-24.04")
        del self.data["os_type"]
        for item in self.data["results"]:
            item["recommendation"] = item.pop("guide")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "result.json"

    def aggregate(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return DiagnosisAggregator(str(self.path)).aggregate_results()

    def test_mock_rate_and_severity(self):
        summary = self.aggregate(self.data)
        self.assertEqual(summary["metrics"]["pass_rate"], "40.0%")
        self.assertEqual(summary["metrics"]["total_items"], 8)
        self.assertEqual(summary["metrics"]["evaluable_items"], 5)
        self.assertEqual(summary["severity_breakdown"],
                         {"critical": 1, "high": 1, "medium": 0, "low": 1})

    def test_five_statuses(self):
        metrics = self.aggregate(self.data)["metrics"]
        for field, count in {"pass_count": 2, "vulnerable_count": 3,
                             "error_count": 1, "na_count": 1,
                             "needs_review_count": 1}.items():
            with self.subTest(field=field):
                self.assertEqual(metrics[field], count)

    def test_no_evaluable_items(self):
        for results in (self.data["results"][5:],):
            with self.subTest(results=results):
                self.data["results"] = results
                metrics = self.aggregate(self.data)["metrics"]
                self.assertEqual(metrics["evaluable_items"], 0)
                self.assertEqual(metrics["pass_rate"], "N/A (계산 불가)")

    def test_missing_top_level_fields(self):
        for field in ("schema_version", "scan_id", "target_id", "os", "scanned_at", "results"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                del data[field]
                with self.assertRaises(KeyError):
                    self.aggregate(data)

    def test_invalid_top_level_types(self):
        for field in ("schema_version", "scan_id", "target_id", "os", "scanned_at", "results"):
            for value in (None, 1, True, {}):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.data)
                    data[field] = value
                    with self.assertRaises(TypeError):
                        self.aggregate(data)
        with self.assertRaises(ValueError):
            self.aggregate([])

    def test_unsupported_schema_version(self):
        self.data["schema_version"] = "2.0"
        with self.assertRaises(ValueError):
            self.aggregate(self.data)

    def test_missing_result_fields(self):
        for field in ("check_id", "status", "severity", "evidence", "recommendation"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                del data["results"][0][field]
                with self.assertRaises(KeyError):
                    self.aggregate(data)

    def test_invalid_result_types(self):
        for field in ("check_id", "status", "severity", "evidence", "recommendation"):
            for value in (1, [], {}):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.data)
                    data["results"][0][field] = value
                    with self.assertRaises(TypeError):
                        self.aggregate(data)
            data = copy.deepcopy(self.data)
            data["results"][0][field] = None
            with self.assertRaises(TypeError):
                self.aggregate(data)
        self.data["results"] = ["invalid"]
        with self.assertRaises(TypeError):
            self.aggregate(self.data)

    def test_unsupported_status(self):
        self.data["results"][0]["status"] = "unknown"
        with self.assertRaises(ValueError):
            self.aggregate(self.data)

    def test_unsupported_severity(self):
        self.data["results"][0]["severity"] = "urgent"
        with self.assertRaises(ValueError):
            self.aggregate(self.data)

    def test_uppercase_severity_rejected(self):
        for item in self.data["results"]:
            item["severity"] = item["severity"].upper()
        with self.assertRaises(ValueError):
            self.aggregate(self.data)

    def test_invalid_scanned_at(self):
        for value in ("2026-11-05T14:00:00", "not-a-date", "", "2026-13-05T14:00:00+09:00"):
            with self.subTest(value=value):
                self.data["scanned_at"] = value
                with self.assertRaises(ValueError):
                    self.aggregate(self.data)

    def test_utc_scanned_at(self):
        self.data["scanned_at"] = "2026-11-05T05:00:00Z"
        summary = self.aggregate(self.data)
        self.assertEqual(summary["target_info"]["scanned_at"], self.data["scanned_at"])

    def test_json_syntax_error(self):
        self.path.write_text('{"results": [}', encoding="utf-8")
        with self.assertRaises(ValueError):
            DiagnosisAggregator(str(self.path))

    def test_terminal_report_and_existing_fields(self):
        self.aggregate(self.data)
        aggregator = DiagnosisAggregator(str(self.path))
        self.assertEqual(aggregator.data, self.data)
        summary = aggregator.aggregate_results()
        self.assertEqual(summary["target_info"]["ip_address"], self.data["ip_address"])
        self.assertIn("계정 관리", summary["category_breakdown"])
        output = io.StringIO()
        with redirect_stdout(output):
            aggregator.print_summary(summary)
        self.assertIn("40.0%", output.getvalue())
        self.assertIn("CRITICAL", output.getvalue())

    def test_cli_exit_codes(self):
        for valid in (True, False):
            with self.subTest(valid=valid):
                self.path.write_text(json.dumps(self.data) if valid else "{", encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-B", "-X", "utf8", str(ROOT / "core" / "main.py"), str(self.path)],
                    capture_output=True, encoding="utf-8", check=False,
                )
                self.assertEqual(result.returncode, 0 if valid else 1)
                if valid:
                    self.assertIn("40.0%", result.stdout)
                else:
                    self.assertIn("JSON", result.stderr)

    def test_official_mock(self):
        # 원본은 수정하거나 체크아웃하지 않고 로컬 원격 추적 커밋에서 읽는다.
        raw = subprocess.run(
            ["git", "show", "origin/main:tests/fixtures/sample-result-v1.1-MOCK.json"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout
        data = json.loads(raw.decode("utf-8"))
        summary = self.aggregate(data)
        self.assertEqual(summary["metrics"]["pass_rate"], "0.0%")
        self.assertEqual(summary["metrics"]["needs_review_count"], 1)
        self.assertEqual(summary["severity_breakdown"]["high"], 1)
        report = DiagnosisAggregator(str(self.path)).get_report()
        self.assertEqual(report, data)
        self.assertNotIn("metrics", report)
        self.assertIn("details", report["results"][1])

    def test_legacy_rejected(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(ValueError, "scan_id.*os.*recommendation"):
            self.aggregate(data)

    def test_duplicate_check_id(self):
        self.data["results"].append(copy.deepcopy(self.data["results"][0]))
        with self.assertRaisesRegex(ValueError, "중복 check_id"):
            self.aggregate(self.data)

    def test_empty_results(self):
        self.data["results"] = []
        with self.assertRaises(ValueError):
            self.aggregate(self.data)

    def test_empty_strings(self):
        for field in ("schema_version", "scan_id", "target_id", "os", "scanned_at", "ip_address"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                data[field] = ""
                with self.assertRaises(ValueError):
                    self.aggregate(data)
        for field in ("check_id", "status", "severity", "evidence", "recommendation", "category", "title", "checked_at"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                data["results"][0][field] = ""
                with self.assertRaises(ValueError):
                    self.aggregate(data)

    def test_extra_fields(self):
        for field in ("server_id", "os_type", "checked_at", "metrics", "unknown"):
            data = copy.deepcopy(self.data)
            data[field] = "legacy"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.aggregate(data)
        for field in ("guide", "unknown"):
            data = copy.deepcopy(self.data)
            data["results"][0][field] = "legacy"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.aggregate(data)

    def test_optional_fields(self):
        for field, invalid in (("category", 1), ("title", None), ("checked_at", []), ("details", [])):
            data = copy.deepcopy(self.data)
            data["results"][0][field] = invalid
            with self.subTest(field=field), self.assertRaises(TypeError):
                self.aggregate(data)
        self.data["ip_address"] = None
        with self.assertRaises(TypeError):
            self.aggregate(self.data)

    def test_checked_at_and_strict_timestamp(self):
        for field in ("scanned_at", "checked_at"):
            for value in ("2026-11-06T10:00:00", "2026-11-06 10:00:00+09:00",
                          "2026-02-30T10:00:00+09:00", "2026-11-06T10:00:00+09:99"):
                data = copy.deepcopy(self.data)
                target = data if field == "scanned_at" else data["results"][0]
                target[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.aggregate(data)
        self.data["results"][0]["checked_at"] = "2026-11-06T10:00:00Z"
        self.aggregate(self.data)

    def test_status_case_and_whitespace_rejected(self):
        for value in ("PASS", " pass ", "Needs_Review"):
            self.data["results"][0]["status"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.aggregate(self.data)

    def test_report_copy_and_details(self):
        self.data["results"][0]["details"] = {"files": [{"path": "mock"}]}
        self.aggregate(self.data)
        aggregator = DiagnosisAggregator(str(self.path))
        report = aggregator.get_report()
        self.assertEqual(report, self.data)
        report["results"][0]["details"]["files"].clear()
        self.assertEqual(aggregator.data, self.data)


if __name__ == "__main__":
    unittest.main()
