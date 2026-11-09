import copy
import json
from pathlib import Path
import tempfile
import unittest

from core.main import DiagnosisAggregator
from core.remote_result import RemoteResultError, parse_result_json
from core.runner import RunFailed, run_target
from core.storage import ReportStore


class RemoteResultTests(unittest.TestCase):
    def setUp(self):
        self.item = {"check_id": "FILE-01", "status": "needs_review", "severity": "high",
                     "evidence": "MOCK: 검토 필요", "recommendation": "MOCK: 승인 기준 확인",
                     "details": {"files": [{"path": "/etc/shadow", "mode": "0640"}]}}

    def parse(self, text=None, **options):
        return parse_result_json(json.dumps(self.item) if text is None else text,
                                 **{**dict(exit_code=0, execution_succeeded=True), **options})

    def test_valid_json_preserved(self):
        before = copy.deepcopy(self.item)
        text = json.dumps(self.item, ensure_ascii=False)
        result = self.parse(" \n" + text + "\n")
        self.assertEqual(result, before)
        result["details"]["files"].clear()
        self.assertEqual(self.item, before)
        self.assertEqual(json.loads(text), before)

    def test_invalid_json_and_mixed_output(self):
        for text in ("", " ", "{", "MOCK log\n" + json.dumps(self.item),
                     json.dumps(self.item) + "\n{}", "```json\n{}\n```", "\ufeff{}"):
            with self.subTest(text=text), self.assertRaises(RemoteResultError):
                self.parse(text)

    def test_non_object(self):
        for value in ([], [self.item], None, "string", 1, True):
            with self.subTest(value=value), self.assertRaises(RemoteResultError):
                self.parse(json.dumps(value))

    def test_missing_required_fields(self):
        for field in ("check_id", "status", "severity", "evidence", "recommendation"):
            item = copy.deepcopy(self.item)
            del item[field]
            with self.subTest(field=field), self.assertRaises(RemoteResultError):
                self.parse(json.dumps(item))

    def test_invalid_types_and_values(self):
        for field, value in (("check_id", 1), ("evidence", {}), ("recommendation", None),
                             ("status", "PASS"), ("severity", "HIGH"), ("details", []),
                             ("checked_at", "2026-11-09T10:00:00"), ("guide", "old")):
            with self.subTest(field=field), self.assertRaises(RemoteResultError):
                self.parse(json.dumps({**self.item, field: value}))
        with self.assertRaises(RemoteResultError):
            self.parse('{"schema_version":"1.1","results":[]}')

    def test_execution_failure_overrides_valid_pass_json(self):
        self.item["status"] = "pass"
        for code in (1, 2, -9, 255):
            with self.subTest(code=code), self.assertRaises(RemoteResultError):
                self.parse(exit_code=code)
        with self.assertRaises(RemoteResultError):
            self.parse(execution_succeeded=False)

    def test_explicit_execution_metadata_types(self):
        for code in (None, True, "0", 0.0):
            with self.subTest(code=code), self.assertRaises(TypeError):
                self.parse(exit_code=code)
        for success in (None, 1, "true"):
            with self.subTest(success=success), self.assertRaises(TypeError):
                self.parse(execution_succeeded=success)
        for value in (b"{}", {}, [], 1):
            with self.assertRaises(TypeError):
                parse_result_json(value, exit_code=0, execution_succeeded=True)

    def test_duplicate_keys_at_any_depth(self):
        for text in ('{"status":"pass","status":"error"}',
                     '{"details":{"mode":1,"mode":2}}'):
            with self.assertRaises(RemoteResultError):
                self.parse(text)

    def test_nonfinite_numbers(self):
        for number in ("NaN", "Infinity", "-Infinity", "1e999"):
            text = json.dumps(self.item).replace('"0640"', number)
            with self.subTest(number=number), self.assertRaises(RemoteResultError):
                self.parse(text)

    def test_size_limit_and_deep_json(self):
        text = json.dumps(self.item, ensure_ascii=False)
        size = len(text.encode("utf-8"))
        self.assertEqual(self.parse(text, max_bytes=size), self.item)
        with self.assertRaises(RemoteResultError):
            self.parse(text, max_bytes=size - 1)
        with self.assertRaises(RemoteResultError):
            self.parse("[" * 2000 + "0" + "]" * 2000)
        for limit in (0, -1, True, "100"):
            with self.assertRaises(ValueError):
                self.parse(max_bytes=limit)

    def test_error_and_review_are_valid_diagnosis_results(self):
        for status in ("pass", "vulnerable", "error", "not_applicable", "needs_review"):
            self.item["status"] = status
            self.assertEqual(self.parse()["status"], status)

    def test_error_messages_do_not_echo_output(self):
        for text in ('{"secret":"synthetic-secret",',
                     json.dumps({**self.item, "check_id": "synthetic-secret", "status": "bad"})):
            with self.assertRaises(RemoteResultError) as caught:
                self.parse(text)
            self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_synthetic_response_to_runner_and_storage(self):
        text = json.dumps(self.item, ensure_ascii=False)
        with tempfile.TemporaryDirectory() as directory:
            result = run_target(
                account_checks=[], system_checks=[lambda: self.parse(text)],
                target_id="mock-response", os="ubuntu-24.04", output_root=directory,
                mode="mock", scan_id="mock-response-scan",
            )
            saved = ReportStore(Path(directory) / "mock").load("mock-response", "mock-response-scan")
            self.assertEqual(saved["results"], [self.item])
            self.assertEqual(saved, result.report)
            self.assertEqual(result.summary["metrics"]["needs_review_count"], 1)
            self.assertEqual(result.summary["metrics"]["pass_rate"], "N/A (계산 불가)")
            direct = DiagnosisAggregator.from_results(
                [], [self.parse(text)], target_id="mock-response", os="ubuntu-24.04")
            self.assertEqual(direct.get_report()["results"], saved["results"])

    def test_failed_response_never_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RunFailed) as caught:
                run_target(
                    account_checks=[], system_checks=[lambda: self.parse(exit_code=2)],
                    target_id="mock-response", os="ubuntu-24.04", output_root=directory, mode="mock",
                )
            self.assertIsInstance(caught.exception.failures[0].cause, RemoteResultError)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
