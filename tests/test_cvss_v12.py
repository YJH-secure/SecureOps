"""JSON v1.2 schema/runtime and MOCK D pipeline acceptance tests.

B/C callbacks here return synthetic v1.2 objects, not guessed production metrics.
Existing test_bc_offline_integration remains the actual B/C v1.1 regression suite.
"""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from core.main import DiagnosisAggregator
from core.remote_result import RemoteResultError, parse_result_json
from core.runner import RunFailed, run_target
from core.storage import ReportStore
from core.cvss_validation import loads_strict


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/sample-result-v1.2-MOCK.json"
SCHEMA = ROOT / "docs/architecture/json-result-schema-v1.2.schema.json"


def report():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def v11(scan_id="old"):
    return {"schema_version": "1.1", "scan_id": scan_id, "target_id": "ubuntu-a-mock",
            "os": "ubuntu-24.04", "scanned_at": "2026-11-09T12:00:00+09:00",
            "results": [{"check_id": "SSH-01", "status": "vulnerable", "severity": "high",
                         "evidence": "MOCK policy violation", "recommendation": "MOCK review"}]}


class V12RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.data = report()
        self.scored = self.data["results"][-1]

    def validate(self):
        DiagnosisAggregator._validate_report(self.data)

    def test_official_mock_and_expected_aggregates(self):
        self.validate()
        data = self.data
        aggregator = DiagnosisAggregator.from_results(data["results"][:2], data["results"][2:],
            target_id=data["target_id"], os=data["os"], scan_id=data["scan_id"],
            scanned_at=data["scanned_at"], schema_version="1.2")
        self.assertEqual(aggregator.get_report(), data)
        self.assertEqual(json.loads(aggregator.to_json()), data)
        summary = aggregator.aggregate_results()
        self.assertEqual(summary["metrics"]["pass_rate"], "25.0%")
        self.assertEqual(summary["cvss_assessment_breakdown"],
                         {"scored": 1, "pending": 1, "not_applicable": 2})
        self.assertEqual(summary["cvss_rating_breakdown"],
                         {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 1})
        self.assertNotIn("severity_breakdown", summary)

    def test_all_diagnosis_and_assessment_state_combinations(self):
        for status in ("pass", "vulnerable", "error", "not_applicable", "needs_review"):
            for assessment in ("scored", "pending", "not_applicable"):
                with self.subTest(status=status, assessment=assessment):
                    self.data = report()
                    item = self.data["results"][-1]
                    item["status"] = status
                    item["cvss"]["assessment_status"] = assessment
                    if assessment != "scored":
                        for key in ("version", "vector", "base_score", "rating"):
                            item["cvss"][key] = None
                    if status == "vulnerable" or assessment == "not_applicable":
                        self.validate()
                    else:
                        with self.assertRaises(ValueError):
                            self.validate()

    def test_score_and_vector_mismatch(self):
        self.scored["cvss"].update(base_score=9.7)
        with self.assertRaisesRegex(ValueError, "vector and base_score"):
            self.validate()

    def test_rating_mismatch(self):
        self.scored["cvss"]["rating"] = "high"
        with self.assertRaisesRegex(ValueError, "base_score and rating"):
            self.validate()

    def test_invalid_numeric_scores_and_precision(self):
        for score in (True, False, None, "9.8", -1, 11, 9.81, 9.80000000001,
                      float("nan"), float("inf"), 10**1000):
            with self.subTest(score_type=type(score).__name__):
                self.scored["cvss"]["base_score"] = score
                with self.assertRaises((ValueError, TypeError)):
                    self.validate()

    def test_zero_score_and_null_are_distinct(self):
        self.scored["cvss"].update(
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            base_score=0.0, rating="none")
        self.validate()
        aggregator = DiagnosisAggregator.from_results(self.data["results"], [],
            target_id="mock", os="ubuntu-24.04", schema_version="1.2")
        self.assertEqual(aggregator.aggregate_results()["cvss_rating_breakdown"]["none"], 1)
        self.assertIsNone(aggregator.get_report()["results"][0]["cvss"]["base_score"])
        self.assertEqual(aggregator.get_report()["results"][-1]["cvss"]["base_score"], 0.0)
        self.scored["cvss"]["base_score"] = None
        with self.assertRaises(TypeError):
            self.validate()

    def test_unscored_values_must_all_be_null(self):
        for index in (0, 1, 2):
            for key, value in (("version", "3.1"), ("vector", "MOCK"),
                               ("base_score", 0.0), ("rating", "none")):
                with self.subTest(index=index, key=key):
                    self.data = report()
                    self.data["results"][index]["cvss"][key] = value
                    with self.assertRaises(ValueError):
                        self.validate()

    def test_cvss_required_extra_fields_source_and_reason(self):
        for key in report()["results"][-1]["cvss"]:
            self.data = report()
            del self.data["results"][-1]["cvss"][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validate()
        for change in ({"extra": "MOCK"}, {"source": None}, {"source": " "},
                       {"rationale": ""}, {"rationale": " "}, {"version": "4.0"},
                       {"assessment_status": "unknown"}, {"source": False}):
            self.data = report()
            self.data["results"][-1]["cvss"].update(change)
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                self.validate()

    def test_invalid_vector_and_unknown_contract(self):
        for vector in ("CVSS:3.1/AV:N/AV:N", None, True,
                       self.scored["cvss"]["vector"] + "/E:F"):
            self.scored["cvss"]["vector"] = vector
            with self.assertRaises((ValueError, TypeError)):
                self.validate()
        for version in ("1.0", "1.3", True, None):
            self.data = report()
            self.data["schema_version"] = version
            with self.assertRaises((ValueError, TypeError)):
                self.validate()

    def test_duplicate_check_ids(self):
        self.data["results"].append(copy.deepcopy(self.scored))
        with self.assertRaisesRegex(ValueError, "Duplicate check_id"):
            self.validate()

    def test_report_and_item_required_fields_and_types(self):
        for field in ("schema_version", "scan_id", "target_id", "os", "scanned_at", "results"):
            self.data = report()
            del self.data[field]
            with self.subTest(missing=field), self.assertRaises((KeyError, ValueError)):
                self.validate()
        for field in ("check_id", "status", "evidence", "recommendation", "cvss"):
            self.data = report()
            del self.data["results"][0][field]
            with self.subTest(missing=field), self.assertRaises((KeyError, ValueError)):
                self.validate()
        for change in ({"scan_id": True}, {"target_id": ""}, {"os": None},
                       {"results": []}, {"results": {}}, {"extra": "MOCK"}, {"ip_address": 1}):
            self.data = {**report(), **change}
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                self.validate()
        for change in ({"cvss": []}, {"status": "PASS"}, {"check_id": False},
                       {"evidence": {}}, {"recommendation": ""}, {"details": []},
                       {"title": 1}, {"category": ""}):
            self.data = report()
            self.data["results"][0].update(change)
            with self.subTest(change=change), self.assertRaises((TypeError, ValueError)):
                self.validate()

    def test_timestamp_semantics_and_timezone(self):
        for value in ("2026-11-10T12:00:00", "2026-02-30T12:00:00Z", "2026-11-10",
                      "2026-11-10T25:00:00Z", "2026-11-10T12:00:00+24:00", True):
            for field in ("scanned_at", "checked_at"):
                self.data = report()
                (self.data if field == "scanned_at" else self.data["results"][0])[field] = value
                with self.subTest(value=value, field=field), self.assertRaises((ValueError, TypeError)):
                    self.validate()

    def test_contracts_are_not_mixed_or_automatically_migrated(self):
        self.scored["severity"] = "critical"
        with self.assertRaises(ValueError):
            self.validate()
        with self.assertRaises((KeyError, ValueError)):
            DiagnosisAggregator.from_results(report()["results"], [], target_id="mock", os="mock")
        with self.assertRaises((KeyError, ValueError)):
            DiagnosisAggregator.from_results(v11()["results"], [], target_id="mock", os="mock",
                                              schema_version="1.2")

    def test_json_native_types_and_nonfinite_details(self):
        for details in ({"value": (1, 2)}, {1: "value"}, {"value": {1, 2}},
                        {"value": float("nan")}, {"value": float("inf")}):
            self.scored["details"] = details
            with self.assertRaises((TypeError, ValueError)):
                self.validate()
        cyclic = {}
        cyclic["self"] = cyclic
        self.scored["details"] = cyclic
        with self.assertRaises(ValueError):
            self.validate()

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for text in ('{"key":1,"key":2}', '{"inner":{"key":1,"key":2}}',
                     '{"x":NaN}', '{"x":1e999}'):
            with self.assertRaises(ValueError):
                loads_strict(text)


class V12PipelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = report()

    def run_mock(self, **overrides):
        items = self.data["results"]
        receive = lambda item: parse_result_json(json.dumps(item, ensure_ascii=False),
            exit_code=0, execution_succeeded=True, schema_version="1.2")
        arguments = dict(account_checks=[lambda: receive(items[0]), lambda: receive(items[1])],
            system_checks=[],
            target_id=self.data["target_id"], os=self.data["os"], mode="mock",
            output_root=self.root, schema_version="1.2", scan_id=self.data["scan_id"],
            scanned_at=self.data["scanned_at"])
        arguments["system_checks"] = [lambda item=item: receive(item) for item in items[2:]]
        return run_target(**{**arguments, **overrides})

    def test_bc_mock_json_runner_aggregation_storage_and_details(self):
        self.data["results"][2].update(check_id="FILE-01", details={
            "files": [{"path": "/etc/shadow", "acl": {"entries": ["MOCK"], "mode": "0600"}}]})
        original = copy.deepcopy(self.data)
        with (patch("subprocess.Popen", side_effect=AssertionError("No commands")) as commands,
              patch("socket.socket", side_effect=AssertionError("No network")) as sockets):
            result = self.run_mock()
        commands.assert_not_called()
        sockets.assert_not_called()
        self.assertEqual(self.data, original)
        self.assertEqual(result.report, original)
        store = ReportStore(result.path.parent)
        self.assertEqual(store.load(original["target_id"], original["scan_id"]), original)
        self.assertEqual(DiagnosisAggregator(str(result.path)).get_report(), original)
        self.assertEqual(result.summary["metrics"]["pass_rate"], "25.0%")
        self.data["results"][2]["details"]["files"].clear()
        self.assertEqual(result.report, original)
        result.report["results"][2]["details"]["files"].clear()
        self.assertEqual(store.load(original["target_id"], original["scan_id"]), original)

    def test_five_statuses_and_no_evaluable_results(self):
        template = self.data["results"][1]
        items = []
        for index, status in enumerate(("pass", "vulnerable", "error", "not_applicable", "needs_review")):
            item = copy.deepcopy(template)
            item.update(check_id=f"MOCK-{index}", status=status)
            items.append(item)
        self.data["results"] = items
        result = self.run_mock()
        metrics = result.summary["metrics"]
        self.assertEqual([metrics[k] for k in ("pass_count", "vulnerable_count", "error_count", "na_count", "needs_review_count")], [1]*5)
        self.assertEqual(metrics["pass_rate"], "50.0%")
        self.assertEqual(result.summary["cvss_assessment_breakdown"]["not_applicable"], 5)
        self.data["results"] = items[2:]
        result = self.run_mock(scan_id="unevaluable")
        self.assertEqual(result.summary["metrics"]["pass_rate"], "N/A (계산 불가)")

    def test_mixed_version_failure_and_bad_metadata_do_not_save(self):
        with self.assertRaises(RunFailed):
            self.run_mock(system_checks=[lambda: v11()["results"][0]])
        callback = Mock()
        with self.assertRaises(ValueError):
            self.run_mock(schema_version="1.3", account_checks=[callback])
        callback.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_remote_cvss_never_saved(self):
        self.data["results"][-1]["cvss"]["base_score"] = 9.7
        with self.assertRaises(RunFailed) as caught:
            self.run_mock()
        self.assertIsInstance(caught.exception.failures[0].cause, RemoteResultError)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_remote_v12_strictness_and_explicit_version_selection(self):
        item = self.data["results"][-1]
        text = json.dumps(item)
        self.assertEqual(parse_result_json(text, exit_code=0, execution_succeeded=True,
                                          schema_version="1.2"), item)
        for payload, code, success in ((text, 1, True), (text, 0, False),
                                      (text.replace('"cvss": {', '"cvss": {"rating": "high",'), 0, True),
                                      (text.replace('"base_score": 9.8', '"base_score": NaN'), 0, True),
                                      (text + "\n{}", 0, True), ("MOCK log\n" + text, 0, True)):
            with self.subTest(code=code, success=success), self.assertRaises(RemoteResultError):
                parse_result_json(payload, exit_code=code, execution_succeeded=success, schema_version="1.2")
        with self.assertRaises(RemoteResultError):
            parse_result_json(text, exit_code=0, execution_succeeded=True)

    def test_v11_v12_storage_history_and_comparison(self):
        store = ReportStore(self.root)
        old = v11()
        old_path = store.save(old)
        old_bytes = old_path.read_bytes()
        store.save(self.data)
        self.assertEqual([r["schema_version"] for r in store.history(old["target_id"])], ["1.1", "1.2"])
        self.assertEqual(store.load(old["target_id"], "old"), old)
        self.assertEqual(old_path.read_bytes(), old_bytes)
        with self.assertRaisesRegex(ValueError, "different schema versions"):
            store.match_results(old["target_id"], "old", self.data["scan_id"])
        after = copy.deepcopy(self.data)
        after.update(scan_id="after", scanned_at="2026-11-10T13:00:00+09:00")
        after["results"][0]["status"] = "pass"
        after["results"][0]["cvss"]["assessment_status"] = "not_applicable"
        store.save(after)
        matched = store.match_results(old["target_id"], self.data["scan_id"], "after")
        self.assertEqual(matched["SSH-01"]["before"]["status"], "vulnerable")
        self.assertEqual(matched["SSH-01"]["after"]["status"], "pass")

    def test_v12_file_and_storage_reject_duplicate_json_keys(self):
        text = json.dumps(self.data).replace('"schema_version": "1.2"',
                                             '"schema_version": "1.1", "schema_version": "1.2"')
        path = self.root / "duplicate.json"
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(ValueError):
            DiagnosisAggregator(str(path))
        store = ReportStore(self.root / "store")
        saved = store.save(self.data)
        saved.write_text(text, encoding="utf-8")
        with self.assertRaises(ValueError):
            store.load(self.data["target_id"], self.data["scan_id"])

    def test_sensitive_values_still_rejected(self):
        self.data["results"][-1]["cvss"]["source"] = "token=synthetic-secret"
        with self.assertRaises(ValueError):
            self.run_mock()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cli_supports_v12_and_both_invocation_styles(self):
        for entry in ([str(ROOT / "core/main.py")], ["-m", "core.main"]):
            completed = subprocess.run([sys.executable, "-B", "-X", "utf8", *entry, str(FIXTURE)],
                cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("25.0%", completed.stdout)
            self.assertIn("critical: 1", completed.stdout)


@unittest.skipUnless(importlib.util.find_spec("jsonschema"), "JSON Schema 검증 의존 패키지 jsonschema 없음")
class V12SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from jsonschema import Draft202012Validator, FormatChecker
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def test_adopted_schema_and_mock(self):
        self.validator.validate(report())
        DiagnosisAggregator._validate_report(report())

    def test_schema_and_runtime_reject_structural_negatives(self):
        # Calendar/timezone semantics are asserted independently in runtime tests;
        # jsonschema's RFC3339 checker is an optional dependency in some installs.
        for change in ("severity", "missing_cvss", "extra", "wrong_status", "bool_score", "na_score"):
            data = report()
            item = data["results"][-1]
            if change == "severity":
                item["severity"] = "high"
            elif change == "missing_cvss":
                del item["cvss"]
            elif change == "extra":
                item["cvss"]["extra"] = "MOCK"
            elif change == "wrong_status":
                item["status"] = "pass"
            elif change == "bool_score":
                item["cvss"]["base_score"] = True
            elif change == "na_score":
                data["results"][1]["cvss"]["base_score"] = 0.0
            with self.subTest(change=change):
                self.assertTrue(list(self.validator.iter_errors(data)))
                with self.assertRaises((KeyError, ValueError, TypeError)):
                    DiagnosisAggregator._validate_report(data)

    def test_schema_all_state_combinations(self):
        for status in ("pass", "vulnerable", "error", "not_applicable", "needs_review"):
            for assessment in ("scored", "pending", "not_applicable"):
                data = report()
                item = data["results"][-1]
                item["status"] = status
                item["cvss"]["assessment_status"] = assessment
                if assessment != "scored":
                    for key in ("version", "vector", "base_score", "rating"):
                        item["cvss"][key] = None
                with self.subTest(status=status, assessment=assessment):
                    self.assertEqual(not list(self.validator.iter_errors(data)),
                                     status == "vulnerable" or assessment == "not_applicable")

    def test_runtime_checks_numeric_consistency_beyond_schema(self):
        for change in ("score", "precision", "duplicate_id"):
            data = report()
            if change == "score":
                data["results"][-1]["cvss"]["base_score"] = 9.7
            elif change == "precision":
                data["results"][-1]["cvss"]["base_score"] = 9.81
            else:
                data["results"].append(copy.deepcopy(data["results"][0]))
            self.validator.validate(data)
            with self.subTest(change=change), self.assertRaises(ValueError):
                DiagnosisAggregator._validate_report(data)


if __name__ == "__main__":
    unittest.main()
