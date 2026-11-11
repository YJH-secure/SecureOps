"""PR #21 B run_check -> unchanged D, synthetic collection only.

This is a pending PR integration, not official main B integration.
SECUREOPS_B_PR21_SOURCE_ROOT must point to the exact recorded source export.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from core.main import DiagnosisAggregator
from core.remote_result import RemoteResultError, parse_result_json
from core.runner import RunFailed, run_target
from core.storage import ReportStore


B_COMMIT = "9f58ee2efca3189866548219e05b732d254e279f"
SOURCE_HASHES = {
    "checks/account/ssh_check.py": "22025954e4905c5c1229106e6d5167991655c0f27ca63adee6b0515c484c767c",
    "checks/account/policies/ssh_policy.json": "d45d94043584f2cf080f33abb014dbe90a8e819b2cf2fc4a729e1f0b85b5db68",
}
CASE_RECORDS = []
SCENARIOS = {
    "pass": ("no", "no", "", "pass"),
    "vulnerable": ("yes", "yes", "", "vulnerable"),
    "error": (None, "no", "", "error"),
    "needs-review": ("no", "no", "Match Address 198.51.100.44\n PermitRootLogin yes\n", "needs_review"),
}


class BPr21V12OfflineTests(unittest.TestCase):
    def setUp(self):
        supplied = os.environ.get("SECUREOPS_B_PR21_SOURCE_ROOT")
        if not supplied:
            self.skipTest("PR #21 source not supplied: SECUREOPS_B_PR21_SOURCE_ROOT")
        source = Path(supplied)
        for name, expected in SOURCE_HASHES.items():
            path = source / name
            self.assertTrue(path.is_file(), "Required PR #21 source missing: " + name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected,
                             "Source differs from fixed B commit " + B_COMMIT)
        guard = patch.dict(sys.modules)
        guard.start()
        self.addCleanup(guard.stop)
        spec = importlib.util.spec_from_file_location("_pr21_b_offline", source / "checks/account/ssh_check.py")
        self.b = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.b
        spec.loader.exec_module(self.b)
        self.policy_path = source / "checks/account/policies/ssh_policy.json"
        self.policy = self.b.load_policy(self.policy_path)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name) / "reports"
        self.sequence = 0
        for name in ("subprocess.Popen", "os.system", "socket.socket"):
            guard = patch(name, side_effect=AssertionError("Actual process/network forbidden"))
            blocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(blocked.assert_not_called)

    def actual_b(self, global_value="no", root_value="no", config="", *, version="1.2",
                 installed=True, **overrides):
        self.sequence += 1
        global_output = None if global_value is None else "permitrootlogin " + global_value + "\n"
        root_output = None if root_value is None else "permitrootlogin " + root_value + "\n"
        with patch.object(self.b, "find_sshd", return_value="<MOCK_SSHD>" if installed else None), \
             patch.object(self.b, "get_sshd_output", side_effect=[global_output, root_output]) as collect, \
             patch.object(self.b, "read_config_text", return_value=config):
            options = {} if version is None else {"result_version": version}
            # Real loader, run_check, judgement, details and serializer remain unpatched.
            result = self.b.run_check(policy_path=self.policy_path, **options, **overrides)
        if installed and global_output is not None and config is not None:
            self.assertEqual(collect.call_count, 2)
        return result

    def pipeline(self, item, version="1.2", label="case"):
        snapshot = copy.deepcopy(item)
        text = json.dumps(item, ensure_ascii=False, allow_nan=False)
        def receive():
            options = {} if version == "1.1" else {"schema_version": "1.2"}
            return parse_result_json(text, exit_code=0, execution_succeeded=True, **options)
        options = {} if version == "1.1" else {"schema_version": "1.2"}
        scan = label + "-" + str(self.sequence)
        result = run_target(account_checks=[receive], system_checks=[], target_id="mock-b-pr21",
                            os="ubuntu-24.04", output_root=self.output, mode="mock", scan_id=scan,
                            scanned_at="2026-11-11T11:00:00+09:00", **options)
        self.assertEqual(item, snapshot)
        self.assertEqual(result.report["results"], [snapshot])
        store = ReportStore(self.output / "mock")
        self.assertEqual(store.load("mock-b-pr21", scan), result.report)
        aggregator = DiagnosisAggregator(str(result.path))
        self.assertEqual(aggregator.get_report(), result.report)
        self.assertEqual(aggregator.aggregate_results(), result.summary)
        CASE_RECORDS.append({"case": label, "version": version, "b_result": snapshot,
                             "d_report": copy.deepcopy(result.report), "d_summary": result.summary,
                             "reloaded_equal": True})
        return result

    def assert_unscored(self, item):
        self.assertNotIn("severity", item)
        self.assertEqual(item["cvss"]["assessment_status"],
                         "pending" if item["status"] == "vulnerable" else "not_applicable")
        for key in ("version", "vector", "base_score", "rating", "source"):
            self.assertIsNone(item["cvss"][key])
        self.assertTrue(item["cvss"]["rationale"].strip())

    def test_four_actual_states_through_d(self):
        for name, (global_value, root_value, config, status) in SCENARIOS.items():
            with self.subTest(case=name):
                item = self.actual_b(global_value, root_value, config)
                self.assertEqual(item["status"], status)
                self.assert_unscored(item)
                result = self.pipeline(item, label=name)
                metrics = result.summary["metrics"]
                self.assertEqual(metrics["total_items"], 1)
                for state in ("pass", "vulnerable", "error", "not_applicable", "needs_review"):
                    key = "na_count" if state == "not_applicable" else state + "_count"
                    self.assertEqual(metrics[key], int(state == status))
                if status in ("pass", "vulnerable"):
                    self.assertEqual(metrics["pass_rate"], "100.0%" if status == "pass" else "0.0%")
                else:
                    self.assertTrue(metrics["pass_rate"].startswith("N/A"))
                self.assertEqual(sum(result.summary["cvss_rating_breakdown"].values()), 0)
                self.assertEqual(result.summary["cvss_assessment_breakdown"], {
                    "scored": 0, "pending": int(status == "vulnerable"),
                    "not_applicable": int(status != "vulnerable")})

    def test_root_effective_match_details_preserved(self):
        item = self.actual_b("yes", "no", "PermitRootLogin yes\nMatch User root\n PermitRootLogin no\n")
        self.assertEqual(item["status"], "pass")
        self.assertEqual(item["details"], {"setting": "permitrootlogin", "expected": "no",
            "global_value": "yes", "root_value": "no", "root_evaluation": "sshd -T -C user=root",
            "match_rules": [{"conditions": ["user"], "value": "no"}]})
        self.pipeline(item, label="root-match")

    def test_four_policy_vulnerable_values_stay_pending(self):
        for value in self.policy["criteria"]["vulnerable_values"]:
            with self.subTest(value=value):
                item = self.actual_b(value, value)
                self.assertEqual(item["status"], "vulnerable")
                self.assert_unscored(item)
                self.assertEqual(item["cvss"]["rationale"], self.policy["cvss_assessment"]["rationale"])
                self.pipeline(item, label="vulnerable-" + value)

    def test_early_error_and_not_applicable_without_details(self):
        with patch.object(self.b, "find_sshd", side_effect=AssertionError("No collection after invalid policy")):
            item = self.b.run_check(policy_path=self.output / "missing.json", result_version="1.2")
        self.assertEqual(item["status"], "error")
        self.assertNotIn("details", item)
        self.assert_unscored(item)
        self.pipeline(item, label="policy-error")
        item = self.actual_b(installed=False)
        self.assertEqual(item["status"], "not_applicable")
        self.assertNotIn("details", item)
        self.assert_unscored(item)
        self.pipeline(item, label="not-installed")

    def test_v11_default_and_v12_identical_judgement(self):
        for name, (global_value, root_value, config, _) in SCENARIOS.items():
            with self.subTest(case=name):
                old = self.actual_b(global_value, root_value, config, version=None)
                new = self.actual_b(global_value, root_value, config)
                self.assertEqual(set(old), {"check_id", "status", "severity", "evidence", "recommendation"})
                self.assertEqual(old["severity"], self.policy["severity"])
                self.assertNotIn("cvss", old)
                for key in ("check_id", "status", "evidence", "recommendation"):
                    self.assertEqual(old[key], new[key])
                self.pipeline(old, "1.1", "v11-" + name)

    def test_collection_failure_is_diagnosis_error(self):
        for global_value, root_value, config in [(None, "no", ""), ("no", None, ""), ("no", "no", None), ("", "no", "")]:
            with self.subTest(global_value=global_value, root_value=root_value, config=config):
                item = self.actual_b(global_value, root_value, config)
                self.assertEqual(item["status"], "error")
                self.assert_unscored(item)
                self.pipeline(item, label="collection-error")

    def test_connection_identifiers_not_exported(self):
        # Documentation-only address and synthetic hostname, never real host data.
        host, addr = "mock-private-host.invalid", "192.0.2.123"
        item = self.actual_b("no", "no", SCENARIOS["needs-review"][2], host=host, addr=addr)
        text = json.dumps(item)
        for value in (host, addr, "198.51.100.44", self.policy["criteria"]["test_connection"]["host"],
                      self.policy["criteria"]["test_connection"]["addr"]):
            self.assertNotIn(value, text)
        for key in ("password", "private_key", "token", "credentials", "host", "addr"):
            self.assertNotIn(key, item)
            self.assertNotIn(key, item["details"])
        self.pipeline(item, label="sanitized-connection")

    def assert_rejected(self, text, code=0, succeeded=True):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "must-not-save"
            with self.assertRaises(RunFailed) as raised:
                run_target(account_checks=[lambda: parse_result_json(text, exit_code=code,
                    execution_succeeded=succeeded, schema_version="1.2")], system_checks=[],
                    target_id="mock-b-pr21", os="ubuntu-24.04", output_root=output, mode="mock", schema_version="1.2")
            self.assertIsInstance(raised.exception.failures[0].cause, RemoteResultError)
            self.assertFalse(output.exists())

    def test_execution_failure_and_malformed_json_rejected(self):
        text = json.dumps(self.actual_b("yes", "yes"))
        for code, success in ((1, True), (0, False), (255, False)):
            with self.subTest(code=code, success=success):
                self.assert_rejected(text, code, success)
        for value in ("", "{", "[]", "MOCK log\n" + text, text + "{}", text.replace('"cvss": {', '"cvss": {"rating": "high",')):
            with self.subTest(payload=value[:16]):
                self.assert_rejected(value)

    def test_inappropriate_cvss_objects_rejected(self):
        original = self.actual_b("yes", "yes")
        for fields in ({"base_score": 0.0}, {"base_score": True}, {"rating": "high"},
                       {"assessment_status": "scored"}, {"version": "3.1"}, {"vector": "CVSS:3.1/AV:N"},
                       {"rationale": ""}, {"assessment_status": "unknown"}):
            item = copy.deepcopy(original)
            item["cvss"].update(fields)
            with self.subTest(fields=fields):
                self.assert_rejected(json.dumps(item))
        for cvss in (None, {}, []):
            item = copy.deepcopy(original)
            item["cvss"] = cvss
            self.assert_rejected(json.dumps(item))
        item = self.actual_b()
        item["cvss"]["assessment_status"] = "pending"
        self.assert_rejected(json.dumps(item))

    def test_nested_details_independence_after_save(self):
        item = self.actual_b("yes", "no", "Match User root\n PermitRootLogin no\n")
        snapshot = copy.deepcopy(item)
        result = self.pipeline(item, label="details-independent")
        item["details"]["match_rules"][0]["conditions"].clear()
        self.assertEqual(result.report["results"], [snapshot])
        result.report["results"][0]["details"]["match_rules"].clear()
        self.assertEqual(ReportStore(self.output / "mock").load("mock-b-pr21", result.report["scan_id"])["results"], [snapshot])


if __name__ == "__main__":
    unittest.main()
