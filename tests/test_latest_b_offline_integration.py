"""Actual current B SSH-01 -> D v1.1, separate from historical B/C regressions.

SECUREOPS_LATEST_B_SOURCE_ROOT points to a source checkout/export. The exact
policy file is loaded via B's loader, not reconstructed from the old fixture.
Only decoded synthetic observations enter the real check_ssh_01 function.
No Git, process execution, network, SSH or VM collection runs in these tests.
"""

import copy
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from core.main import DiagnosisAggregator
from core.remote_result import parse_result_json
from core.runner import run_target
from core.storage import ReportStore


ROOT = Path(__file__).resolve().parents[1]
CASE_RECORDS = []
POLICY_ERROR_RECORDS = []


class LatestBOfflineIntegrationTests(unittest.TestCase):
    def setUp(self):
        source = Path(os.environ.get("SECUREOPS_LATEST_B_SOURCE_ROOT", ROOT))
        module_path = source / "checks/account/ssh_check.py"
        policy_path = source / "checks/account/policies/ssh_policy.json"
        for path in (module_path, policy_path):
            if not path.is_file():
                self.skipTest("최신 B 소스 또는 정책 없음: " + str(path))
        module_guard = patch.dict(sys.modules)
        module_guard.start()
        self.addCleanup(module_guard.stop)
        spec = importlib.util.spec_from_file_location("_latest_b_offline", module_path)
        self.b = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.b
        try:
            spec.loader.exec_module(self.b)
        except ModuleNotFoundError as exc:
            self.skipTest("최신 B 의존 패키지 없음: " + str(exc.name))
        self.policy = self.b.load_policy(policy_path)
        self.b.validate_policy(self.policy)
        for name in ("find_sshd", "get_sshd_output", "read_config_text", "run_check"):
            guard = patch.object(self.b, name, side_effect=AssertionError("Actual collection forbidden"))
            mocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mocked.assert_not_called)
        for name in ("subprocess.Popen", "os.system", "socket.socket"):
            guard = patch(name, side_effect=AssertionError("External commands/network forbidden"))
            mocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mocked.assert_not_called)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name)

    def run_case(self, case_id, stdout, expected, *, config="", root_output=None):
        before = copy.deepcopy(self.policy)
        self.b.validate_policy(self.policy)
        actual = self.b.check_ssh_01(self.policy, stdout, config, root_output)
        original = copy.deepcopy(actual)
        self.assertEqual(actual["status"], expected)
        self.assertEqual(set(actual), {"check_id", "status", "severity", "evidence", "recommendation"})
        self.assertEqual(actual["check_id"], "SSH-01")
        self.assertEqual(actual["severity"], self.policy["severity"])
        self.assertTrue(actual["evidence"])
        self.assertTrue(actual["recommendation"])
        self.assertNotIn("cvss", actual)
        wire = json.dumps(actual, ensure_ascii=False, allow_nan=False)
        parsed = parse_result_json(wire, exit_code=0, execution_succeeded=True, schema_version="1.1")
        self.assertEqual(parsed, original)
        result = run_target(account_checks=[lambda: parsed], system_checks=[],
            target_id="latest-b-offline", os="ubuntu-24.04", output_root=self.output,
            mode="mock", schema_version="1.1", scan_id=case_id,
            scanned_at="2026-11-10T12:00:00+09:00")
        self.assertEqual(self.policy, before)
        self.assertEqual(actual, original)
        self.assertEqual(parsed, original)
        self.assertEqual(result.report["schema_version"], "1.1")
        self.assertEqual(result.report["results"], [original])
        reloaded = ReportStore(self.output / "mock").load("latest-b-offline", case_id)
        self.assertEqual(reloaded, result.report)
        loader = DiagnosisAggregator(str(result.path))
        self.assertEqual(loader.get_report(), result.report)
        self.assertEqual(loader.aggregate_results(), result.summary)
        metrics = result.summary["metrics"]
        self.assertEqual(metrics["total_items"], 1)
        for status, key in (("pass", "pass_count"), ("vulnerable", "vulnerable_count"),
                            ("error", "error_count"), ("not_applicable", "na_count"),
                            ("needs_review", "needs_review_count")):
            self.assertEqual(metrics[key], int(status == expected), key)
        self.assertEqual(metrics["pass_rate"],
                         "100.0%" if expected == "pass" else
                         "0.0%" if expected == "vulnerable" else "N/A (계산 불가)")
        CASE_RECORDS.append({"case_id": case_id, "synthetic_input": {
            "sshd_output": stdout, "config_text": config, "root_output": root_output},
            "expected_status": expected, "b_result": original,
            "d_report": reloaded, "d_summary": result.summary,
            "input_and_original_fields_preserved": True, "saved_and_reloaded_equal": True})
        return result

    def policy_error(self, label, policy):
        before = copy.deepcopy(policy)
        with self.assertRaises(ValueError) as caught:
            self.b.validate_policy(policy)
        self.assertEqual(policy, before)
        POLICY_ERROR_RECORDS.append({"case": label, "exception": type(caught.exception).__name__,
                                     "message": str(caught.exception), "rejected_before_d_run": True})
        self.assertEqual(list(self.output.iterdir()), [])

    def test_policy_loader_and_actual_interface(self):
        signature = inspect.signature(self.b.check_ssh_01)
        self.assertEqual(list(signature.parameters), ["policy", "sshd_output", "config_text", "root_output"])
        self.assertEqual(signature.parameters["config_text"].default, "")
        self.assertIsNone(signature.parameters["root_output"].default)
        criteria = self.policy["criteria"]
        self.assertEqual(criteria["expected"], "no")
        self.assertEqual(set(criteria["vulnerable_values"]),
                         {"yes", "prohibit-password", "without-password", "forced-commands-only"})
        self.assertEqual(criteria["test_connection"]["user"], "root")
        self.assertEqual(set(criteria["test_connection"]), {"user", "host", "addr"})

    def test_normal_policy_pass(self):
        self.run_case("pass-global", "permitrootlogin no\n", "pass")

    def test_all_policy_defined_vulnerable_values(self):
        for value, reason in self.policy["criteria"]["vulnerable_values"].items():
            with self.subTest(value=value):
                result = self.run_case("vulnerable-" + value, f"permitrootlogin {value}\n",
                                       "vulnerable", root_output=f"permitrootlogin {value}\n")
                evidence = result.report["results"][0]["evidence"]
                self.assertIn(reason, evidence)
                self.assertIn("violation:", evidence)

    def test_missing_or_empty_collection_output_is_error(self):
        for index, stdout in enumerate((None, "", " ", "port 22\n")):
            with self.subTest(stdout=stdout):
                self.run_case(f"collection-error-{index}", stdout, "error")

    def test_unresolved_match_without_root_output_is_review(self):
        for value in ("no", "yes"):
            self.run_case("match-no-root-" + value, f"permitrootlogin {value}\n", "needs_review",
                          config="Match User root\n PermitRootLogin yes\n")

    def test_explicit_root_output_controls_user_match(self):
        self.run_case("root-blocked", "permitrootlogin yes\n", "pass",
            config="PermitRootLogin yes\nMatch User root\n PermitRootLogin no\n",
            root_output="permitrootlogin no\n")
        self.run_case("root-allowed", "permitrootlogin no\n", "vulnerable",
            config="PermitRootLogin no\nMatch User root\n PermitRootLogin yes\n",
            root_output="permitrootlogin yes\n")
        self.run_case("root-output-invalid", "permitrootlogin no\n", "error", root_output="")

    def test_conditional_match_does_not_infer_all_connections_safe(self):
        config = ("PermitRootLogin no\nMatch Address 192.0.2.10\n PermitRootLogin no\n"
                  "Match User root\n PermitRootLogin yes\n")
        self.run_case("conditional-unresolved", "permitrootlogin no\n", "needs_review",
                      config=config, root_output="permitrootlogin no\n")
        self.run_case("conditional-confirmed-vulnerable", "permitrootlogin no\n", "vulnerable",
                      config=config, root_output="permitrootlogin yes\n")
        self.run_case("conditional-all-blocked", "permitrootlogin no\n", "pass",
            config="PermitRootLogin no\nMatch Address 192.0.2.10\n PermitRootLogin no\n",
            root_output="permitrootlogin no\n")

    def test_invalid_vulnerable_values_and_expected_conflict(self):
        for value in (None, [], {}, {"yes": ""}, {"": "reason"}, {"yes": 1}, {"NO": "conflict"}):
            policy = copy.deepcopy(self.policy)
            policy["criteria"]["vulnerable_values"] = value
            with self.subTest(value=value):
                self.policy_error("invalid-vulnerable-values-" + repr(value), policy)
        policy = copy.deepcopy(self.policy)
        del policy["criteria"]["vulnerable_values"]
        self.policy_error("missing-vulnerable-values", policy)

    def test_invalid_test_connection_fields(self):
        for key in ("user", "host", "addr"):
            policy = copy.deepcopy(self.policy)
            del policy["criteria"]["test_connection"][key]
            self.policy_error("missing-test-connection-" + key, policy)
        for key, value in (("user", "alice"), ("user", "ROOT"), ("host", ""),
                           ("host", "bad host"), ("addr", "192.0.2.10,user=alice")):
            policy = copy.deepcopy(self.policy)
            policy["criteria"]["test_connection"][key] = value
            self.policy_error("invalid-test-connection-" + key + "-" + value, policy)
        policy = copy.deepcopy(self.policy)
        del policy["criteria"]["test_connection"]
        self.policy_error("missing-test-connection", policy)

    def test_before_after_history_preserves_b_results(self):
        before = self.run_case("history-before", "permitrootlogin yes\n", "vulnerable")
        after = self.run_case("history-after", "permitrootlogin no\n", "pass")
        store = ReportStore(self.output / "mock")
        history = store.history("latest-b-offline")
        self.assertEqual(len(history), 2)
        matched = store.match_results("latest-b-offline", "history-before", "history-after")["SSH-01"]
        self.assertEqual(matched["before"], before.report["results"][0])
        self.assertEqual(matched["after"], after.report["results"][0])


if __name__ == "__main__":
    unittest.main()
