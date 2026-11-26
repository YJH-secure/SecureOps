"""D-owned checks, independent of C verify_json_scenarios implementation.

Use fixed official C source via SECUREOPS_C_PR27_SOURCE_ROOT. Collectors only
are synthetic; not_applicable is a contract fixture, not automatic diagnosis.
"""
import copy
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from core.main import DiagnosisAggregator
from core.remote_result import RemoteResultError, parse_result_json
from core.runner import RunFailed, run_target
from core.storage import ReportStore

RECORDS = []


class OfficialCIndependentTests(unittest.TestCase):
    def setUp(self):
        supplied = os.environ.get("SECUREOPS_C_PR27_SOURCE_ROOT")
        if not supplied:
            self.skipTest("Official C PR27 source not supplied: SECUREOPS_C_PR27_SOURCE_ROOT")
        self.source = Path(supplied)
        guard = patch.dict(sys.modules)
        guard.start()
        self.addCleanup(guard.stop)
        package = types.ModuleType("_d_independent_c27")
        package.__path__ = [str(self.source / "checks/system")]
        sys.modules[package.__name__] = package
        self.file, self.svc, self.fw, self.log, self.adapter, self.common = [
            importlib.import_module(package.__name__ + "." + name) for name in
            ("file_check", "service_check", "firewall_check", "log_check", "result_adapter", "common")]
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.temp = Path(directory.name)
        self.output = self.temp / "reports"
        self.os_input = {"id": "ubuntu", "version_id": "24.04", "collection_origin": "MOCK"}
        self.cases = json.loads((self.source / "checks/system/scenarios/v1.2.json").read_text(encoding="utf-8"))
        for name in ("subprocess.Popen", "os.system", "socket.socket"):
            guard = patch(name, side_effect=AssertionError("Real process/network forbidden"))
            blocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(blocked.assert_not_called)
        for module in (self.svc, self.fw, self.log):
            guard = patch.object(module, "read_target_os", return_value=copy.deepcopy(self.os_input))
            guard.start()
            self.addCleanup(guard.stop)
        guard = patch("socket.gethostname", return_value="mock-official-c")
        guard.start()
        self.addCleanup(guard.stop)

    def generate(self):
        # Reuse declared synthetic inputs, but do not call C's verifier/runners
        # or read its expected result objects to decide D assertions.
        inputs = {case["runner"]: copy.deepcopy(case["inputs"]) for case in self.cases}
        item = inputs["file"]
        file_result = self.file.run(item["policy"], collector=lambda path: copy.deepcopy(item["observation"]),
                                    environment=copy.deepcopy(self.os_input))
        def policy_file(name, policy=None):
            path = self.temp / (name + "-policy.json")
            path.write_text(json.dumps({"policy_version": "MOCK-only", "policies": [] if policy is None else [policy]}), encoding="utf-8")
            return path
        item = inputs["service"]
        svc_responses = {self.svc.ACTIVE_COMMAND: item["active_units_stdout"],
                         self.svc.UNIT_FILES_COMMAND: item["unit_files_stdout"],
                         self.svc.LISTENERS_COMMAND: item["listeners_stdout"]}
        svc_result = self.svc.run_from_policy(policy_file("svc", item["policy"]),
            command_runner=lambda command: svc_responses[command], **item["target"])
        item = inputs["firewall"]
        fw_responses = {self.fw.UFW_STATUS: item["ufw_stdout"], self.fw.LISTENERS_COMMAND: item["listeners_stdout"]}
        def fw_collect(command):
            if command == self.fw.NFT_RULESET:
                raise PermissionError("MOCK nft denied")
            return fw_responses[command]
        fw_result = self.fw.run_from_policy(policy_file("fw"), command_runner=fw_collect)
        item = inputs["log"]
        etc = self.temp / "synthetic-etc"
        etc.mkdir(exist_ok=True)
        log_responses = {self.log.unit_command(unit): item["unit_stdout"] for unit in self.log.UNITS}
        log_responses.update({self.log.JOURNAL_CONFIG: item["journald_stdout"], self.log.JOURNAL_USAGE: item["usage_stdout"]})
        def config_metadata(path):
            if not Path(path).resolve().is_relative_to(etc.resolve()):
                raise AssertionError("Config metadata outside synthetic tree")
            return {"path": Path(path).as_posix(), "state": "missing"}
        with patch.object(self.log, "path_metadata", side_effect=config_metadata):
            log_result = self.log.run_from_policy(policy_file("log"), config_root=etc,
                command_runner=lambda command: log_responses[command],
                metadata_reader=lambda path: {"path": path.as_posix(), "state": "missing"})
        exemption = self.common.make_result("FILE-01", "not_applicable", "high",
            "MOCK contract fixture exemption", "MOCK verify approval separately", {"fixture_only": True})
        results = [file_result, svc_result, fw_result, log_result, exemption]
        self.assertEqual([r["status"] for r in results], ["pass", "vulnerable", "error", "needs_review", "not_applicable"])
        return results

    def pipeline(self, item, version, label):
        original = copy.deepcopy(item)
        text = json.dumps(item, ensure_ascii=False)
        result = run_target(account_checks=[], system_checks=[lambda: parse_result_json(text,
            exit_code=0, execution_succeeded=True, schema_version=version)], schema_version=version,
            target_id="mock-official-c", os="ubuntu-24.04", mode="mock", output_root=self.output,
            scan_id=label, scanned_at="2026-11-11T18:00:00+09:00")
        loaded = ReportStore(self.output / "mock").load("mock-official-c", label)
        self.assertEqual(loaded, result.report)
        self.assertEqual(loaded["results"], [original])
        self.assertEqual(item, original)
        aggregator = DiagnosisAggregator(str(result.path))
        self.assertEqual(aggregator.aggregate_results(), result.summary)
        RECORDS.append({"label": label, "report": loaded, "summary": result.summary, "reload_equal": True})
        return result

    def test_five_statuses_cvss_nulls_and_roundtrip(self):
        legacy = self.generate()
        before = copy.deepcopy(legacy)
        for index, old in enumerate(legacy):
            item = self.adapter.adapt_result(old, "1.2")
            self.assertEqual({k: v for k, v in old.items() if k != "severity"}, {k: v for k, v in item.items() if k != "cvss"})
            cvss = item["cvss"]
            self.assertEqual(cvss["assessment_status"], "pending" if old["status"] == "vulnerable" else "not_applicable")
            for key in ("version", "vector", "base_score", "rating", "source"):
                self.assertIsNone(cvss[key])
            result = self.pipeline(item, "1.2", "state-" + str(index))
            metrics = result.summary["metrics"]
            key = "na_count" if item["status"] == "not_applicable" else item["status"] + "_count"
            self.assertEqual(metrics[key], 1)
            self.assertEqual(sum(result.summary["cvss_rating_breakdown"].values()), 0)
            if item["status"] in ("error", "needs_review", "not_applicable"):
                self.assertEqual(metrics["evaluable_items"], 0)
        self.assertEqual(legacy, before)

    def test_v11_default_output_and_roundtrip(self):
        for index, old in enumerate(self.generate()):
            item = self.adapter.adapt_result(old)
            self.assertEqual(item, old)
            self.assertIn("severity", item)
            self.assertNotIn("cvss", item)
            self.assertEqual(parse_result_json(json.dumps(item), exit_code=0, execution_succeeded=True), old)
            self.pipeline(item, "1.1", "legacy-" + str(index))

    def assert_rejected(self, text, code=0, success=True):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "no-report"
            with self.assertRaises(RunFailed) as raised:
                run_target(account_checks=[], system_checks=[lambda: parse_result_json(text,
                    exit_code=code, execution_succeeded=success, schema_version="1.2")],
                    target_id="mock-official-c", os="ubuntu-24.04", output_root=output, mode="mock", schema_version="1.2")
            self.assertIsInstance(raised.exception.failures[0].cause, RemoteResultError)
            self.assertFalse(output.exists())

    def test_malformed_and_duplicate_json_rejected(self):
        text = json.dumps(self.adapter.adapt_result(self.generate()[0], "1.2"))
        for value in ("", "{", "[]", text + "{}", "MOCK log\n" + text,
                      text.replace('"cvss": {', '"cvss": {"rating": "high",')):
            with self.subTest(payload=value[:18]):
                self.assert_rejected(value)

    def test_invalid_cvss_combinations_rejected(self):
        old = self.adapter.adapt_result(self.generate()[1], "1.2")
        for values in ({"base_score": 0.0}, {"base_score": True}, {"rating": "high"},
                       {"assessment_status": "scored"}, {"rationale": ""}, {"vector": "INVALID"}):
            item = copy.deepcopy(old)
            item["cvss"].update(values)
            with self.subTest(values=values):
                self.assert_rejected(json.dumps(item))
        item = self.adapter.adapt_result(self.generate()[0], "1.2")
        item["cvss"]["assessment_status"] = "pending"
        self.assert_rejected(json.dumps(item))

    def test_duplicate_check_id_rejected_before_save(self):
        item = self.adapter.adapt_result(self.generate()[0], "1.2")
        with self.assertRaisesRegex(ValueError, "Duplicate check_id"):
            run_target(account_checks=[], system_checks=[lambda: copy.deepcopy(item), lambda: copy.deepcopy(item)],
                target_id="mock-official-c", os="ubuntu-24.04", output_root=self.output, mode="mock", schema_version="1.2")
        self.assertFalse(self.output.exists())

    def test_duplicate_scan_id_preserves_original(self):
        item = self.adapter.adapt_result(self.generate()[0], "1.2")
        result = self.pipeline(item, "1.2", "duplicate-scan")
        data = result.path.read_bytes()
        alternate = copy.deepcopy(result.report)
        alternate["results"][0]["evidence"] = "MOCK different content"
        with self.assertRaises(FileExistsError):
            ReportStore(self.output / "mock").save(alternate)
        self.assertEqual(result.path.read_bytes(), data)
        self.assertEqual(ReportStore(self.output / "mock").load("mock-official-c", "duplicate-scan"), result.report)

    def test_valid_diagnosis_error_and_delivery_failure_differ(self):
        item = self.adapter.adapt_result(self.generate()[2], "1.2")
        result = self.pipeline(item, "1.2", "diagnosis-error")
        self.assertEqual(result.summary["metrics"]["error_count"], 1)
        for code, success in ((1, True), (0, False), (255, False)):
            with self.subTest(code=code, success=success):
                self.assert_rejected(json.dumps(item), code, success)

    def test_details_and_original_fields_are_independent(self):
        item = self.adapter.adapt_result(self.generate()[0], "1.2")
        snapshot = copy.deepcopy(item)
        result = self.pipeline(item, "1.2", "details")
        item["details"]["files"].clear()
        self.assertEqual(result.report["results"], [snapshot])
        result.report["results"][0]["details"]["files"].clear()
        self.assertEqual(ReportStore(self.output / "mock").load("mock-official-c", "details")["results"], [snapshot])
