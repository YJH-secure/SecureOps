"""Actual supplied C ZIP diagnosis/adapter -> unchanged D; synthetic inputs only.

SECUREOPS_C_ZIP_SOURCE_ROOT is independent from the historical C regression root.
This supplied source is not an official C Git commit. No verdict is mocked.
"""

import argparse
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


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = {}


class CZipV12IntegrationTests(unittest.TestCase):
    def setUp(self):
        supplied = os.environ.get("SECUREOPS_C_ZIP_SOURCE_ROOT")
        if not supplied:
            self.skipTest("C ZIP source not supplied: SECUREOPS_C_ZIP_SOURCE_ROOT")
        self.source = Path(supplied)
        if not (self.source / "checks/system/result_adapter.py").is_file():
            self.skipTest("C ZIP adapter source missing")
        module_guard = patch.dict(sys.modules)
        module_guard.start()
        self.addCleanup(module_guard.stop)
        package = types.ModuleType("_c_zip_integration_pkg")
        package.__path__ = [str(self.source / "checks/system")]
        sys.modules[package.__name__] = package
        self.file, self.svc, self.fw, self.log, self.adapter, self.common = [
            importlib.import_module(package.__name__ + "." + name) for name in
            ("file_check", "service_check", "firewall_check", "log_check", "result_adapter", "common")]
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.temporary = Path(directory.name)
        self.etc = self.temporary / "synthetic-etc"
        self.etc.mkdir()
        self.output = self.temporary / "reports"
        self.environment = {"id": "ubuntu", "version_id": "24.04",
                            "named_groups": {"shadow": 42}, "group_lookup_state": "collected"}
        for module in (self.svc, self.fw, self.log):
            guard = patch.object(module, "read_target_os", return_value=copy.deepcopy(self.environment))
            guard.start()
            self.addCleanup(guard.stop)
        hostname = patch("socket.gethostname", return_value="mock-c-zip")
        hostname.start()
        self.addCleanup(hostname.stop)
        for target in ("subprocess.Popen", "os.system", "socket.socket"):
            guard = patch(target, side_effect=AssertionError("Actual process/network forbidden"))
            mock = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mock.assert_not_called)
        # Every normal C call below receives synthetic collectors. Block fallbacks.
        for module, name in ((self.file, "collect_file_info"), (self.file, "environment_info"),
                             (self.svc, "_read_command"), (self.fw, "_read_command")):
            guard = patch.object(module, name, side_effect=AssertionError("Live collection forbidden"))
            mock = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mock.assert_not_called)
        # LOG's config discovery calls path_metadata directly even when the
        # log-path metadata_reader is injected. Confine that separate boundary
        # to this test's empty synthetic config tree; never inspect /etc.
        def synthetic_config_metadata(path):
            if not Path(path).resolve().is_relative_to(self.etc.resolve()):
                raise AssertionError("Host metadata read outside synthetic config tree")
            return {"path": path.as_posix(), "state": "missing"}
        metadata_guard = patch.object(self.log, "path_metadata", side_effect=synthetic_config_metadata)
        metadata_guard.start()
        self.addCleanup(metadata_guard.stop)
        self.calls = []

    def generate(self):
        policy = self.common.load_policy(self.source / "checks/system/policies/file_policy.ubuntu-24.04.json")
        file_policy = next(p for p in policy["policies"] if p["check_id"] == "FILE-01")
        observations = {
            "/etc/passwd": {"path": "/etc/passwd", "uid": 0, "gid": 0, "mode": "0666",
                            "file_type": "regular", "acl": {"state": "collected",
                            "raw": "user::rw-\ngroup::rw-\nother::rw-\n"}},
            "/etc/shadow": {"path": "/etc/shadow", "uid": 0, "gid": 42, "mode": "0640",
                            "file_type": "regular", "acl": {"state": "collected",
                            "raw": "user::rw-\ngroup::r--\nother::---\n"}},
        }
        before = copy.deepcopy((file_policy, observations, self.environment))
        file_result = self.file.run(file_policy, collector=lambda p: observations[p],
                                    environment=self.environment)
        self.assertEqual((file_policy, observations, self.environment), before)

        svc_outputs = {
            self.svc.ACTIVE_COMMAND: "example.service loaded active running MOCK service\n",
            self.svc.UNIT_FILES_COMMAND: "example.service enabled enabled\n",
            self.svc.LISTENERS_COMMAND: "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\n",
        }
        fw_outputs = {
            self.fw.UFW_STATUS: "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
            self.fw.NFT_RULESET: json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}]}),
            self.fw.LISTENERS_COMMAND: "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\n",
        }
        log_outputs = {self.log.unit_command(unit): "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"
                       for unit in self.log.UNITS}
        log_outputs[self.log.JOURNAL_CONFIG] = "[Journal]\nStorage=auto\nSystemMaxUse=200M\n"

        def supplied(name, outputs):
            def collect(command):
                self.calls.append({"module": name, "command_not_executed": list(command)})
                if name == "LOG-01" and command == self.log.JOURNAL_USAGE:
                    raise PermissionError("MOCK journal usage collection denied")
                if command not in outputs:
                    raise AssertionError("Unexpected collector request")
                return outputs[command]
            return collect

        svc_result = self.svc.run_from_policy(command_runner=supplied("SVC-01", svc_outputs),
            target_id="mock-c-zip", role="mock-service", network_context="mock-offline")
        fw_result = self.fw.run_from_policy(command_runner=supplied("FW-01", fw_outputs))
        log_result = self.log.run_from_policy(command_runner=supplied("LOG-01", log_outputs),
            config_root=self.etc, metadata_reader=lambda p: {"path": p.as_posix(), "state": "missing"})
        results = [file_result, svc_result, fw_result, log_result]
        self.assertEqual([r["check_id"] for r in results], ["FILE-01", "SVC-01", "FW-01", "LOG-01"])
        self.assertEqual([r["status"] for r in results], ["vulnerable", "needs_review", "needs_review", "error"])
        return results

    def receive(self, item, version):
        return parse_result_json(json.dumps(item, ensure_ascii=False, allow_nan=False),
                                 exit_code=0, execution_succeeded=True, schema_version=version)

    def pipeline(self, items, version, scan_id):
        result = run_target(account_checks=[], system_checks=[
            lambda item=item: self.receive(item, version) for item in items],
            target_id="mock-c-zip", os="ubuntu-24.04", mode="mock", output_root=self.output,
            schema_version=version, scan_id=scan_id, scanned_at="2026-11-10T12:00:00+09:00")
        loaded = ReportStore(self.output / "mock").load("mock-c-zip", scan_id)
        self.assertEqual(loaded, result.report)
        self.assertEqual(loaded["results"], items)
        loader = DiagnosisAggregator(str(result.path))
        self.assertEqual(loader.get_report(), loaded)
        self.assertEqual(loader.aggregate_results(), result.summary)
        return result

    def test_four_actual_c_v12_results_to_d_storage(self):
        legacy = self.generate()
        before = copy.deepcopy(legacy)
        v12 = [self.adapter.adapt_result(item, "1.2") for item in legacy]
        self.assertEqual(legacy, before)
        for old, new in zip(legacy, v12):
            self.assertEqual({k: new[k] for k in old if k != "severity"},
                             {k: old[k] for k in old if k != "severity"})
            self.assertNotIn("severity", new)
            for key in ("version", "vector", "base_score", "rating", "source"):
                self.assertIsNone(new["cvss"][key])
        result = self.pipeline(v12, "1.2", "c-v12")
        metrics = result.summary["metrics"]
        self.assertEqual([metrics[k] for k in ("total_items", "vulnerable_count", "error_count", "needs_review_count")],
                         [4, 1, 1, 2])
        self.assertEqual(metrics["pass_rate"], "0.0%")
        self.assertEqual(result.summary["cvss_assessment_breakdown"],
                         {"scored": 0, "pending": 1, "not_applicable": 3})
        self.assertEqual(sum(result.summary["cvss_rating_breakdown"].values()), 0)
        EVIDENCE.update(c_v11=before, c_v12=copy.deepcopy(v12), report_v12=result.report,
                        summary_v12=result.summary, synthetic_command_requests=self.calls)

    def test_v11_default_adapter_and_d_default_contract(self):
        legacy = self.generate()
        exported = [self.adapter.adapt_result(item) for item in legacy]
        self.assertEqual(exported, legacy)
        for item in exported:
            self.assertIn("severity", item)
            self.assertNotIn("cvss", item)
            self.assertEqual(parse_result_json(json.dumps(item), exit_code=0, execution_succeeded=True), item)
        result = run_target(account_checks=[], system_checks=[lambda item=item: item for item in exported],
            target_id="mock-c-zip", os="ubuntu-24.04", mode="mock", output_root=self.output, scan_id="c-v11")
        self.assertEqual(result.report["schema_version"], "1.1")
        self.assertEqual(ReportStore(self.output / "mock").load("mock-c-zip", "c-v11")["results"], legacy)
        EVIDENCE["report_v11"] = result.report
        EVIDENCE["summary_v11"] = result.summary

    def test_diagnosis_error_is_valid_delivered_json(self):
        item = self.adapter.adapt_result(self.generate()[-1], "1.2")
        result = self.pipeline([item], "1.2", "diagnosis-error")
        self.assertEqual(result.summary["metrics"]["error_count"], 1)
        self.assertEqual(result.summary["metrics"]["pass_count"], 0)
        self.assertEqual(result.summary["metrics"]["pass_rate"], "N/A (계산 불가)")
        self.assertEqual(item["cvss"]["assessment_status"], "not_applicable")

    def assert_pipeline_rejects(self, text, *, code=0, succeeded=True):
        with self.assertRaises(RunFailed) as raised:
            run_target(account_checks=[], system_checks=[lambda: parse_result_json(
                text, exit_code=code, execution_succeeded=succeeded, schema_version="1.2")],
                target_id="mock-c-zip", os="ubuntu-24.04", output_root=self.output,
                mode="mock", schema_version="1.2")
        self.assertIsInstance(raised.exception.failures[0].cause, RemoteResultError)
        self.assertFalse((self.output / "mock").exists())

    def test_execution_failure_rejected_without_report(self):
        text = json.dumps(self.adapter.adapt_result(self.generate()[0], "1.2"))
        for code, success in ((1, True), (0, False), (255, False)):
            with self.subTest(code=code, success=success):
                self.assert_pipeline_rejects(text, code=code, succeeded=success)

    def test_malformed_json_rejected_without_report(self):
        text = json.dumps(self.adapter.adapt_result(self.generate()[0], "1.2"))
        for value in ("", "{", "MOCK log\n" + text, text + "\n{}", "[]",
                      text.replace('"cvss": {', '"cvss": {"rating": "high",')):
            with self.subTest(payload=value[:20]):
                self.assert_pipeline_rejects(value)

    def test_invalid_cvss_rejected_without_repair(self):
        original = self.adapter.adapt_result(self.generate()[0], "1.2")
        for change in ({"base_score": 0.0}, {"base_score": True},
                       {"assessment_status": "scored"}, {"rationale": ""},
                       {"assessment_status": "unknown"}, {"vector": "CVSS:3.1/AV:N"}):
            item = copy.deepcopy(original)
            item["cvss"].update(change)
            with self.subTest(change=change):
                self.assert_pipeline_rejects(json.dumps(item))

    def test_existing_scored_fixture_is_separate_from_c_outputs(self):
        # This is the existing mathematical fixture, never relabeled as a C result.
        fixture = json.loads((ROOT / "tests/fixtures/sample-result-v1.2-MOCK.json").read_text(encoding="utf-8"))
        item = next(r for r in fixture["results"] if r["cvss"]["assessment_status"] == "scored")
        parsed = self.receive(item, "1.2")
        self.assertEqual((parsed["cvss"]["base_score"], parsed["cvss"]["rating"]), (9.8, "critical"))
        bad = copy.deepcopy(item)
        bad["cvss"]["base_score"] = 9.7
        self.assert_pipeline_rejects(json.dumps(bad))

    def test_deep_details_and_input_independence(self):
        legacy = self.generate()
        v12 = [self.adapter.adapt_result(item, "1.2") for item in legacy]
        snapshot = copy.deepcopy(v12)
        result = self.pipeline(v12, "1.2", "preserved")
        legacy[0]["details"]["files"].clear()
        v12[0]["details"]["files"].clear()
        self.assertEqual(result.report["results"], snapshot)
        result.report["results"][0]["details"]["files"].clear()
        self.assertEqual(ReportStore(self.output / "mock").load("mock-c-zip", "preserved")["results"], snapshot)

    def test_c_cli_version_selection_defaults_to_v11(self):
        parser = argparse.ArgumentParser()
        self.adapter.add_result_version_argument(parser)
        self.assertEqual(parser.parse_args([]).result_version, "1.1")
        self.assertEqual(parser.parse_args(["--result-version", "1.2"]).result_version, "1.2")


if __name__ == "__main__":
    unittest.main()
