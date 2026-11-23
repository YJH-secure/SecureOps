"""Offline D adapter tests. External C support fixtures must be hash-verified.

Set SECUREOPS_CD_FILE01_SUPPORT to the extracted support directory. A01 replays
an old sanitized VM JSON; transport metadata and all failure injections are MOCK.
No sample is presented as a new VM/SSH execution. No skip fallback is used.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker

from core.storage import ReportStore
from integration import cd_file01_adapter as adapter


class CDFile01AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.support = Path(os.environ["SECUREOPS_CD_FILE01_SUPPORT"])
        cls.actual = (cls.support / "samples/actual-needs-review-v12.json").read_bytes()
        cls.error = (cls.support / "samples/mock-diagnosis-error-v12.json").read_bytes()
        if hashlib.sha256(cls.actual).hexdigest() != "9848fa6687d0626f470851f92331e4321b7767f474b7a70005d0fa5de0d467f2":
            raise AssertionError("Recorded VM fixture hash mismatch")
        if hashlib.sha256(cls.error).hexdigest() != "2864024f7e7f8ed82a550c26b4022e3b5d59de514e33c67848b78192011976e2":
            raise AssertionError("Synthetic C error fixture hash mismatch")
        plan = json.loads((cls.support / "ADAPTER_TEST_CASES.json").read_text(encoding="utf-8"))
        if [r["id"] for r in plan["cases"]] != ["A%02d" % i for i in range(1, 18)]:
            raise AssertionError("A01-A17 source plan changed")
        schema = json.loads((Path(__file__).resolve().parents[1] /
            "docs/architecture/json-result-schema-v1.2.schema.json").read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ReportStore(self.temp.name)
        for name in ("subprocess.Popen", "os.system", "socket.create_connection"):
            guard = patch(name, side_effect=AssertionError("offline only"))
            guard.start()
            self.addCleanup(guard.stop)

    def execution(self, stdout=None, stderr=b""):
        stdout = self.actual if stdout is None else stdout
        return {
            "execution_id": adapter.new_execution_id(), "target_id": "ubuntu-a",
            "operation": adapter.OPERATION, "stdout": stdout, "stderr": stderr,
            "metadata": {
                "execution_succeeded": True, "exit_code": 0, "timeout": False,
                "truncated": False, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                "limits": {"connect_timeout_seconds": 10, "total_timeout_seconds": 60,
                           "stdout_max_bytes": 1048576, "stderr_max_bytes": 65536, "max_retries": 0},
                "preflight": {
                    "d_source_sha": adapter.D_SHA, "c_source_sha": adapter.C_SHA,
                    "d_source_verified": True, "c_files_verified": True,
                    "vm_state_verified": True, "apt_state_verified": True,
                },
            },
        }

    def call(self, execution, **kwargs):
        return adapter.receive_file01_result(execution, approved_target_id=kwargs.get("approved_target_id", "ubuntu-a"),
                                            store=self.store)

    def successful(self, execution, status):
        original = deepcopy(execution)
        result = self.call(execution)
        self.assertTrue(result["integration_success"], result)
        self.assertTrue(result["report_verified"])
        self.assertIsNone(result["error_stage"])
        self.assertEqual(result["execution_id"], execution["execution_id"])
        self.assertEqual(result["diagnosis_status"], status)
        self.assertEqual((result["save_status"], result["load_status"]), ("success", "success"))
        report = result["report"]
        self.validator.validate(report)
        self.assertEqual(report["results"], [json.loads(execution["stdout"].decode("utf-8"))])
        self.assertEqual(self.store.load("ubuntu-a", result["scan_id"]), report)
        self.assertEqual(json.loads(Path(result["saved_path"]).read_text(encoding="utf-8")), report)
        self.assertEqual(set(report), {"schema_version", "scan_id", "target_id", "os", "scanned_at", "results"})
        self.assertEqual(report["os"], "ubuntu-24.04")
        self.assertEqual(report["schema_version"], "1.2")
        self.assertEqual(str(UUID(result["scan_id"])), result["scan_id"])
        self.assertNotEqual(result["execution_id"], result["scan_id"])
        self.assertEqual(datetime.fromisoformat(report["scanned_at"]).utcoffset(), timezone.utc.utcoffset(None))
        item = report["results"][0]
        self.assertEqual(item["cvss"]["assessment_status"], "not_applicable")
        for key in ("version", "vector", "base_score", "rating", "source"):
            self.assertIsNone(item["cvss"][key])
        self.assertEqual(result["summary"]["metrics"]["total_items"], 1)
        self.assertEqual(result["summary"]["metrics"]["pass_rate"], "N/A (계산 불가)")
        self.assertEqual(execution, original)
        evidence = os.environ.get("SECUREOPS_CD_FILE01_EVIDENCE")
        if evidence:
            name = self._testMethodName + "-" + str(len(list(Path(evidence).glob("*-report.json"))))
            for suffix, data in (("report", report), ("loaded", self.store.load("ubuntu-a", result["scan_id"]))):
                (Path(evidence) / (name + "-" + suffix + ".json")).write_text(
                    json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result

    def stopped(self, execution, *, stage=None, code=None, parse_allowed=False, **kwargs):
        files = {p.name: p.read_bytes() for p in Path(self.temp.name).glob("*.json")}
        with patch.object(self.store, "save") as save, patch.object(self.store, "load") as load, \
             patch.object(adapter, "parse_result_json", wraps=adapter.parse_result_json) as parse:
            result = self.call(execution, **kwargs)
        self.assertFalse(result["integration_success"])
        self.assertFalse(result["report_verified"])
        self.assertIsNone(result["scan_id"])
        self.assertIsNone(result["report"])
        self.assertEqual(result["save_status"], "not_attempted")
        self.assertEqual(result["load_status"], "not_attempted")
        save.assert_not_called()
        load.assert_not_called()
        if not parse_allowed:
            parse.assert_not_called()
        if stage:
            self.assertEqual(result["error_stage"], stage)
        if code:
            self.assertEqual(result["error_code"], code)
        self.assertEqual(files, {p.name: p.read_bytes() for p in Path(self.temp.name).glob("*.json")})
        return result

    def test_A01_recorded_needs_review_json(self):
        self.successful(self.execution(), "needs_review")

    def test_A02_synthetic_diagnosis_error_exit_zero(self):
        self.successful(self.execution(self.error), "error")

    def test_A03_nonzero_exit(self):
        execution = self.execution(stderr=(self.support / "samples/mock-cli-failure.stderr").read_bytes())
        execution["metadata"]["exit_code"] = 2
        self.stopped(execution, code="unconfirmed_or_nonzero_exit")

    def test_A04_empty_stdout(self):
        self.stopped(self.execution((self.support / "samples/mock-empty.stdout").read_bytes()),
                     stage="parse", parse_allowed=True)

    def test_A05_broken_json(self):
        self.stopped(self.execution((self.support / "samples/mock-broken-json.stdout").read_bytes()),
                     stage="parse", parse_allowed=True)

    def test_A06_nonempty_stderr(self):
        self.stopped(self.execution(stderr=(self.support / "samples/mock-cli-warning.stderr").read_bytes()),
                     code="nonempty_stderr")

    def test_A07_connect_or_hostkey_failure(self):
        execution = self.execution()
        execution["metadata"].update(execution_succeeded=False, exit_code=None)
        result = self.stopped(execution, stage="transport", code="execution_failed")
        self.assertEqual(result["execution_id"], execution["execution_id"])

    def test_A08_timeout(self):
        execution = self.execution()
        execution["metadata"]["timeout"] = True
        self.stopped(execution, code="timeout")

    def test_A09_stdout_over_limit(self):
        self.stopped(self.execution(b"x" * (adapter.STDOUT_LIMIT + 1)), code="stdout_limit_exceeded")

    def test_A10_stderr_over_limit(self):
        self.stopped(self.execution(stderr=b"x" * (adapter.STDERR_LIMIT + 1)), code="stderr_limit_exceeded")

    def test_A11_truncation_with_valid_json(self):
        execution = self.execution()
        execution["metadata"]["truncated"] = True
        self.stopped(execution, code="truncated")

    def test_A12_wrong_check_id(self):
        item = json.loads(self.actual)
        item["check_id"] = "SVC-01"
        self.stopped(self.execution(json.dumps(item).encode()), stage="identity", code="wrong_check_id", parse_allowed=True)

    def test_A13_observed_os_missing_wrong_type_or_mismatch(self):
        for env in (None, [], "ubuntu", {}, {"id": "rocky", "version_id": "24.04"},
                    {"id": "ubuntu", "version_id": "24.04.5"}, {"id": "ubuntu", "version_id": 24.04},
                    {"id": True, "version_id": "24.04"}, {"id": "ubuntu ", "version_id": "24.04"}):
            with self.subTest(environment=env):
                item = json.loads(self.actual)
                if env is None:
                    del item["details"]["environment"]
                else:
                    item["details"]["environment"] = env
                self.stopped(self.execution(json.dumps(item).encode()), stage="os", parse_allowed=True)
        for details in (None, {}, []):
            with self.subTest(details=details):
                item = json.loads(self.actual)
                if details is None:
                    del item["details"]
                else:
                    item["details"] = details
                self.stopped(self.execution(json.dumps(item).encode()), parse_allowed=True)

    def test_A14_central_target_missing_or_mismatch(self):
        for target in (None, "", "rocky-b", False, 1):
            with self.subTest(target=target):
                execution = self.execution()
                execution["target_id"] = target
                self.stopped(execution, stage="identity")
        self.stopped(self.execution(), approved_target_id="rocky-b", stage="identity")

    def test_A15_preflight_hash_vm_or_apt_not_verified(self):
        for field in ("d_source_verified", "c_files_verified", "vm_state_verified", "apt_state_verified"):
            with self.subTest(field=field):
                execution = self.execution()
                execution["metadata"]["preflight"][field] = False
                transport = Mock()
                with self.assertRaises(ValueError):
                    adapter.validate_preflight(execution["metadata"]["preflight"])
                    transport()
                transport.assert_not_called()
                self.stopped(execution, stage="preflight")
        execution = self.execution()
        execution["metadata"]["preflight"]["c_source_sha"] = "wrong"
        self.stopped(execution, stage="preflight")

    def test_A16_store_failure_is_not_success(self):
        with patch.object(self.store, "save", side_effect=PermissionError("sensitive message")) as save, \
             patch.object(self.store, "load") as load:
            result = self.call(self.execution())
        save.assert_called_once()
        load.assert_not_called()
        self.assertFalse(result["integration_success"])
        self.assertEqual(result["save_status"], "unconfirmed")
        self.assertEqual(result["error_stage"], "save")
        self.assertIsNotNone(result["scan_id"])
        self.assertNotIn("sensitive message", json.dumps(result))

    def test_A17_load_failure_preserves_saved_report_and_id(self):
        execution = self.execution()
        with patch.object(self.store, "save", wraps=self.store.save) as save, \
             patch.object(self.store, "load", side_effect=OSError("private path")) as load:
            result = self.call(execution)
        save.assert_called_once()
        load.assert_called_once()
        self.assertEqual((result["save_status"], result["load_status"]), ("success", "failed"))
        self.assertFalse(result["report_verified"])
        self.assertFalse(result["integration_success"])
        self.assertEqual(result["error_stage"], "load")
        self.assertEqual(result["execution_id"], execution["execution_id"])
        self.assertIsNotNone(result["scan_id"])
        self.assertTrue(Path(result["saved_path"]).is_file())
        self.assertEqual(self.store.load("ubuntu-a", result["scan_id"]), result["report"])
        self.assertEqual(len(self.store.history("ubuntu-a")), 1)

    def test_X01_metadata_strict_types_and_required_fields(self):
        for field, values in {
            "exit_code": (None, True, False, "0", 1, -1),
            "execution_succeeded": (None, 1, "true"), "timeout": (None, 0), "truncated": (None, 0),
            "stdout_bytes": (True, "1", -1), "stderr_bytes": (False, None, -1),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    execution = self.execution()
                    execution["metadata"][field] = value
                    self.stopped(execution)
        for field in self.execution()["metadata"]:
            with self.subTest(missing=field):
                execution = self.execution()
                del execution["metadata"][field]
                self.stopped(execution)

    def test_X02_limit_attestations_and_byte_counts(self):
        for key in self.execution()["metadata"]["limits"]:
            for bad in (None, True, "10", 11):
                with self.subTest(limit=key, value=bad):
                    execution = self.execution()
                    execution["metadata"]["limits"][key] = bad
                    self.stopped(execution, code="limit_contract_mismatch")
        for key in ("stdout_bytes", "stderr_bytes"):
            execution = self.execution()
            execution["metadata"][key] += 1
            self.stopped(execution, code="output_byte_count_mismatch")
        execution = self.execution()
        execution["stdout"] = self.actual.decode()
        self.stopped(execution, code="raw_output_bytes_required")

    def test_X03_exact_stdout_boundary_and_stderr_boundary(self):
        data = self.actual + b" " * (adapter.STDOUT_LIMIT - len(self.actual))
        self.successful(self.execution(data), "needs_review")
        self.stopped(self.execution(stderr=b"x" * adapter.STDERR_LIMIT), code="nonempty_stderr")

    def test_X04_invalid_utf8_duplicate_json_and_invalid_cvss(self):
        self.stopped(self.execution(b"\xff"), stage="decode")
        self.stopped(self.execution(self.actual.replace(b'"check_id": "FILE-01"',
            b'"check_id": "FILE-01", "check_id": "FILE-01"')), stage="parse", parse_allowed=True)
        for changes in ({"base_score": 0.0}, {"assessment_status": "pending"}, {"rating": "low"}):
            with self.subTest(cvss=changes):
                item = json.loads(self.actual)
                item["cvss"].update(changes)
                self.stopped(self.execution(json.dumps(item).encode()), stage="parse", parse_allowed=True)
        self.stopped(self.execution(b"log\n" + self.actual), stage="parse", parse_allowed=True)
        self.stopped(self.execution(self.actual + self.actual), stage="parse", parse_allowed=True)

    def test_X05_loaded_dict_mismatch_is_not_verified(self):
        real_load = self.store.load
        def changed_load(target, scan):
            report = real_load(target, scan)
            report["results"][0]["evidence"] = "changed"
            return report
        with patch.object(self.store, "load", side_effect=changed_load):
            result = self.call(self.execution())
        self.assertEqual(result["error_stage"], "verify")
        self.assertEqual(result["error_code"], "report_mismatch")
        self.assertEqual(result["load_status"], "success")
        self.assertFalse(result["report_verified"])
        self.assertFalse(result["integration_success"])
        self.assertEqual(real_load("ubuntu-a", result["scan_id"]), result["report"])

    def test_X06_duplicate_scan_does_not_overwrite(self):
        first = self.successful(self.execution(), "needs_review")
        data = Path(first["saved_path"]).read_bytes()
        with patch("core.main.uuid4", return_value=UUID(first["scan_id"])):
            second = self.call(self.execution())
        self.assertFalse(second["integration_success"])
        self.assertEqual(second["error_stage"], "save")
        self.assertEqual(second["scan_id"], first["scan_id"])
        self.assertEqual(Path(first["saved_path"]).read_bytes(), data)
        self.assertEqual(len(self.store.history("ubuntu-a")), 1)

    def test_X07_save_published_then_raised_is_unconfirmed_not_deleted(self):
        real_save = self.store.save
        def publish_then_fail(report):
            real_save(report)
            raise OSError("after publication")
        with patch.object(self.store, "save", side_effect=publish_then_fail) as save, \
             patch.object(self.store, "load") as load:
            result = self.call(self.execution())
        save.assert_called_once()
        load.assert_not_called()
        self.assertEqual(result["save_status"], "unconfirmed")
        self.assertFalse(result["integration_success"])
        self.assertEqual(self.store.load("ubuntu-a", result["scan_id"]), result["report"])

    def test_X08_missing_execution_id_or_operation_never_generates_report(self):
        for bad in (None, "", "not-an-id", False):
            execution = self.execution()
            execution["execution_id"] = bad
            self.stopped(execution, code="invalid_execution_id")
        execution = self.execution()
        execution["operation"] = "arbitrary"
        self.stopped(execution, code="operation_mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=2)
