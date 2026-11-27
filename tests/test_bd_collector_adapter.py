"""Synthetic D boundary regressions and separately named official B integration tests."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4, UUID

from jsonschema import Draft202012Validator, FormatChecker

from core.storage import ReportStore
from integration import bd_collector_adapter as adapter


ARTIFACTS = []


class ProposedCollectorTrustError(ValueError):
    """Test-only stand-in, not a claimed public B exception class."""


def synthetic_document():
    os_record = {"state": "ok", "text": 'ID=ubuntu\nVERSION_ID="24.04"\n'}
    return {"collector": {"name": "secureops-b-read", "version": "0.1-draft", "elapsed_ms": 1},
            "context_used": {"host": "192.0.2.10", "addr": "192.0.2.10"},
            "payloads": {"SSH-02": {"sshd_installed": True},
                         "ACC-01": {"os_release": deepcopy(os_record)},
                         "ACC-02": {"os_release": deepcopy(os_record)}}}


def synthetic_results():
    results = []
    for check_id, status in zip(("SSH-02", "ACC-01", "ACC-02"),
                                ("pass", "vulnerable", "needs_review")):
        results.append({"check_id": check_id, "status": status,
                        "evidence": "Synthetic B-shaped result, no policy evaluation.",
                        "recommendation": "Review synthetic evidence.",
                        "details": {"findings": [{"status": status, "actual": None}],
                                    "nested": {"values": [None, False, 0, "preserved"]}},
                        "cvss": {"assessment_status": "pending" if status == "vulnerable"
                                 else "not_applicable", "version": None, "vector": None,
                                 "base_score": None, "rating": None, "source": None,
                                 "rationale": "Synthetic unscored result."}})
    return {r["check_id"]: r for r in results}


class _BoundaryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Guard all test paths against accidental subprocess/network execution.
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen"):
            blocker = patch(target, side_effect=AssertionError("external execution forbidden"))
            blocker.start()
            self.addCleanup(blocker.stop)
        self.store = ReportStore(Path(self.tmp.name) / "reports")
        self.save = Mock(wraps=self.store.save)
        self.load = Mock(wraps=self.store.load)
        self.store.save, self.store.load = self.save, self.load
        self.profile = adapter.ApprovedProfile("ubuntu-a", "192.0.2.10", "192.0.2.10",
                                               "ubuntu", "24.04", "ubuntu-24.04")
        self.document = synthetic_document()
        self.results = synthetic_results()
        self.judge = Mock(side_effect=lambda raw_stdout, trusted_context, *, result_version: deepcopy(self.results))
        self.trust_error = ProposedCollectorTrustError
        self.execution = {"execution_id": str(uuid4()), "target_id": "ubuntu-a",
                          "operation": "b_read_v1", "stdout": b"", "stderr": b"",
                          "metadata": {"execution_succeeded": True, "exit_code": 0,
                                       "timeout": False, "truncated": False,
                                       "limits": dict(adapter.LIMITS)}}
        self.set_stdout(json.dumps(self.document).encode() + b"\n")

    def set_stdout(self, value):
        self.execution["stdout"] = value
        self.execution["metadata"]["stdout_bytes"] = len(value)
        self.execution["metadata"]["stderr_bytes"] = len(self.execution["stderr"])

    def sync_document(self):
        self.set_stdout(json.dumps(self.document).encode() + b"\n")

    def receive(self):
        response = adapter.receive_b_collector_result(
            self.execution, profile=self.profile, store=self.store,
            judge_collector_output=self.judge, collector_trust_error=self.trust_error,
            evidence_ref="synthetic-case")
        recorded = deepcopy(response)
        if recorded["saved_path"]:
            recorded["saved_path"] = "<TEMP_REPORTSTORE>/" + Path(recorded["saved_path"]).name
        ARTIFACTS.append({"test": self.id(), "response": recorded})
        return response

    def assert_stopped(self, response, stage, *, before_judge=True):
        self.assertFalse(response["integration_success"])
        self.assertFalse(response["report_verified"])
        self.assertEqual(response["failure"]["stage"], stage)
        self.save.assert_not_called()
        self.load.assert_not_called()
        self.assertEqual(list(self.store.root.glob("*.json")), [])
        if before_judge:
            self.judge.assert_not_called()
        ARTIFACTS.append({"test": self.id(), "failure": response["failure"]})


class BDCollectorAdapterTests(_BoundaryCase):
    def test_BD01_normal_three_results(self):
        response = self.receive()
        self.assertTrue(response["integration_success"])
        self.assertEqual(response["report"]["results"], list(self.results.values()))
        self.assertEqual(response["report"]["target_id"], "ubuntu-a")
        self.assertEqual(response["report"]["os"], "ubuntu-24.04")
        self.assertEqual(str(UUID(response["scan_id"])), response["scan_id"])
        self.assertTrue(response["scanned_at"].endswith("+00:00"))
        self.judge.assert_called_once_with(self.execution["stdout"],
            {"host": self.profile.host, "addr": self.profile.addr,
             "os_id": self.profile.os_id, "os_version": self.profile.version_id}, result_version="1.2")
        schema_path = Path(__file__).parents[1] / "docs/architecture/json-result-schema-v1.2.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(response["report"])
        self.assertNotIn("execution_id", response["report"])
        ARTIFACTS.append({"test": self.id(), "report": response["report"],
                          "summary": response["summary"], "execution_id": response["execution_id"],
                          "scan_id": response["scan_id"], "report_verified": True})

    def test_BD02_valid_diagnosis_error_preserved(self):
        self.results["SSH-02"]["status"] = "error"
        self.results["SSH-02"]["details"]["findings"][0]["status"] = "error"
        response = self.receive()
        self.assertTrue(response["integration_success"])
        self.assertEqual(response["report"]["results"], list(self.results.values()))
        self.assertEqual(response["report"]["results"][0]["status"], "error")

    def test_BD03_collection_failure(self):
        self.execution["metadata"]["execution_succeeded"] = False
        self.assert_stopped(self.receive(), "transport")

    def test_BD04_nonempty_stderr(self):
        self.execution["stderr"] = b"restricted synthetic warning"
        self.execution["metadata"]["stderr_bytes"] = len(self.execution["stderr"])
        self.assert_stopped(self.receive(), "transport")

    def test_BD05_timeout(self):
        self.execution["metadata"]["timeout"] = True
        self.assert_stopped(self.receive(), "transport")

    def test_BD06_truncated(self):
        self.execution["metadata"]["truncated"] = True
        self.assert_stopped(self.receive(), "transport")

    def test_BD07_exit_code_rejection(self):
        for value in (255, 1, 2, 3, 4, None, True, "0"):
            with self.subTest(exit_code=value):
                self.execution["metadata"]["exit_code"] = value
                self.assert_stopped(self.receive(), "transport")

    def test_BD08_target_mismatch(self):
        self.execution["target_id"] = "rocky-b"
        self.assert_stopped(self.receive(), "identity")

    def test_BD09_host_addr_mismatch(self):
        for field in ("host", "addr"):
            with self.subTest(field=field):
                self.document = synthetic_document()
                self.document["context_used"][field] = "mismatch"
                self.sync_document()
                self.assert_stopped(self.receive(), "context")

    def test_BD10_os_id_version_mismatch(self):
        for check in ("ACC-01", "ACC-02"):
            for text in ('ID=rocky\nVERSION_ID="9.8"', 'ID=ubuntu\nVERSION_ID="22.04"'):
                with self.subTest(check=check, text=text):
                    self.document = synthetic_document()
                    self.document["payloads"][check]["os_release"]["text"] = text
                    self.sync_document()
                    self.assert_stopped(self.receive(), "os")

    def test_BD11_missing_result(self):
        self.results.pop("ACC-02")
        self.assert_stopped(self.receive(), "results", before_judge=False)

    def test_BD12_duplicate_result(self):
        self.results["ACC-02"] = deepcopy(self.results["SSH-02"])
        self.assert_stopped(self.receive(), "results", before_judge=False)

    def test_BD13_save_failure_unconfirmed_no_retry(self):
        self.save.side_effect = PermissionError("secret exception text")
        response = self.receive()
        self.assertFalse(response["integration_success"])
        self.assertEqual(response["failure"]["stage"], "save")
        self.assertEqual(response["save_status"], "unconfirmed")
        self.assertIsNotNone(response["scan_id"])
        self.save.assert_called_once()
        self.load.assert_not_called()
        self.assertNotIn("secret", json.dumps(response["failure"]))

    def test_BD14_load_failure_preserves_publication_and_ids(self):
        self.load.side_effect = OSError("restricted path")
        response = self.receive()
        self.assertFalse(response["integration_success"])
        self.assertEqual(response["save_status"], "success")
        self.assertEqual(response["load_status"], "failed")
        self.assertEqual(response["failure"]["stage"], "load")
        self.assertEqual(response["execution_id"], self.execution["execution_id"])
        self.assertTrue(Path(response["saved_path"]).exists())
        self.assertEqual(ReportStore.load(self.store, "ubuntu-a", response["scan_id"]),
                         response["report"])
        self.save.assert_called_once()
        self.load.assert_called_once()

    def test_BD15_full_roundtrip_and_input_immutability(self):
        before = deepcopy(self.execution), deepcopy(self.results)
        response = self.receive()
        self.assertTrue(response["report_verified"])
        self.assertEqual(ReportStore.load(self.store, "ubuntu-a", response["scan_id"]),
                         response["report"])
        self.assertEqual(before, (self.execution, self.results))
        self.save.assert_called_once()
        self.load.assert_called_once()

    def test_BD16_collector_trust_error_is_stop(self):
        self.judge.side_effect = ProposedCollectorTrustError("restricted trust reason")
        response = self.receive()
        self.assert_stopped(response, "judge", before_judge=False)
        self.assertEqual(response["failure"]["code"], "collector_trust_error")

    def test_BD17_load_mismatch_is_not_success(self):
        self.load.side_effect = lambda *args: {"changed": True}
        response = self.receive()
        self.assertFalse(response["integration_success"])
        self.assertFalse(response["report_verified"])
        self.assertEqual(response["failure"]["stage"], "verify")
        self.assertEqual(response["save_status"], "success")

    def test_BD18_invalid_utf8(self):
        self.set_stdout(b"\xff")
        self.assert_stopped(self.receive(), "decode")

    def test_BD19_malformed_and_duplicate_json(self):
        for value in (b"{", b'{"collector":{},"collector":{}}', b"NaN"):
            with self.subTest(value=value):
                self.set_stdout(value)
                self.assert_stopped(self.receive(), "envelope")

    def test_BD20_byte_limits(self):
        self.set_stdout(b"x" * (adapter.STDOUT_LIMIT + 1))
        self.assert_stopped(self.receive(), "transport")
        self.sync_document()
        self.execution["stderr"] = b"x" * (adapter.STDERR_LIMIT + 1)
        self.execution["metadata"]["stderr_bytes"] = len(self.execution["stderr"])
        self.assert_stopped(self.receive(), "transport")

    def test_BD21_invalid_metadata(self):
        original = deepcopy(self.execution)
        for key, value in (("timeout", 0), ("truncated", None),
                           ("execution_succeeded", 1), ("stdout_bytes", True)):
            with self.subTest(key=key):
                self.execution = deepcopy(original)
                self.execution["metadata"][key] = value
                self.assert_stopped(self.receive(), "metadata")
        self.execution = deepcopy(original)
        self.execution["metadata"]["stdout_bytes"] += 1
        self.assert_stopped(self.receive(), "transport")

    def test_BD22_payload_set_and_envelope_validation(self):
        for mutation in (lambda d: d["payloads"].pop("ACC-02"),
                         lambda d: d.update(extra=True),
                         lambda d: d["collector"].update(elapsed_ms=True)):
            with self.subTest(mutation=mutation):
                self.document = synthetic_document()
                mutation(self.document)
                self.sync_document()
                self.assert_stopped(self.receive(), "envelope")

    def test_BD23_missing_unknown_or_ambiguous_os(self):
        for text in ("", "ID=ubuntu", "ID=ubuntu\nID=rocky\nVERSION_ID=24.04"):
            with self.subTest(text=text):
                self.document["payloads"]["ACC-01"]["os_release"]["text"] = text
                self.sync_document()
                self.assert_stopped(self.receive(), "os")

    def test_BD24_severity_invalid_cvss_and_missing_field_rejected(self):
        for mutation in (lambda r: r.update(severity="high"),
                         lambda r: r["cvss"].update(base_score=0.0),
                         lambda r: r.pop("recommendation")):
            with self.subTest(mutation=mutation):
                self.results = synthetic_results()
                mutation(self.results["SSH-02"])
                self.assert_stopped(self.receive(), "results", before_judge=False)

    def test_BD25_operation_and_id_validation(self):
        self.execution["operation"] = "file01_v12"
        self.assert_stopped(self.receive(), "identity")
        self.execution["operation"] = "b_read_v1"
        self.execution["execution_id"] = "invalid"
        self.assert_stopped(self.receive(), "input")

    def test_BD26_limits_and_raw_types(self):
        self.execution["metadata"]["limits"]["max_retries"] = True
        self.assert_stopped(self.receive(), "metadata")
        self.execution["metadata"]["limits"] = dict(adapter.LIMITS)
        self.execution["stdout"] = self.execution["stdout"].decode()
        self.assert_stopped(self.receive(), "transport")

    def test_BD27_extra_metadata_is_not_diagnosis_data(self):
        self.execution["metadata"]["unapproved_extra"] = "not persisted"
        response = self.receive()
        self.assertTrue(response["integration_success"])
        self.assertNotIn("unapproved_extra", json.dumps(response))

    def test_BD28_report_collision_preserves_existing_report(self):
        first = self.receive()
        with patch("core.main.uuid4", return_value=UUID(first["scan_id"])):
            second = self.receive()
        self.assertFalse(second["integration_success"])
        self.assertEqual(second["failure"]["stage"], "save")
        self.assertEqual(ReportStore.load(self.store, "ubuntu-a", first["scan_id"]), first["report"])
        self.assertEqual(len(list(self.store.root.glob("*.json"))), 1)


class OfficialBIntegrationTests(_BoundaryCase):
    """Real provided B entry + pinned B collector/judgment code + real D store.

    Only target filesystem/command observations are fake. Mock(wraps=...) below
    observes the real B entry; it does not replace its return or judgment.
    """
    def setUp(self):
        super().setUp()
        import collector_entry
        from test_collector_entry import collector_stdout
        self.entry = collector_entry
        self.set_stdout(collector_stdout())
        self.judge = Mock(wraps=collector_entry.judge_collector_output)
        self.trust_error = collector_entry.CollectorTrustError

    def change_document(self, change):
        document = json.loads(self.execution["stdout"])
        change(document)
        self.set_stdout((json.dumps(document, ensure_ascii=False) + "\n").encode("utf-8"))

    def test_OBD01_real_entry_roundtrip_raw_bytes_and_trusted_context(self):
        raw = self.execution["stdout"]
        trusted = {"host": self.profile.host, "addr": self.profile.addr,
                   "os_id": self.profile.os_id, "os_version": self.profile.version_id}
        expected = self.entry.judge_collector_output(raw, trusted, result_version="1.2")
        response = self.receive()
        self.assertTrue(response["integration_success"])
        self.judge.assert_called_once_with(raw, trusted, result_version="1.2")
        self.assertIs(self.judge.call_args.args[0], raw)
        self.assertEqual(set(self.judge.call_args.args[1]),
                         {"host", "addr", "os_id", "os_version"})
        self.assertEqual(response["report"]["results"], list(expected.values()))
        self.assertEqual(ReportStore.load(self.store, "ubuntu-a", response["scan_id"]),
                         response["report"])
        self.assertEqual(response["execution_id"], self.execution["execution_id"])
        self.assertNotIn("execution_id", response["report"])
        self.assertTrue(response["report_verified"])
        self.save.assert_called_once()
        self.load.assert_called_once()
        schema_path = Path(__file__).parents[1] / "docs/architecture/json-result-schema-v1.2.schema.json"
        Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")),
                             format_checker=FormatChecker()).validate(response["report"])

    def test_OBD02_real_item_error_preserved(self):
        def change(document):
            user = next(iter(document["payloads"]["SSH-02"]["sshd_T_C"]))
            document["payloads"]["SSH-02"]["sshd_T_C"][user] = {"state": "timeout"}
            document["payloads"]["ACC-02"]["files"]["/etc/pam.d/common-auth"] = {"state": "error"}
        self.change_document(change)
        expected = self.entry.judge_collector_output(self.execution["stdout"],
            {"host": self.profile.host, "addr": self.profile.addr,
             "os_id": self.profile.os_id, "os_version": self.profile.version_id})
        response = self.receive()
        self.assertTrue(response["integration_success"])
        self.assertEqual(response["report"]["results"], list(expected.values()))
        self.assertEqual(expected["SSH-02"]["status"], "error")
        self.assertEqual(expected["ACC-02"]["status"], "error")
        self.assertIsNone(expected["ACC-02"]["cvss"]["base_score"])

    def test_OBD03_real_needs_review_and_null_preserved(self):
        response = self.receive()
        self.assertTrue(response["integration_success"])
        reviews = [r for r in response["report"]["results"] if r["status"] == "needs_review"]
        self.assertTrue(reviews)
        for result in reviews:
            self.assertEqual(result["cvss"]["assessment_status"], "not_applicable")
            for key in ("version", "vector", "base_score", "rating"):
                self.assertIsNone(result["cvss"][key])
            self.assertIn("details", result)

    def test_OBD04_invalid_utf8_before_B(self):
        self.set_stdout(b"\xff")
        self.assert_stopped(self.receive(), "decode")

    def test_OBD05_malformed_json_before_B(self):
        self.set_stdout(b"{bad json}\n")
        self.assert_stopped(self.receive(), "envelope")

    def test_OBD06_duplicate_json_key_before_B(self):
        text = self.execution["stdout"].decode().rstrip()
        self.set_stdout((text[:-1] + ',"payloads":{}}\n').encode())
        self.assert_stopped(self.receive(), "envelope")

    def test_OBD07_missing_payload_before_B(self):
        self.change_document(lambda d: d["payloads"].pop("ACC-02"))
        self.assert_stopped(self.receive(), "envelope")

    def test_OBD08_host_addr_mismatch_before_B(self):
        original = self.execution["stdout"]
        for key in ("host", "addr"):
            with self.subTest(key=key):
                self.set_stdout(original)
                self.change_document(lambda d: d["context_used"].update({key: "mismatch"}))
                self.assert_stopped(self.receive(), "context")

    def test_OBD09_os_mismatch_before_B(self):
        original = self.execution["stdout"]
        for text in ("ID=rocky\nVERSION_ID=9.8", "ID=ubuntu\nVERSION_ID=22.04"):
            with self.subTest(text=text):
                self.set_stdout(original)
                self.change_document(lambda d: d["payloads"]["ACC-01"]["os_release"].update(text=text))
                self.assert_stopped(self.receive(), "os")

    def test_OBD10_nonzero_exit_before_B(self):
        for code in (255, 1, 2, 3, 4, None, True, "0"):
            with self.subTest(code=code):
                self.execution["metadata"]["exit_code"] = code
                self.assert_stopped(self.receive(), "transport")

    def test_OBD11_stderr_before_B(self):
        self.execution["stderr"] = b"synthetic warning"
        self.execution["metadata"]["stderr_bytes"] = len(self.execution["stderr"])
        self.assert_stopped(self.receive(), "transport")

    def test_OBD12_timeout_before_B(self):
        self.execution["metadata"]["timeout"] = True
        self.assert_stopped(self.receive(), "transport")

    def test_OBD13_truncated_before_B(self):
        self.execution["metadata"]["truncated"] = True
        self.assert_stopped(self.receive(), "transport")

    def test_OBD14_actual_B_trust_exception_blocks_store(self):
        # D's strict JSON accepts CRLF; the real B single-line contract rejects it.
        self.set_stdout(self.execution["stdout"].rstrip(b"\n") + b"\r\n")
        with self.assertRaises(self.entry.CollectorTrustError) as caught:
            self.entry.judge_collector_output(self.execution["stdout"],
                {"host": self.profile.host, "addr": self.profile.addr,
                 "os_id": self.profile.os_id, "os_version": self.profile.version_id})
        self.assertEqual(caught.exception.stage, "decode")
        self.assertEqual(caught.exception.reason, "not_single_line_json")
        response = self.receive()
        self.assert_stopped(response, "judge", before_judge=False)
        self.judge.assert_called_once()
        self.assertEqual(response["failure"]["code"], "collector_trust_error")
        self.assertEqual(response["failure"]["collector_trust"],
                         {"stage": "decode", "reason": "not_single_line_json"})
        self.assertIsNone(response["report"])
        self.assertIsNone(response["scan_id"])

    def test_OBD15_real_judge_save_failure_not_success(self):
        self.save.side_effect = PermissionError("restricted synthetic permission error")
        response = self.receive()
        self.assertFalse(response["integration_success"])
        self.assertEqual(response["failure"]["stage"], "save")
        self.assertEqual(response["save_status"], "unconfirmed")
        self.judge.assert_called_once()
        self.save.assert_called_once()
        self.load.assert_not_called()

    def test_OBD16_real_judge_load_failure_preserves_report_and_ids(self):
        self.load.side_effect = OSError("restricted synthetic read error")
        response = self.receive()
        self.assertFalse(response["integration_success"])
        self.assertEqual(response["save_status"], "success")
        self.assertEqual(response["load_status"], "failed")
        self.assertEqual(response["failure"]["stage"], "load")
        self.assertEqual(response["execution_id"], self.execution["execution_id"])
        self.assertEqual(ReportStore.load(self.store, "ubuntu-a", response["scan_id"]),
                         response["report"])
        self.judge.assert_called_once()
        self.save.assert_called_once()
        self.load.assert_called_once()

    def test_OBD17_real_judge_load_mismatch_not_success(self):
        self.load.side_effect = lambda *args: {"tampered": True}
        response = self.receive()
        self.assertFalse(response["integration_success"])
        self.assertFalse(response["report_verified"])
        self.assertEqual(response["failure"]["stage"], "verify")
        self.assertEqual(response["save_status"], "success")

    def test_OBD18_target_mismatch_before_B(self):
        self.execution["target_id"] = "rocky-b"
        self.assert_stopped(self.receive(), "identity")


if __name__ == "__main__":
    unittest.main()
