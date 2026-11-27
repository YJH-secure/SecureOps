"""New wrapper tests, separate from the accepted 21-case harness.

Use run_tests.py to supply the frozen external dependencies. This directory is
an explicit offline test job, not an implicit main-discovery dependency.
"""
from copy import deepcopy
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from core.storage import ReportStore
from integration import a_ssh_transport as transport
from integration import a_file01_cli as a_cli
import collector_entry as entry
import b_collector
import test_b_collector as fixture
from orchestration import abd_diagnosis as wrapper


OBSERVATIONS = []


class ABDOperatingWrapperTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen", "subprocess.run"):
            guard = patch(target, side_effect=AssertionError("no external execution"))
            guard.start()
            self.addCleanup(guard.stop)
        guard = patch("os.killpg", side_effect=AssertionError("no real killpg"), create=True)
        guard.start()
        self.addCleanup(guard.stop)
        self.tmp = tempfile.TemporaryDirectory(prefix="secureops-abd-wrapper-")
        self.addCleanup(self.tmp.cleanup)
        self.store = ReportStore(Path(self.tmp.name) / "reports")
        self.save, self.load = Mock(wraps=self.store.save), Mock(wraps=self.store.load)
        self.store.save, self.store.load = self.save, self.load
        self.context = transport.b_read_trusted_context("ubuntu-a")
        self.profile = wrapper.ApprovedProfile("ubuntu-a", self.context["host"], self.context["addr"],
            self.context["os_id"], self.context["os_version"], "ubuntu-24.04")
        self.judge = Mock(wraps=entry.judge_collector_output)
        self.receiver = Mock(wraps=wrapper.receive_b_collector_result)
        self.gate = Mock(wraps=transport.b_read_stop_reason)
        for name, value in (("judge_collector_output", self.judge),
                            ("receive_b_collector_result", self.receiver),
                            ("b_read_stop_reason", self.gate)):
            guard = patch.object(wrapper, name, value)
            guard.start()
            self.addCleanup(guard.stop)
        ctx = {"host": self.context["host"], "addr": self.context["addr"]}
        commands = {(fixture.SSHD, "-T", "-C", fixture.spec(user, ctx)): fixture.GOOD_SSHD
                    for user in fixture.SSH_USERS}
        out = io.StringIO()
        with patch.object(fixture, "CONTEXT", ctx), \
             patch.object(fixture, "CONFIG_TEXT", json.dumps(ctx)), fixture.target(commands=commands):
            self.assertEqual(b_collector.main([], out=out), 0)
        self.raw = out.getvalue().encode("utf-8")

    def execution(self, raw=None, *, stderr=b"", returncode=0, hang=False):
        raw = self.raw if raw is None else raw
        popen = Mock(side_effect=lambda *args, **kw:
                     a_cli._FakeProc(stdout=raw, stderr=stderr, returncode=returncode, hang=hang))
        kw = {}
        if hang:
            clock = a_cli._FakeClock()
            kw = {"clock": clock.now, "sleep": clock.sleep}
        result = transport.run_b_read(execution_id=str(uuid4()), target_id="ubuntu-a", ssh_alias="ubuntu-a",
            remote_argv=list(transport.B_READ_REMOTE_ARGV),
            preflight={"b_source_sha": transport.B_SOURCE_SHA,
                       **{key: True for key in transport.B_PREFLIGHT_FLAGS}},
            popen=popen, **kw)
        self.assertEqual(popen.call_count, 1)
        return result

    def changed(self, mutate):
        document = json.loads(self.raw)
        mutate(document)
        return (json.dumps(document) + "\n").encode("utf-8")

    def call(self, execution, profile=None):
        result = wrapper.diagnose_abd_execution(execution, profile=profile or self.profile,
                                                store=self.store, evidence_ref="wrapper-MOCK")
        recorded = deepcopy(result)
        if recorded["D_response"] and recorded["D_response"]["saved_path"]:
            recorded["D_response"]["saved_path"] = "<TEMP_REPORTSTORE>/" + Path(recorded["D_response"]["saved_path"]).name
        OBSERVATIONS.append({"test": self.id(), "response": recorded})
        return result

    def assert_roundtrip(self, result):
        self.assertTrue(result["integration_success"])
        self.assertIsNone(result["failure"])
        report = result["D_response"]["report"]
        self.assertEqual(ReportStore.load(self.store, "ubuntu-a", report["scan_id"]), report)
        self.assertEqual({r["check_id"] for r in report["results"]}, {"SSH-02", "ACC-01", "ACC-02"})
        from jsonschema import Draft202012Validator, FormatChecker
        schema = json.loads((Path(__file__).parents[2] / "docs/architecture/json-result-schema-v1.2.schema.json").read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
        self.assertTrue(all("severity" not in r for r in report["results"]))
        self.save.assert_called_once()
        self.load.assert_called_once()

    def assert_A_stop(self, result):
        self.assertEqual(result["failure_layer"], "A")
        self.assertFalse(result["integration_success"])
        self.assertIsNone(result["D_response"])
        self.assertIsNone(result["scan_id"])
        self.receiver.assert_not_called()
        self.judge.assert_not_called()
        self.save.assert_not_called()
        self.load.assert_not_called()
        self.assertEqual(list(self.store.root.glob("*.json")), [])

    def test_W01_normal_v12_full_dict_roundtrip(self):
        execution = self.execution()
        result = self.call(execution)
        self.assert_roundtrip(result)
        self.assertIs(self.judge.call_args.args[0], execution["stdout"])
        self.assertEqual(self.judge.call_args.args[1], self.context)
        self.assertEqual(self.judge.call_args.kwargs, {"result_version": "1.2"})

    def test_W02_valid_error_result_is_preserved(self):
        raw = self.changed(lambda d: d["payloads"]["ACC-02"]["files"].update(
            {"/etc/pam.d/common-auth": {"state": "error"}}))
        expected = entry.judge_collector_output(raw, self.context)
        result = self.call(self.execution(raw))
        self.assert_roundtrip(result)
        self.assertEqual(result["D_response"]["report"]["results"], list(expected.values()))
        self.assertEqual(expected["ACC-02"]["status"], "error")

    def test_W03_needs_review_and_null_are_preserved(self):
        expected = entry.judge_collector_output(self.raw, self.context)
        result = self.call(self.execution())
        self.assert_roundtrip(result)
        self.assertEqual(result["D_response"]["report"]["results"], list(expected.values()))
        review = expected["ACC-01"]
        self.assertEqual(review["status"], "needs_review")
        self.assertTrue(all(review["cvss"][k] is None for k in ("version", "vector", "base_score", "rating")))

    def test_W04_vulnerable_pending_is_not_zero(self):
        raw = self.changed(lambda d: d["payloads"]["ACC-01"]["files"]["/etc/login.defs"].update(
            text="PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n"))
        result = self.call(self.execution(raw))
        self.assert_roundtrip(result)
        item = result["D_response"]["report"]["results"][1]
        self.assertEqual(item["status"], "vulnerable")
        self.assertEqual(item["cvss"]["assessment_status"], "pending")
        self.assertIsNone(item["cvss"]["base_score"])

    def test_W05_A_failure_reasons_block_B_and_D(self):
        for kwargs in ({"stderr": b"warning"}, {"returncode": 1}, {"returncode": 4}, {"returncode": 255}):
            with self.subTest(kwargs=kwargs):
                self.assert_A_stop(self.call(self.execution(**kwargs)))

    def test_W06_A_timeout_blocks_B_and_D(self):
        result = self.call(self.execution(hang=True))
        self.assert_A_stop(result)
        self.assertEqual(result["A_stop_reason"], "timeout")

    def test_W07_A_truncated_output_blocks_B_and_D(self):
        self.assert_A_stop(self.call(self.execution(b"x" * (transport.LIMITS["stdout_max_bytes"] + 1))))

    def test_W08_actual_B_trust_stage_reason_preserved(self):
        result = self.call(self.execution(self.raw.rstrip(b"\n") + b"\r\n"))
        self.assertEqual(result["failure_layer"], "B")
        self.assertEqual(result["failure"]["collector_trust"],
                         {"stage": "decode", "reason": "not_single_line_json"})
        self.judge.assert_called_once()
        self.assertFalse(result["integration_success"])
        self.assertIsNone(result["scan_id"])
        self.save.assert_not_called()
        self.load.assert_not_called()

    def test_W09_bad_JSON_and_UTF8_block_storage(self):
        for raw in (b"{broken", b"\xff", b'{"collector":{},"collector":{}}'):
            with self.subTest(raw=raw):
                result = self.call(self.execution(raw))
                self.assertEqual(result["failure_layer"], "D")
                self.assertFalse(result["integration_success"])
        self.judge.assert_not_called()
        self.save.assert_not_called()
        self.load.assert_not_called()

    def test_W10_observed_context_and_OS_mismatch_STOP(self):
        changes = [lambda d: d["context_used"].update(host="mismatch"),
                   lambda d: d["payloads"]["ACC-01"]["os_release"].update(text="ID=rocky\nVERSION_ID=9.8")]
        for mutate in changes:
            result = self.call(self.execution(self.changed(mutate)))
            self.assertEqual(result["failure_layer"], "D")
            self.assertFalse(result["integration_success"])
        self.judge.assert_not_called()
        self.save.assert_not_called()

    def test_W11_profile_must_match_A_fixed_approval_context(self):
        result = self.call(self.execution(), replace(self.profile, host="mismatch"))
        self.assertEqual(result["failure"]["stage"], "profile")
        self.receiver.assert_not_called()
        self.judge.assert_not_called()
        self.save.assert_not_called()

    def test_W12_save_failure_keeps_scan_and_not_success(self):
        self.save.side_effect = PermissionError("sensitive exception omitted")
        result = self.call(self.execution())
        self.assertFalse(result["integration_success"])
        self.assertEqual(result["D_response"]["save_status"], "unconfirmed")
        self.assertEqual(result["failure"]["stage"], "save")
        self.assertIsNotNone(result["id_link"]["scan_id"])
        self.load.assert_not_called()
        self.assertNotIn("sensitive exception", json.dumps(result))

    def test_W13_load_failure_keeps_saved_data_and_IDs(self):
        self.load.side_effect = OSError("sensitive read path omitted")
        execution = self.execution()
        result = self.call(execution)
        self.assertFalse(result["integration_success"])
        self.assertEqual(result["D_response"]["save_status"], "success")
        self.assertEqual(result["D_response"]["load_status"], "failed")
        self.assertEqual(result["id_link"]["execution_id"], execution["execution_id"])
        self.assertEqual(ReportStore.load(self.store, "ubuntu-a", result["scan_id"]), result["D_response"]["report"])
        self.save.assert_called_once()
        self.load.assert_called_once()

    def test_W14_load_mismatch_is_not_success(self):
        self.load.side_effect = lambda *a: {"changed": True}
        result = self.call(self.execution())
        self.assertFalse(result["integration_success"])
        self.assertEqual(result["failure"]["stage"], "verify")

    def test_W15_A_gate_then_single_D_and_B_delegation(self):
        order = []
        self.gate.side_effect = lambda ex: (order.append("A_gate"), transport.b_read_stop_reason(ex))[1]
        original_receiver = wrapper.receive_b_collector_result._mock_wraps
        self.receiver.side_effect = lambda *a, **kw: (order.append("D"), original_receiver(*a, **kw))[1]
        self.judge.side_effect = lambda *a, **kw: (order.append("B"), entry.judge_collector_output(*a, **kw))[1]
        self.assert_roundtrip(self.call(self.execution()))
        self.assertEqual(order, ["A_gate", "D", "B"])
        self.receiver.assert_called_once()
        self.judge.assert_called_once()

    def test_W16_IDs_are_extracted_not_created_by_wrapper(self):
        execution = self.execution()
        result = self.call(execution)
        self.assert_roundtrip(result)
        self.assertEqual(result["execution_id"], execution["execution_id"])
        self.assertEqual(result["id_link"]["scan_id"], result["D_response"]["report"]["scan_id"])
        self.assertNotEqual(result["execution_id"], result["scan_id"])

    def test_W17_no_transport_execution_or_metadata_writer(self):
        execution = self.execution()
        with patch.object(transport, "run_b_read", side_effect=AssertionError("receipt only")), \
             patch.object(Path, "write_text", side_effect=AssertionError("no metadata writer")) as text, \
             patch.object(Path, "write_bytes", side_effect=AssertionError("no metadata writer")) as binary:
            result = self.call(execution)
        self.assert_roundtrip(result)
        text.assert_not_called()
        binary.assert_not_called()
        self.assertEqual(len(list(self.store.root.glob("*.json"))), 1)

    def test_W18_fault_injected_v12_severity_is_rejected_not_removed(self):
        def invalid(*args, **kw):
            result = entry.judge_collector_output(*args, **kw)
            result["SSH-02"]["severity"] = "high"
            return result
        self.judge.side_effect = invalid
        result = self.call(self.execution())
        self.assertFalse(result["integration_success"])
        self.assertEqual(result["failure_layer"], "D")
        self.save.assert_not_called()

    def test_W19_fault_injected_missing_and_duplicate_result_rejected(self):
        for duplicate in (False, True):
            def invalid(*args, **kw):
                result = entry.judge_collector_output(*args, **kw)
                if duplicate:
                    result["ACC-02"] = deepcopy(result["SSH-02"])
                else:
                    result.pop("ACC-02")
                return result
            self.judge.side_effect = invalid
            result = self.call(self.execution())
            self.assertFalse(result["integration_success"])
            self.assertEqual(result["failure_layer"], "D")
        self.save.assert_not_called()
        self.load.assert_not_called()
