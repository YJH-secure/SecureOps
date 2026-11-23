"""MOCK tests for the A SSH transport (no real ssh, no network)."""

import contextlib
import io
import json
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from integration import a_file01_cli as cli
from integration import a_ssh_transport as t

POLICY = "checks/system/policies/file_policy.ubuntu-24.04.json"
PREFLIGHT = {
    "d_source_sha": t.D_SOURCE_SHA,
    "c_source_sha": t.C_SOURCE_SHA,
    "d_source_verified": True,
    "c_files_verified": True,
    "vm_state_verified": True,
    "apt_state_verified": True,
}
META_KEYS = {"execution_succeeded", "timeout", "truncated", "exit_code",
             "stdout_bytes", "stderr_bytes", "limits", "preflight"}


class Recorder:
    """Popen stand-in that records calls and returns a prepared fake process."""

    def __init__(self, **spec):
        self.spec = spec
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return cli._FakeProc(**self.spec)


class RealChild:
    """Popen replacement that ignores the ssh argv and runs a local Python child."""

    def __init__(self, code):
        self.code = code
        self.calls = 0

    def __call__(self, argv, **kwargs):
        self.calls += 1
        return subprocess.Popen([sys.executable, "-c", self.code], **kwargs)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self.tmp.name) / "runs"
        self.runs.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_t(self, popen, **kw):
        args = dict(execution_id=str(uuid.uuid4()), target_id="ubuntu-a", ssh_alias="ubuntu-a",
                    remote_argv=t.fixed_remote_argv("ubuntu-a", POLICY), preflight=dict(PREFLIGHT),
                    popen=popen, record_dir=self.runs)
        args.update(kw)
        return args["execution_id"], t.run_file01(**args)

    def a_meta(self, execution_id):
        return json.loads((self.runs / execution_id / "a_meta.json").read_text(encoding="utf-8"))


class ShapeTests(Base):
    def test_ok_execution_shape_matches_d_contract(self):
        out = json.dumps(cli.MOCK_FILE01).encode() + b"\n"
        eid, ex = self.run_t(Recorder(stdout=out))
        self.assertEqual(set(ex), {"execution_id", "target_id", "operation", "stdout", "stderr", "metadata"})
        self.assertEqual((ex["execution_id"], ex["target_id"], ex["operation"]), (eid, "ubuntu-a", "file01_v12"))
        self.assertIs(type(ex["stdout"]), bytes)
        self.assertIs(type(ex["stderr"]), bytes)
        self.assertEqual(ex["stdout"], out)
        m = ex["metadata"]
        self.assertEqual(set(m), META_KEYS)
        self.assertIs(m["execution_succeeded"], True)
        self.assertIs(m["timeout"], False)
        self.assertIs(m["truncated"], False)
        self.assertIs(type(m["exit_code"]), int)
        self.assertEqual(m["exit_code"], 0)
        self.assertEqual((m["stdout_bytes"], m["stderr_bytes"]), (len(out), 0))
        self.assertEqual(m["preflight"], PREFLIGHT)
        self.assertEqual(self.a_meta(eid)["a_reason"], "ok")
        self.assertEqual((self.runs / eid / "stdout.bin").read_bytes(), out)

    def test_limits_are_exact_ints(self):
        _, ex = self.run_t(Recorder(stdout=b"{}"))
        limits = ex["metadata"]["limits"]
        self.assertEqual(limits, {"connect_timeout_seconds": 10, "total_timeout_seconds": 60,
                                  "stdout_max_bytes": 1048576, "stderr_max_bytes": 65536,
                                  "max_retries": 0})
        self.assertTrue(all(type(v) is int for v in limits.values()))

    def test_raw_bytes_not_decoded_or_stripped(self):
        raw = b"  \xff\xfe{\"a\":1}\r\n\n"
        _, ex = self.run_t(Recorder(stdout=raw, stderr=b"\x00w\n"))
        self.assertEqual(ex["stdout"], raw)
        self.assertEqual(ex["stderr"], b"\x00w\n")

    def test_stderr_noise_kept_for_d_stop(self):
        eid, ex = self.run_t(Recorder(stdout=b"{}", stderr=b"warning\n"))
        self.assertEqual(ex["stderr"], b"warning\n")
        self.assertEqual(ex["metadata"]["stderr_bytes"], 8)


class FailureMappingTests(Base):
    def test_timeout(self):
        clock = cli._FakeClock()
        eid, ex = self.run_t(Recorder(hang=True), clock=clock.now, sleep=clock.sleep)
        m = ex["metadata"]
        self.assertEqual((m["timeout"], m["truncated"], m["execution_succeeded"]), (True, False, False))
        self.assertIsNone(m["exit_code"])
        meta = self.a_meta(eid)
        self.assertEqual(meta["a_reason"], "timeout")
        self.assertTrue(meta["killed"])
        self.assertGreaterEqual(meta["elapsed_seconds"], 60)

    def test_stdout_over_limit(self):
        eid, ex = self.run_t(Recorder(stdout=b"x" * (t.LIMITS["stdout_max_bytes"] + 1)))
        m = ex["metadata"]
        self.assertEqual((m["truncated"], m["timeout"], m["execution_succeeded"]), (True, False, False))
        self.assertIsNone(m["exit_code"])
        self.assertEqual(m["stdout_bytes"], t.LIMITS["stdout_max_bytes"])
        self.assertEqual(self.a_meta(eid)["a_reason"], "stdout_over")

    def test_stderr_over_limit(self):
        eid, ex = self.run_t(Recorder(stdout=b"{}", stderr=b"e" * (t.LIMITS["stderr_max_bytes"] + 1)))
        self.assertIs(ex["metadata"]["truncated"], True)
        self.assertEqual(ex["metadata"]["stderr_bytes"], t.LIMITS["stderr_max_bytes"])
        self.assertEqual(self.a_meta(eid)["a_reason"], "stderr_over")

    def test_exit_255_classification_stays_in_a_meta(self):
        cases = {
            b"u@h: Permission denied (publickey).\r\n": "auth_failed",
            b"Host key verification failed.\r\n": "host_key_mismatch",
            b"ssh: connect to host h port 22: Connection timed out\r\n": "connect_failed",
            b"ssh: connect to host h port 22: Connection refused\r\n": "connect_failed",
            b"something else\n": "ssh_error_255",
        }
        for stderr, reason in cases.items():
            with self.subTest(reason=reason):
                eid, ex = self.run_t(Recorder(stderr=stderr, returncode=255))
                m = ex["metadata"]
                self.assertEqual((m["execution_succeeded"], m["exit_code"]), (False, 255))
                self.assertEqual(set(m), META_KEYS)
                self.assertEqual(self.a_meta(eid)["a_reason"], reason)

    def test_remote_nonzero(self):
        eid, ex = self.run_t(Recorder(stderr=b"Traceback\n", returncode=1))
        self.assertEqual((ex["metadata"]["execution_succeeded"], ex["metadata"]["exit_code"]), (False, 1))
        self.assertEqual(self.a_meta(eid)["a_reason"], "remote_nonzero")

    def test_spawn_failure_does_not_raise(self):
        def popen(argv, **kw):
            raise FileNotFoundError("ssh")
        eid, ex = self.run_t(popen)
        self.assertEqual((ex["metadata"]["execution_succeeded"], ex["metadata"]["exit_code"]), (False, None))
        self.assertEqual(self.a_meta(eid)["a_reason"], "spawn_failed")


class InputGateTests(Base):
    def assert_rejected(self, code, **kw):
        rec = Recorder(stdout=b"{}")
        with self.assertRaises(ValueError) as ctx:
            self.run_t(rec, **kw)
        self.assertEqual(str(ctx.exception), code)
        self.assertEqual(rec.calls, [], "nothing may start after an input error")

    def test_execution_id(self):
        self.assert_rejected("execution_id_not_uuid", execution_id="abc")
        self.assert_rejected("execution_id_not_canonical", execution_id=str(uuid.uuid4()).upper())
        self.assert_rejected("execution_id_must_be_str", execution_id=None)

    def test_target_alias_argv_policy(self):
        self.assert_rejected("target_not_allowed", target_id="rocky-b")
        self.assert_rejected("ssh_alias_not_allowed", ssh_alias="rocky-b")
        argv = t.fixed_remote_argv("ubuntu-a", POLICY)
        self.assert_rejected("remote_argv_not_allowed", remote_argv=argv + ["--extra"])
        self.assert_rejected("remote_argv_not_allowed", remote_argv=["/bin/sh", "-c", "id"])
        with self.assertRaises(ValueError):
            t.fixed_remote_argv("ubuntu-a", "../../etc/passwd")

    def test_preflight(self):
        for key in t.PREFLIGHT_FLAGS:
            for bad in (False, 1, "true", None):
                with self.subTest(key=key, value=bad):
                    pf = dict(PREFLIGHT, **{key: bad})
                    self.assert_rejected("preflight_flag_not_true:" + key, preflight=pf)
        self.assert_rejected("preflight_d_source_sha_mismatch", preflight=dict(PREFLIGHT, d_source_sha="0" * 40))
        self.assert_rejected("preflight_c_source_sha_mismatch", preflight=dict(PREFLIGHT, c_source_sha="0" * 40))
        self.assert_rejected("preflight_object_required", preflight=[])

    def test_duplicate_execution_id_refused(self):
        eid = str(uuid.uuid4())
        first = Recorder(stdout=b"{}")
        self.run_t(first, execution_id=eid)
        self.assertEqual(len(first.calls), 1)
        self.assert_rejected("duplicate_execution_id", execution_id=eid)


class CommandTests(unittest.TestCase):
    def test_fixed_remote_argv_matches_c_contract(self):
        self.assertEqual(t.fixed_remote_argv("ubuntu-a", POLICY), [
            "/usr/bin/python3", "-B", "-m", "checks.system.file_check",
            "--policy", POLICY, "--result-version", "1.2"])

    def test_remote_command_is_quoted_and_round_trips(self):
        workdir = t.TARGETS["ubuntu-a"]["workdir"]
        argv = t.fixed_remote_argv("ubuntu-a", POLICY)
        cmd = t.build_remote_command(workdir, argv)
        self.assertEqual(cmd, "cd -- /home/secureops-scan/secureops-c-verify/2fac2a02 && exec "
                              "/usr/bin/python3 -B -m checks.system.file_check --policy "
                              + POLICY + " --result-version 1.2")
        self.assertEqual(shlex.split(cmd), ["cd", "--", workdir, "&&", "exec"] + argv)

    def test_unsafe_tokens_rejected(self):
        for bad in ("a b", "$(id)", "`id`", "a;b", "a|b", "~/x", "*", "a'b", ""):
            with self.subTest(token=bad), self.assertRaises(ValueError):
                t.build_remote_command("/w", ["x", bad])
        with self.assertRaises(ValueError):
            t.build_remote_command("relative", ["x"])
        for alias in ("-oProxyCommand=x", "a b", ""):
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                t.build_ssh_argv(alias, "x")

    def test_ssh_options_and_single_attempt(self):
        rec2 = Recorder(stderr=b"x", returncode=255)
        t.run_file01(execution_id=str(uuid.uuid4()), target_id="ubuntu-a", ssh_alias="ubuntu-a",
                     remote_argv=t.fixed_remote_argv("ubuntu-a", POLICY), preflight=dict(PREFLIGHT),
                     popen=rec2)
        self.assertEqual(len(rec2.calls), 1, "no retry after failure")
        argv, kwargs = rec2.calls[0]
        for opt in ("BatchMode=yes", "ConnectTimeout=10", "ConnectionAttempts=1",
                    "StrictHostKeyChecking=yes", "RequestTTY=no", "ControlMaster=no", "ControlPath=none"):
            self.assertIn(opt, argv)
        self.assertEqual(argv[:2], ["ssh", "-T"])
        self.assertEqual(argv[-3:-1], ["--", "ubuntu-a"])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)


class RealProcessTests(Base):
    """Exercise real pipes, streaming limits and kill with a local child (no ssh)."""

    def test_real_ok(self):
        child = RealChild("import sys; sys.stdout.buffer.write(b'{\"check_id\": \"FILE-01\"}\\n')")
        eid, ex = self.run_t(child)
        self.assertEqual(ex["stdout"], b'{"check_id": "FILE-01"}\n')
        self.assertIs(ex["metadata"]["execution_succeeded"], True)
        self.assertEqual(child.calls, 1)

    def test_real_streaming_stdout_limit_kills_early(self):
        child = RealChild("import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)")
        start = time.monotonic()
        eid, ex = self.run_t(child)
        self.assertLess(time.monotonic() - start, 15)
        self.assertIs(ex["metadata"]["truncated"], True)
        self.assertEqual(ex["metadata"]["stdout_bytes"], t.LIMITS["stdout_max_bytes"])
        self.assertTrue(self.a_meta(eid)["killed"])

    def test_real_total_deadline_kills(self):
        child = RealChild("import time; time.sleep(30)")
        t0 = time.monotonic()
        fast = lambda: (time.monotonic() - t0) * 100  # 60 s budget passes in ~0.6 s
        start = time.monotonic()
        eid, ex = self.run_t(child, clock=fast)
        self.assertLess(time.monotonic() - start, 15)
        self.assertIs(ex["metadata"]["timeout"], True)
        self.assertIsNone(ex["metadata"]["exit_code"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pf = Path(self.tmp.name) / "preflight.json"
        self.pf.write_text(json.dumps(PREFLIGHT), encoding="utf-8")
        real_mkdtemp = cli.tempfile.mkdtemp
        self._orig = real_mkdtemp
        cli.tempfile.mkdtemp = lambda prefix="": real_mkdtemp(prefix=prefix, dir=self.tmp.name)

    def tearDown(self):
        cli.tempfile.mkdtemp = self._orig
        self.tmp.cleanup()

    def call(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--target", "ubuntu-a", "--policy", POLICY, "--preflight", str(self.pf), *extra])
        return code, out.getvalue(), err.getvalue()

    def test_real_mode_refused(self):
        code, out, err = self.call()
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("not approved", err)

    def test_policy_required_and_fixed(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["--target", "ubuntu-a", "--preflight", str(self.pf), "--mock", "ok"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--target", "ubuntu-a", "--policy", "x.json", "--preflight", str(self.pf), "--mock", "ok"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("policy_not_allowed", err.getvalue())

    def test_bad_preflight_file_refused(self):
        self.pf.write_text(json.dumps(dict(PREFLIGHT, vm_state_verified=False)), encoding="utf-8")
        code, out, err = self.call("--mock", "ok")
        self.assertEqual(code, cli.EXIT_USAGE)

    def test_mock_scenarios(self):
        expect = {"ok": 0, "stderr_noise": 0, "timeout": 1, "stdout_over": 1, "stderr_over": 1,
                  "auth_failed": 1, "host_key_mismatch": 1, "connect_failed": 1, "remote_nonzero": 1}
        for scenario, code_expected in expect.items():
            with self.subTest(scenario=scenario):
                code, out, err = self.call("--mock", scenario)
                self.assertEqual(code, code_expected)
                summary = json.loads(out)
                self.assertEqual(summary["mode"], "MOCK:" + scenario)
                self.assertIn("a-file01-mock-", summary["record_dir"])

    def test_deliver_to_d_without_adapter(self):
        try:
            import integration.cd_file01_adapter  # noqa: F401
        except ImportError:
            code, out, err = self.call("--mock", "ok", "--deliver-to-d")
            self.assertEqual(code, cli.EXIT_D_UNAVAILABLE)
            self.assertEqual(json.loads(out)["d_response"]["error"], "d_adapter_unavailable")
        else:
            self.skipTest("D adapter present; covered by A/D integration MOCK")


if __name__ == "__main__":
    unittest.main()
