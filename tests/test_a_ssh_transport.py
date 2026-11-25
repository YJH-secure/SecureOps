"""MOCK tests for the A SSH transport (no real ssh, no network)."""

import contextlib
import hashlib
import io
import json
import os
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

    def test_read_error_is_not_normal_eof(self):
        class Broken(io.BytesIO):
            def read1(self, n=-1):
                raise OSError("EIO")

        class Proc(cli._FakeProc):
            def __init__(self):
                super().__init__(stdout=b"", returncode=0)
                self.stdout = Broken()

        eid, ex = self.run_t(lambda argv, **kw: Proc())
        m = ex["metadata"]
        self.assertEqual((m["execution_succeeded"], m["exit_code"], m["timeout"], m["truncated"]),
                         (False, None, False, False))
        meta = self.a_meta(eid)
        self.assertEqual(meta["a_reason"], "stdout_read_error")
        self.assertTrue(meta["killed"])

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

    def test_bad_types_raise_value_error_not_type_error(self):
        # AD26: unhashable target_id must stay inside the ValueError contract.
        for bad in ([], {}, set(), None, 1, b"ubuntu-a", ["ubuntu-a"]):
            with self.subTest(target_id=bad):
                self.assert_rejected("target_not_allowed", target_id=bad)
                with self.assertRaises(ValueError):
                    t.fixed_remote_argv(bad, POLICY)
        for bad in (None, 1, "x", {}, b"x"):
            with self.subTest(remote_argv=bad):
                self.assert_rejected("remote_argv_not_allowed", remote_argv=bad)
                with self.assertRaises(ValueError):
                    t.build_remote_command("/w", bad)
        for bad in ([], {}, None, 1):
            with self.subTest(ssh_alias=bad):
                self.assert_rejected("ssh_alias_not_allowed", ssh_alias=bad)

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

    def test_mock_stdout_file_passed_through_raw(self):
        sample = Path(self.tmp.name) / "c-sample.json"
        sample.write_bytes(b'{"check_id": "FILE-01", "cvss": {}}\r\n')
        code, out, err = self.call("--mock", "ok", "--mock-stdout", str(sample))
        summary = json.loads(out)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(summary["mock_stdout"]["source"], "file")
        self.assertEqual(summary["execution"]["stdout"]["bytes"], len(sample.read_bytes()))

    def fake_adapter(self, response):
        import types
        mod = types.ModuleType("integration.cd_file01_adapter")
        seen = []

        def receive_file01_result(execution, *, approved_target_id, store):
            seen.append((execution, approved_target_id, store))
            return response
        mod.receive_file01_result = receive_file01_result
        sys.modules["integration.cd_file01_adapter"] = mod
        self.addCleanup(sys.modules.pop, "integration.cd_file01_adapter", None)
        return seen

    def test_d_failure_is_not_integration_success(self):
        for response in ({"integration_success": False, "error_stage": "parse", "error_code": "parse_failed"},
                         {"integration_success": None}, {}, None):
            with self.subTest(response=response):
                seen = self.fake_adapter(response)
                code, out, err = self.call("--mock", "ok", "--deliver-to-d")
                self.assertEqual(code, cli.EXIT_D_FAILED)
                self.assertIn("STOP", err)
                summary = json.loads(out)
                self.assertIs(summary["integration_success"], False)
                self.assertEqual(summary["cli_exit"], cli.EXIT_D_FAILED)
                self.assertEqual(seen[0][1], "ubuntu-a")
                self.assertIs(type(seen[0][0]["stdout"]), bytes)

    def test_d_success_exit_zero(self):
        self.fake_adapter({"integration_success": True})
        code, out, err = self.call("--mock", "ok", "--deliver-to-d")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIs(json.loads(out)["integration_success"], True)

    def test_transport_failure_with_d_still_not_success(self):
        self.fake_adapter({"integration_success": False, "error_stage": "execution"})
        code, out, err = self.call("--mock", "timeout", "--deliver-to-d")
        self.assertNotEqual(code, cli.EXIT_OK)

    def test_deliver_to_d_without_adapter(self):
        try:
            import integration.cd_file01_adapter  # noqa: F401
        except ImportError:
            code, out, err = self.call("--mock", "ok", "--deliver-to-d")
            self.assertEqual(code, cli.EXIT_D_UNAVAILABLE)
            self.assertEqual(json.loads(out)["d_response"]["error"], "d_adapter_unavailable")
        else:
            self.skipTest("D adapter present; covered by A/D integration MOCK")


class _Stat:
    def __init__(self, mode, uid=1000):
        self.st_mode = mode
        self.st_uid = uid


DIR_0700 = _Stat(0o040700)


class RealCliTests(unittest.TestCase):
    """--real gates and flow. ssh is a recorded fake; POSIX/stat are patched."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.pf = base / "preflight.json"
        self.pf.write_text(json.dumps(PREFLIGHT), encoding="utf-8")
        self.runs = base / "runs"
        self.store = base / "reports"
        self.runs.mkdir()
        self.store.mkdir()
        self.overrides = {}
        self.popen = Recorder(stdout=b'{"check_id": "FILE-01"}\n')
        self._saved = (cli._is_posix, cli._euid, cli._lstat, cli._real_popen)
        cli._is_posix = lambda: True
        cli._euid = lambda: 1000
        cli._lstat = self.fake_lstat
        cli._real_popen = self.popen

    def tearDown(self):
        cli._is_posix, cli._euid, cli._lstat, cli._real_popen = self._saved
        sys.modules.pop("integration.cd_file01_adapter", None)
        self.tmp.cleanup()

    def fake_lstat(self, path):
        value = self.overrides.get(Path(path))
        if isinstance(value, BaseException):
            raise value
        if value is None and not os.path.lexists(path):
            raise FileNotFoundError(path)
        return value or DIR_0700

    def adapter(self, response):
        import types
        mod = types.ModuleType("integration.cd_file01_adapter")
        seen = []

        def receive_file01_result(execution, *, approved_target_id, store):
            seen.append((execution, approved_target_id, store))
            return response
        mod.receive_file01_result = receive_file01_result
        sys.modules["integration.cd_file01_adapter"] = mod
        return seen

    def call(self, *extra, dirs=True):
        args = ["--target", "ubuntu-a", "--policy", POLICY, "--preflight", str(self.pf), "--real"]
        if dirs:
            args += ["--record-dir", str(self.runs), "--store-dir", str(self.store)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(args + list(extra))
        return code, out.getvalue(), err.getvalue()

    def assert_refused(self, code_expected, fragment, *extra, dirs=True):
        code, out, err = self.call(*extra, dirs=dirs)
        self.assertEqual(code, code_expected)
        self.assertIn(fragment, err)
        self.assertEqual(self.popen.calls, [], "ssh must not start when a gate fails")
        self.assertEqual(list(self.runs.iterdir()), [])
        return err

    def test_real_and_mock_are_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["--target", "ubuntu-a", "--policy", POLICY, "--preflight", str(self.pf),
                      "--real", "--mock", "ok"])

    def test_real_requires_both_dirs(self):
        self.adapter({"integration_success": True})
        self.assert_refused(cli.EXIT_USAGE, "real_requires_record_and_store_dir", dirs=False)
        self.assert_refused(cli.EXIT_USAGE, "real_requires_record_and_store_dir",
                            "--record-dir", str(self.runs), dirs=False)

    def test_real_refused_on_non_posix(self):
        self.adapter({"integration_success": True})
        cli._is_posix = lambda: False
        self.assert_refused(cli.EXIT_USAGE, "real_requires_posix")

    def test_mock_only_and_real_only_options(self):
        sample = Path(self.tmp.name) / "s.json"
        sample.write_bytes(b"{}")
        self.assert_refused(cli.EXIT_USAGE, "mock_stdout_not_allowed_in_real",
                            "--mock-stdout", str(sample))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--target", "ubuntu-a", "--policy", POLICY, "--preflight", str(self.pf),
                             "--mock", "ok", "--record-dir", str(self.runs)])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("record_or_store_dir_only_in_real", err.getvalue())

    def test_bad_preflight_refused_before_dir_gate(self):
        self.pf.write_text(json.dumps(dict(PREFLIGHT, apt_state_verified="true")), encoding="utf-8")
        self.assert_refused(cli.EXIT_USAGE, "preflight_flag_not_true:apt_state_verified")

    def test_dir_gate_codes(self):
        self.adapter({"integration_success": True})
        cases = {
            "dir_missing": FileNotFoundError(),
            "dir_symlink_in_path": _Stat(0o120777),
            "dir_not_directory": _Stat(0o100700),
            "dir_mode_not_0700": _Stat(0o040755),
            "dir_owner_mismatch": _Stat(0o040700, uid=0),
        }
        for fragment, value in cases.items():
            for which in (self.store, self.runs):
                with self.subTest(case=fragment, dir=which.name):
                    self.overrides = {which: value}
                    self.assert_refused(cli.EXIT_USAGE, fragment)
        self.overrides = {}

    def test_symlink_in_parent_refused(self):
        self.adapter({"integration_success": True})
        self.overrides = {self.store.parent: _Stat(0o120777)}
        self.assert_refused(cli.EXIT_USAGE, "dir_symlink_in_path")

    def test_relative_or_same_dir_refused(self):
        self.adapter({"integration_success": True})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--target", "ubuntu-a", "--policy", POLICY, "--preflight", str(self.pf),
                             "--real", "--record-dir", "runs", "--store-dir", str(self.store)])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("dir_must_be_absolute", err.getvalue())
        self.assertEqual(self.popen.calls, [])
        self.store = self.runs
        self.assert_refused(cli.EXIT_USAGE, "record_and_store_dir_must_differ")

    def test_missing_store_dir_is_not_created(self):
        self.adapter({"integration_success": True})
        missing = Path(self.tmp.name) / "not-approved"
        self.store = missing
        self.assert_refused(cli.EXIT_USAGE, "dir_missing")
        self.assertFalse(missing.exists())

    def test_real_without_d_adapter_stops_before_ssh(self):
        sys.modules["integration.cd_file01_adapter"] = None  # forces ImportError
        self.assert_refused(cli.EXIT_D_UNAVAILABLE, "d_adapter_unavailable")

    def test_real_success_one_ssh_call_and_link_record(self):
        response = {"execution_id": None, "target_id": "ubuntu-a", "scan_id": "scan-1",
                    "scanned_at": "2026-11-25T00:00:00Z", "diagnosis_status": "needs_review",
                    "save_status": "success", "load_status": "success", "report_verified": True,
                    "saved_path": "/x/abc.json", "integration_success": True,
                    "error_stage": None, "error_code": None, "report": {"secret": 1}, "summary": {}}
        seen = self.adapter(response)
        code, out, err = self.call()
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertEqual(len(self.popen.calls), 1)
        argv, kwargs = self.popen.calls[0]
        self.assertEqual(argv[0], "ssh")
        self.assertEqual(argv[-2:], ["ubuntu-a", t.build_remote_command(
            t.TARGETS["ubuntu-a"]["workdir"], t.fixed_remote_argv("ubuntu-a", POLICY))])
        summary = json.loads(out)
        self.assertEqual(summary["mode"], "REAL")
        self.assertIsNone(summary["mock_stdout"])
        self.assertIs(summary["integration_success"], True)
        execution, target, store = seen[0]
        self.assertEqual(target, "ubuntu-a")
        from core.storage import ReportStore
        self.assertIsInstance(store, ReportStore)
        self.assertEqual(store.root, self.store.absolute())
        run_dir = self.runs / execution["execution_id"]
        self.assertEqual(summary["record_dir"], str(run_dir))
        self.assertEqual(sorted(p.name for p in run_dir.iterdir()),
                         ["a_meta.json", "d_response.json", "stderr.bin", "stdout.bin"])
        link = json.loads((run_dir / "d_response.json").read_text(encoding="utf-8"))
        self.assertEqual(set(link), set(cli.D_LINK_KEYS) | {
            "record_execution_id", "d_response_type", "mode", "preflight_file", "preflight_file_sha256"})
        self.assertNotIn("report", link)
        self.assertEqual(link["scan_id"], "scan-1")
        self.assertEqual(link["record_execution_id"], execution["execution_id"])
        self.assertEqual(link["preflight_file_sha256"],
                         hashlib.sha256(self.pf.read_bytes()).hexdigest())

    def test_real_d_failure_is_stop_and_still_linked(self):
        for response in ({"integration_success": False, "error_stage": "transport",
                          "error_code": "nonempty_stderr"}, None):
            with self.subTest(response=response):
                self.popen.calls.clear()
                self.adapter(response)
                code, out, err = self.call()
                self.assertEqual(code, cli.EXIT_D_FAILED)
                self.assertIn("STOP", err)
                rid = json.loads(out)["execution"]["execution_id"]
                link = json.loads((self.runs / rid / "d_response.json").read_text(encoding="utf-8"))
                self.assertIs(link["integration_success"], response and response["integration_success"])
                self.assertEqual(link["d_response_type"], type(response).__name__)

    def test_real_transport_failure_goes_to_d_once_no_retry(self):
        self.popen = Recorder(stderr=b"Permission denied (publickey).\r\n", returncode=255)
        cli._real_popen = self.popen
        seen = self.adapter({"integration_success": False, "error_stage": "transport",
                             "error_code": "execution_failed"})
        code, out, err = self.call()
        self.assertEqual(code, cli.EXIT_D_FAILED)
        self.assertEqual(len(self.popen.calls), 1)
        self.assertEqual(seen[0][0]["metadata"]["exit_code"], 255)

    def test_link_write_failure_is_stop(self):
        self.adapter({"integration_success": True})
        saved = cli._write_d_link

        def boom(*a, **k):
            raise PermissionError("no")
        cli._write_d_link = boom
        try:
            code, out, err = self.call()
        finally:
            cli._write_d_link = saved
        self.assertEqual(code, cli.EXIT_RECORD_FAILED)
        self.assertIn("d_response.json could not be written", err)
        self.assertEqual(json.loads(out)["d_link_record_error"], "PermissionError")


class MockLinkTests(unittest.TestCase):
    setUp = CliTests.setUp
    tearDown = CliTests.tearDown
    call = CliTests.call
    fake_adapter = CliTests.fake_adapter

    def test_mock_deliver_writes_link_in_temp_only(self):
        self.fake_adapter({"integration_success": True, "scan_id": "s"})
        code, out, err = self.call("--mock", "ok", "--deliver-to-d")
        self.assertEqual(code, cli.EXIT_OK)
        run_dir = Path(json.loads(out)["record_dir"])
        self.assertIn("a-file01-mock-", str(run_dir))
        link = json.loads((run_dir / "d_response.json").read_text(encoding="utf-8"))
        self.assertEqual(link["mode"], "MOCK:ok")


if __name__ == "__main__":
    unittest.main()
