"""Central FILE-01 entry point (A owner, 2026-11-23; --real 2026-11-25).

    MOCK (isolated, fake ssh process):
    python3 -m integration.a_file01_cli --target ubuntu-a \
        --policy checks/system/policies/file_policy.ubuntu-24.04.json \
        --preflight <preflight.json> --mock ok [--deliver-to-d]

    REAL (only inside an approved run; one ssh call, no retry):
    /usr/bin/python3 -B -m integration.a_file01_cli --target ubuntu-a \
        --policy checks/system/policies/file_policy.ubuntu-24.04.json \
        --preflight <preflight.json> --real \
        --record-dir <approved runs dir> --store-dir <approved reports dir>

Exactly one of ``--mock`` / ``--real`` is required. MOCK records go to a
fresh temporary directory (never an operational runs/ path).

``--real`` gates, all checked before anything is started (no ssh, no D
import side effects, no directory is ever created):
  * POSIX host only;
  * ``--record-dir`` and ``--store-dir`` are required, distinct, absolute,
    already existing real directories (no symlink anywhere in the path),
    mode 0700 and owned by the effective user. ``ReportStore.__init__``
    would otherwise ``mkdir`` the store path, so it is only constructed
    after this check passes;
  * the D adapter and ``ReportStore`` must import; delivery to D is always on.

Flow: arguments -> preflight gate -> (real: dir/D gates) -> new execution_id
-> transport -> (optional in MOCK, always in REAL) D adapter
``receive_file01_result`` -> ``d_response.json`` link record next to the
transport record -> summary JSON on stdout.
"""

import argparse
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from integration import a_ssh_transport as transport

EXIT_OK = 0
EXIT_TRANSPORT_FAILED = 1
EXIT_USAGE = 2
EXIT_D_UNAVAILABLE = 3
EXIT_D_FAILED = 4
EXIT_RECORD_FAILED = 5

# Keys copied from the D response into d_response.json (the report body is
# stored only by ReportStore and never duplicated here).
D_LINK_KEYS = ("execution_id", "target_id", "scan_id", "scanned_at", "diagnosis_status",
               "save_status", "load_status", "report_verified", "saved_path",
               "integration_success", "error_stage", "error_code")

# Indirections so tests can exercise the REAL gates on any host.
_real_popen = subprocess.Popen
_lstat = os.lstat


def _is_posix():
    return os.name == "posix"


def _euid():
    return os.geteuid()

# Transport-only placeholder (no cvss / details.environment): D v1.2 receive
# rejects it with parse_failed by design. For A/D connection MOCK pass a
# C-provided v1.2 FILE-01 sample with --mock-stdout instead.
MOCK_FILE01 = {
    "check_id": "FILE-01",
    "status": "needs_review",
    "severity": "high",
    "evidence": "MOCK: A transport isolated test output",
    "recommendation": "MOCK: not a real diagnosis",
    "details": {"files": [{"path": "/etc/passwd", "mode": "0644"},
                          {"path": "/etc/shadow", "mode": "0640"}]},
}
MOCK_SCENARIOS = ("ok", "timeout", "stdout_over", "stderr_over", "stderr_noise",
                  "auth_failed", "host_key_mismatch", "connect_failed", "remote_nonzero")


def check_private_dir(path):
    """Return the path if it is an existing 0700 dir owned by us; never creates it."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("dir_must_be_absolute")
    if len(path.parts) < 2:
        raise ValueError("dir_must_not_be_root")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            st = _lstat(current)
        except FileNotFoundError:
            raise ValueError("dir_missing") from None
        except OSError:
            raise ValueError("dir_unreadable") from None
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("dir_symlink_in_path")
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError("dir_not_directory")
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError("dir_mode_not_0700")
    if st.st_uid != _euid():
        raise ValueError("dir_owner_mismatch")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(prog="a_file01_cli")
    parser.add_argument("--target", required=True, choices=sorted(transport.TARGETS))
    parser.add_argument("--policy", required=True)
    parser.add_argument("--preflight", required=True, type=Path,
                        help="JSON file with the preflight attestation dict")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--mock", choices=MOCK_SCENARIOS,
                      help="run against a fake ssh process")
    mode.add_argument("--real", action="store_true",
                      help="one real ssh run (approved runs only); implies delivery to D")
    parser.add_argument("--mock-stdout", type=Path,
                        help="raw bytes used as remote stdout in MOCK (e.g. C v1.2 FILE-01 sample)")
    parser.add_argument("--deliver-to-d", action="store_true",
                        help="pass the execution to integration.cd_file01_adapter")
    parser.add_argument("--record-dir", type=Path, help="REAL: approved existing runs/ dir (0700)")
    parser.add_argument("--store-dir", type=Path, help="REAL: approved existing reports/ dir (0700)")
    args = parser.parse_args(argv)

    if args.mock is None and not args.real:
        print("real SSH execution is not approved without --real; use --mock or --real",
              file=sys.stderr)
        return EXIT_USAGE
    if args.real and args.mock_stdout is not None:
        print("input rejected: mock_stdout_not_allowed_in_real", file=sys.stderr)
        return EXIT_USAGE
    if args.mock is not None and (args.record_dir is not None or args.store_dir is not None):
        print("input rejected: record_or_store_dir_only_in_real", file=sys.stderr)
        return EXIT_USAGE
    try:
        remote_argv = transport.fixed_remote_argv(args.target, args.policy)
        raw = args.preflight.read_bytes()
        preflight = json.loads(raw.decode("utf-8"))
        transport.validate_preflight(preflight)
        mock_stdout = args.mock_stdout.read_bytes() if args.mock_stdout else None
    except (OSError, ValueError) as exc:
        print("input rejected: {}".format(exc), file=sys.stderr)
        return EXIT_USAGE

    receive = store = None
    if args.real:
        try:
            if not _is_posix():
                raise ValueError("real_requires_posix")
            if args.record_dir is None or args.store_dir is None:
                raise ValueError("real_requires_record_and_store_dir")
            runs = check_private_dir(args.record_dir)
            store_dir = check_private_dir(args.store_dir)
            if runs == store_dir:
                raise ValueError("record_and_store_dir_must_differ")
        except (OSError, ValueError) as exc:
            print("input rejected: {}".format(exc), file=sys.stderr)
            return EXIT_USAGE
        try:
            from integration.cd_file01_adapter import receive_file01_result as receive
            from core.storage import ReportStore
        except ImportError as exc:
            print("STOP: d_adapter_unavailable: {}".format(exc), file=sys.stderr)
            return EXIT_D_UNAVAILABLE
        try:
            # Safe: the dir already exists, so its mkdir(exist_ok=True) is a no-op.
            store = ReportStore(store_dir)
        except (OSError, ValueError) as exc:
            print("input rejected: store_dir_rejected: {}".format(type(exc).__name__),
                  file=sys.stderr)
            return EXIT_USAGE
        kwargs = {"popen": _real_popen}
        mode_label = "REAL"
    else:
        work = Path(tempfile.mkdtemp(prefix="a-file01-mock-"))
        runs = work / "runs"
        runs.mkdir()
        clock = _FakeClock() if args.mock == "timeout" else None
        kwargs = {"popen": _mock_popen(args.mock, clock, mock_stdout)}
        if clock is not None:
            kwargs.update(clock=clock.now, sleep=clock.sleep)
        mode_label = "MOCK:" + args.mock

    execution_id = str(uuid.uuid4())
    execution = transport.run_file01(
        execution_id=execution_id, target_id=args.target,
        ssh_alias=transport.TARGETS[args.target]["ssh_alias"],
        remote_argv=remote_argv, preflight=preflight, record_dir=runs, **kwargs)
    run_dir = runs / execution_id

    summary = {
        "mode": mode_label,
        "mock_stdout": (None if args.real else
                        {"source": "file", "sha256": hashlib.sha256(mock_stdout).hexdigest()}
                        if mock_stdout is not None else {"source": "builtin_transport_only"}),
        "record_dir": str(run_dir),
        "preflight_file": os.path.abspath(args.preflight),
        "preflight_file_sha256": hashlib.sha256(raw).hexdigest(),
        "execution": _describe(execution),
    }
    code = EXIT_OK if execution["metadata"]["execution_succeeded"] else EXIT_TRANSPORT_FAILED
    deliver = args.real or args.deliver_to_d
    if deliver and not args.real:
        try:
            from integration.cd_file01_adapter import receive_file01_result as receive
            from core.storage import ReportStore
        except ImportError as exc:
            summary["d_response"] = {"error": "d_adapter_unavailable", "detail": str(exc)}
            code = EXIT_D_UNAVAILABLE
        else:
            store = ReportStore(work / "store")
    if receive is not None:
        response = receive(execution, approved_target_id=args.target, store=store)
        summary["d_response"] = response
        # Transport success is not integration success: anything short of an
        # explicit D integration_success=True (parse/save/load) is a STOP.
        if not (isinstance(response, dict) and response.get("integration_success") is True):
            code = EXIT_D_FAILED
        try:
            _write_d_link(run_dir, execution_id, response, summary)
        except OSError as exc:
            summary["d_link_record_error"] = type(exc).__name__
            code = EXIT_RECORD_FAILED
    summary["integration_success"] = (summary.get("d_response") or {}).get("integration_success") is True \
        if deliver else None
    summary["cli_exit"] = code
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    if code == EXIT_D_FAILED:
        print("STOP: D integration not successful", file=sys.stderr)
    elif code == EXIT_RECORD_FAILED:
        print("STOP: d_response.json could not be written; D result is in stdout only",
              file=sys.stderr)
    return code


def _write_d_link(run_dir, execution_id, response, summary):
    """Persist the execution_id -> scan_id link next to the transport record (create-only)."""
    src = response if isinstance(response, dict) else {}
    link = {key: src.get(key) for key in D_LINK_KEYS}
    link.update({
        "record_execution_id": execution_id,
        "d_response_type": type(response).__name__,
        "mode": summary["mode"],
        "preflight_file": summary["preflight_file"],
        "preflight_file_sha256": summary["preflight_file_sha256"],
    })
    with open(run_dir / "d_response.json", "x", encoding="utf-8") as stream:
        stream.write(json.dumps(link, ensure_ascii=False, indent=2, default=str) + "\n")


def _describe(execution):
    out = {k: v for k, v in execution.items() if k not in ("stdout", "stderr")}
    for name in ("stdout", "stderr"):
        data = execution[name]
        out[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                     "head": data[:120].decode("utf-8", "replace")}
    return out


class _FakeClock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


class _FakeProc:
    """Minimal Popen stand-in: finished streams + exit code, or never-ending."""

    def __init__(self, stdout=b"", stderr=b"", returncode=0, hang=False):
        self.pid = 0
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self._rc = returncode
        self._hang = hang
        self.killed = False

    def poll(self):
        if self._hang and not self.killed:
            return None
        return -9 if self.killed else self._rc

    def wait(self, timeout=None):
        return self.poll()

    def kill(self):
        self.killed = True


def _mock_popen(scenario, clock, mock_stdout=None):
    ok = mock_stdout if mock_stdout is not None else \
        (json.dumps(MOCK_FILE01, ensure_ascii=False) + "\n").encode("utf-8")
    table = {
        "ok": dict(stdout=ok),
        "timeout": dict(hang=True),
        "stdout_over": dict(stdout=b"x" * (transport.LIMITS["stdout_max_bytes"] + 1)),
        "stderr_over": dict(stdout=ok, stderr=b"e" * (transport.LIMITS["stderr_max_bytes"] + 1)),
        "stderr_noise": dict(stdout=ok, stderr=b"warning\n"),
        "auth_failed": dict(stderr=b"user@ubuntu-a: Permission denied (publickey).\r\n", returncode=255),
        "host_key_mismatch": dict(stderr=b"Host key verification failed.\r\n", returncode=255),
        "connect_failed": dict(stderr=b"ssh: connect to host ubuntu-a port 22: Connection timed out\r\n",
                               returncode=255),
        "remote_nonzero": dict(stderr=b"Traceback (most recent call last):\n", returncode=1),
    }
    spec = table[scenario]

    def popen(argv, **kwargs):
        return _FakeProc(**spec)
    return popen


if __name__ == "__main__":
    sys.exit(main())
