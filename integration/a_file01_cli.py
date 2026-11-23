"""Central FILE-01 entry point (A owner, 2026-11-23).

    python3 -m integration.a_file01_cli --target ubuntu-a \
        --policy checks/system/policies/file_policy.ubuntu-24.04.json \
        --preflight <preflight.json> --mock ok

This version runs only with ``--mock``. Real SSH execution is refused
until a separate approval. MOCK records go to a fresh temporary
directory (never an operational runs/ path).

Flow: arguments -> preflight gate -> new execution_id -> transport ->
(optional) D adapter ``receive_file01_result`` -> summary JSON on stdout.
"""

import argparse
import hashlib
import io
import json
import sys
import tempfile
import uuid
from pathlib import Path

from integration import a_ssh_transport as transport

EXIT_OK = 0
EXIT_TRANSPORT_FAILED = 1
EXIT_USAGE = 2
EXIT_D_UNAVAILABLE = 3

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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="a_file01_cli")
    parser.add_argument("--target", required=True, choices=sorted(transport.TARGETS))
    parser.add_argument("--policy", required=True)
    parser.add_argument("--preflight", required=True, type=Path,
                        help="JSON file with the preflight attestation dict")
    parser.add_argument("--mock", choices=MOCK_SCENARIOS,
                        help="run against a fake ssh process (required in this version)")
    parser.add_argument("--deliver-to-d", action="store_true",
                        help="pass the execution to integration.cd_file01_adapter")
    args = parser.parse_args(argv)

    if args.mock is None:
        print("real SSH execution is not approved; use --mock", file=sys.stderr)
        return EXIT_USAGE
    try:
        remote_argv = transport.fixed_remote_argv(args.target, args.policy)
        raw = args.preflight.read_bytes()
        preflight = json.loads(raw.decode("utf-8"))
        transport.validate_preflight(preflight)
    except (OSError, ValueError) as exc:
        print("input rejected: {}".format(exc), file=sys.stderr)
        return EXIT_USAGE

    work = Path(tempfile.mkdtemp(prefix="a-file01-mock-"))
    runs = work / "runs"
    runs.mkdir()
    execution_id = str(uuid.uuid4())
    clock = _FakeClock() if args.mock == "timeout" else None
    kwargs = {"popen": _mock_popen(args.mock, clock)}
    if clock is not None:
        kwargs.update(clock=clock.now, sleep=clock.sleep)
    execution = transport.run_file01(
        execution_id=execution_id, target_id=args.target,
        ssh_alias=transport.TARGETS[args.target]["ssh_alias"],
        remote_argv=remote_argv, preflight=preflight, record_dir=runs, **kwargs)

    summary = {
        "mode": "MOCK:" + args.mock,
        "record_dir": str(runs / execution_id),
        "preflight_file_sha256": hashlib.sha256(raw).hexdigest(),
        "execution": _describe(execution),
    }
    code = EXIT_OK if execution["metadata"]["execution_succeeded"] else EXIT_TRANSPORT_FAILED
    if args.deliver_to_d:
        try:
            from integration.cd_file01_adapter import receive_file01_result
            from core.storage import ReportStore
        except ImportError as exc:
            summary["d_response"] = {"error": "d_adapter_unavailable", "detail": str(exc)}
            code = EXIT_D_UNAVAILABLE
        else:
            store = ReportStore(work / "store")
            summary["d_response"] = receive_file01_result(
                execution, approved_target_id=args.target, store=store)
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    return code


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


def _mock_popen(scenario, clock):
    ok = (json.dumps(MOCK_FILE01, ensure_ascii=False) + "\n").encode("utf-8")
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
