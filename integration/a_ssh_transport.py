"""A SSH transport for the central FILE-01 run (A owner, 2026-11-23).

Scope of this version: implementation + isolated MOCK tests only.
Real SSH execution and central deployment need a separate approval.

Output is the D ``execution`` dict agreed with D (cd_file01_adapter):
raw stdout/stderr bytes plus ``metadata`` with exact keys. A-only
details (failure reason, timing, ssh argv) go to ``a_meta.json``
under ``record_dir/<execution_id>/`` and are never passed to D.

Remote command contract (C, 2026-11-23): fixed cwd + fixed argv.
OpenSSH sends one command string to the remote login shell, so the
fixed cwd/argv are joined with ``shlex.quote`` into
``cd -- <cwd> && exec <argv...>``. Every token is a constant that is
checked against a strict character set, so the remote shell performs
no expansion, globbing or substitution on them. No caller-supplied
path, command or extra argument is accepted.
"""

import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

OPERATION = "file01_v12"

LIMITS = {
    "connect_timeout_seconds": 10,
    "total_timeout_seconds": 60,
    "stdout_max_bytes": 1048576,
    "stderr_max_bytes": 65536,
    "max_retries": 0,
}

D_SOURCE_SHA = "0cab3a247d2143fc5556e37f6651440e109eef70"
C_SOURCE_SHA = "2fac2a02edb1edf08cf4435138f4a1d543e33ba2"
PREFLIGHT_FLAGS = (
    "d_source_verified",
    "c_files_verified",
    "vm_state_verified",
    "apt_state_verified",
)

# C fixed CLI (서후, 2026-11-23). FILE-01 only; stdout is one JSON object.
TARGETS = {
    "ubuntu-a": {
        "ssh_alias": "ubuntu-a",
        "workdir": "/home/secureops-scan/secureops-c-verify/2fac2a02",
        "policy": "checks/system/policies/file_policy.ubuntu-24.04.json",
    },
}
_REMOTE_PREFIX = ("/usr/bin/python3", "-B", "-m", "checks.system.file_check", "--policy")
_REMOTE_SUFFIX = ("--result-version", "1.2")

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_./-]+$")
_SSH_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_POLL_SECONDS = 0.05
_KILL_WAIT_SECONDS = 5
_CHUNK = 65536


def fixed_remote_argv(target_id, policy):
    """Return the only remote argv allowed for ``target_id``/``policy``."""
    profile = _profile(target_id)
    if policy != profile["policy"]:
        raise ValueError("policy_not_allowed")
    return list(_REMOTE_PREFIX) + [policy] + list(_REMOTE_SUFFIX)


def build_remote_command(workdir, remote_argv):
    """Join fixed cwd/argv into the single string OpenSSH will send."""
    for token in [workdir] + list(remote_argv):
        if not isinstance(token, str) or not _SAFE_TOKEN.match(token):
            raise ValueError("unsafe_remote_token")
    if not workdir.startswith("/"):
        raise ValueError("workdir_must_be_absolute")
    argv = " ".join(shlex.quote(token) for token in remote_argv)
    return "cd -- {} && exec {}".format(shlex.quote(workdir), argv)


def build_ssh_argv(ssh_alias, remote_command):
    if not isinstance(ssh_alias, str) or not _SSH_ALIAS.match(ssh_alias):
        raise ValueError("unsafe_ssh_alias")
    return [
        "ssh", "-T",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout={}".format(LIMITS["connect_timeout_seconds"]),
        "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "RequestTTY=no",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "LogLevel=ERROR",
        "--", ssh_alias, remote_command,
    ]


def validate_preflight(preflight):
    """Same gate as D: exact SHAs and four explicit ``True`` flags."""
    if type(preflight) is not dict:
        raise ValueError("preflight_object_required")
    if preflight.get("d_source_sha") != D_SOURCE_SHA:
        raise ValueError("preflight_d_source_sha_mismatch")
    if preflight.get("c_source_sha") != C_SOURCE_SHA:
        raise ValueError("preflight_c_source_sha_mismatch")
    for key in PREFLIGHT_FLAGS:
        if preflight.get(key) is not True:
            raise ValueError("preflight_flag_not_true:" + key)


def run_file01(*, execution_id, target_id, ssh_alias, remote_argv, preflight,
               popen=subprocess.Popen, clock=time.monotonic, sleep=time.sleep,
               record_dir=None):
    """Run FILE-01 once over SSH and return one D ``execution`` dict.

    Input errors raise ``ValueError`` before anything is started.
    Transport failures never raise; they are mapped into ``metadata``.
    No retry is ever attempted.
    """
    _check_execution_id(execution_id)
    profile = _profile(target_id)
    if ssh_alias != profile["ssh_alias"]:
        raise ValueError("ssh_alias_not_allowed")
    expected_argv = fixed_remote_argv(target_id, profile["policy"])
    if list(remote_argv) != expected_argv:
        raise ValueError("remote_argv_not_allowed")
    validate_preflight(preflight)
    remote_command = build_remote_command(profile["workdir"], expected_argv)
    ssh_argv = build_ssh_argv(ssh_alias, remote_command)

    run_dir = None
    if record_dir is not None:
        run_dir = Path(record_dir) / execution_id
        try:
            run_dir.mkdir(parents=False, exist_ok=False)
        except FileExistsError:
            raise ValueError("duplicate_execution_id") from None

    started_wall = _utc_now()
    outcome = _execute(ssh_argv, popen=popen, clock=clock, sleep=sleep)
    finished_wall = _utc_now()

    stdout = bytes(outcome["stdout"])
    stderr = bytes(outcome["stderr"])
    timed_out = outcome["reason"] == "timeout"
    truncated = outcome["reason"] in ("stdout_over", "stderr_over")
    exit_code = None if (timed_out or truncated or outcome["returncode"] is None) else outcome["returncode"]
    succeeded = exit_code == 0 and not timed_out and not truncated

    execution = {
        "execution_id": execution_id,
        "target_id": target_id,
        "operation": OPERATION,
        "stdout": stdout,
        "stderr": stderr,
        "metadata": {
            "execution_succeeded": succeeded,
            "timeout": timed_out,
            "truncated": truncated,
            "exit_code": exit_code,
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "limits": dict(LIMITS),
            "preflight": dict(preflight),
        },
    }

    if run_dir is not None:
        reason = outcome["reason"]
        if reason == "exited":
            reason = _classify_exit(outcome["returncode"], stderr)
        a_meta = {
            "execution_id": execution_id,
            "target_id": target_id,
            "operation": OPERATION,
            "a_reason": reason,
            "returncode_raw": outcome["returncode"],
            "killed": outcome["killed"],
            "spawn_error": outcome["spawn_error"],
            "started_at_utc": started_wall,
            "finished_at_utc": finished_wall,
            "elapsed_seconds": round(outcome["elapsed"], 3),
            "ssh_argv": ssh_argv,
            "remote_workdir": profile["workdir"],
            "remote_argv": expected_argv,
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "limits": dict(LIMITS),
            "preflight": dict(preflight),
            "retries": 0,
        }
        (run_dir / "stdout.bin").write_bytes(stdout)
        (run_dir / "stderr.bin").write_bytes(stderr)
        (run_dir / "a_meta.json").write_text(
            json.dumps(a_meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return execution


def _execute(ssh_argv, *, popen, clock, sleep):
    start = clock()
    deadline = start + LIMITS["total_timeout_seconds"]
    result = {"stdout": bytearray(), "stderr": bytearray(), "returncode": None,
              "reason": "exited", "killed": False, "spawn_error": None, "elapsed": 0.0}
    posix = os.name == "posix"
    try:
        proc = popen(ssh_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, start_new_session=posix)
    except OSError as exc:
        result["reason"] = "spawn_failed"
        result["spawn_error"] = type(exc).__name__
        result["elapsed"] = clock() - start
        return result

    over = threading.Event()
    over_name = []
    readers = [
        _reader(proc.stdout, result["stdout"], LIMITS["stdout_max_bytes"], "stdout_over", over, over_name),
        _reader(proc.stderr, result["stderr"], LIMITS["stderr_max_bytes"], "stderr_over", over, over_name),
    ]
    for thread in readers:
        thread.start()

    while True:
        if over.is_set():
            result["reason"] = over_name[0]
            break
        if clock() >= deadline:
            result["reason"] = "timeout"
            break
        if proc.poll() is not None and not any(t.is_alive() for t in readers):
            break
        sleep(_POLL_SECONDS)

    if result["reason"] != "exited":
        _kill(proc, posix)
        result["killed"] = True
    try:
        proc.wait(timeout=_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except Exception:
            pass
    for thread in readers:
        thread.join(_KILL_WAIT_SECONDS)
    result["returncode"] = proc.poll()
    result["elapsed"] = clock() - start
    return result


def _reader(stream, buf, limit, over_reason, over, over_name):
    def run():
        read = getattr(stream, "read1", None) or stream.read
        while not over.is_set():
            try:
                chunk = read(_CHUNK)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            room = limit - len(buf)
            if len(chunk) > room:
                buf.extend(chunk[:max(room, 0)])
                if not over.is_set():
                    over_name.append(over_reason)
                    over.set()
                return
            buf.extend(chunk)
    return threading.Thread(target=run, daemon=True)


def _kill(proc, posix):
    try:
        if posix:
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, OSError):
        pass


def _classify_exit(returncode, stderr):
    if returncode == 0:
        return "ok"
    if returncode != 255:
        return "remote_nonzero"
    text = stderr.decode("utf-8", "replace")
    if "Host key verification failed" in text or "REMOTE HOST IDENTIFICATION HAS CHANGED" in text:
        return "host_key_mismatch"
    if "Permission denied" in text:
        return "auth_failed"
    if any(s in text for s in ("timed out", "Connection refused", "No route to host",
                               "Could not resolve", "Network is unreachable")):
        return "connect_failed"
    return "ssh_error_255"


def _check_execution_id(value):
    if not isinstance(value, str):
        raise ValueError("execution_id_must_be_str")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError:
        raise ValueError("execution_id_not_uuid") from None
    if canonical != value:
        raise ValueError("execution_id_not_canonical")


def _profile(target_id):
    if target_id not in TARGETS:
        raise ValueError("target_not_allowed")
    return TARGETS[target_id]


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
