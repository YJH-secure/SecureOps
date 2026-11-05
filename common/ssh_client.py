"""SecureOps read-only SSH collection (prototype).

Uses local OpenSSH with existing SSH agent/key and known_hosts.
No password/key is stored in source or policy JSON.
Only predefined diagnostic operations are exposed.
"""

from __future__ import annotations

import re
import subprocess
from typing import Any

# Fixed operations only. Never accept arbitrary shell commands from JSON/users.
_OPERATIONS: dict[str, str] = {
    "os_kernel": "uname -s",
    "os_release": "cat /etc/os-release",
    "current_user": "id -un",
    "passwd_metadata": "stat -c '%a %U %G' /etc/passwd",
}

_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
_SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*[$]?$")


class SSHCollectionError(Exception):
    """SSH connection, authentication or remote collection failed."""


def available_operations() -> tuple[str, ...]:
    return tuple(sorted(_OPERATIONS))


def run_readonly(
    *,
    target_id: str,
    host: str,
    username: str,
    operation: str,
    port: int = 22,
    timeout: int = 10,
) -> dict[str, Any]:
    """Execute a fixed read-only diagnostic operation over SSH.

    Requires OpenSSH client and an already verified host key in known_hosts.
    Key/agent authentication is used in noninteractive mode.
    Raises ValueError on invalid inputs and SSHCollectionError on execution failures.
    This is NOT a privileged remediation interface.
    """
    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target_id must be a nonempty string")
    if not isinstance(host, str) or not _SAFE_HOST.fullmatch(host):
        raise ValueError("invalid SSH hostname/address")
    if not isinstance(username, str) or not _SAFE_USER.fullmatch(username):
        raise ValueError("invalid SSH username")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer in 1..65535")
    if type(timeout) is not int or not 1 <= timeout <= 60:
        raise ValueError("timeout must be an integer in 1..60")
    if operation not in _OPERATIONS:
        raise ValueError(f"unsupported read-only operation: {operation!r}")

    args = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=" + str(timeout),
        "-o", "ConnectionAttempts=1",
        "-p", str(port),
        "--",
        f"{username}@{host}",
        _OPERATIONS[operation],
    ]
    try:
        completed = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SSHCollectionError("SSH operation timed out") from exc
    except OSError as exc:
        raise SSHCollectionError("SSH client could not be started") from exc

    if completed.returncode != 0:
        # Do not log full SSH stderr; it can reveal local account/path details.
        raise SSHCollectionError(
            f"SSH operation failed (exit_code={completed.returncode})"
        )
    return {
        "target_id": target_id,
        "operation": operation,
        "stdout": completed.stdout.rstrip("\n"),
        "exit_code": completed.returncode,
    }
