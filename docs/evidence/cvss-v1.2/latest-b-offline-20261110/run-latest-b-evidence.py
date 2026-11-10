"""Fresh latest-B evidence; historical evidence and production code are read-only.

Run from the PR #19 review worktree:
python -B -X utf8 docs/evidence/cvss-v1.2/latest-b-offline-20261110/run-latest-b-evidence.py
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
B_REF = "origin/feature/account-check-cjw"
B_COMMIT = "3eda5a56ed3e9fd56d162676507c526ea0d1a1c1"
OLD_B = "cfbd37b4dbd102ec894a2150d47f751ad5c74afa"
OLD_C = "6bb330feccfc6541bc145db9b6e18f24b4bce394"
B_FILES = ("checks/account/ssh_check.py", "checks/account/policies/ssh_policy.json",
           "checks/account/test_ssh_check.py")
sys.path.insert(0, str(ROOT))


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def sha(content):
    return hashlib.sha256(content).hexdigest()


def worker(kind):
    latest = Path(os.environ["SECUREOPS_LATEST_B_SOURCE_ROOT"])
    if kind == "latest":
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"),
                    pattern="test_latest_b_offline_integration.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        module = sys.modules["test_latest_b_offline_integration"]
        (HERE / "latest-b-cases.json").write_text(json.dumps({
            "b_commit": B_COMMIT, "synthetic_observations_only": True,
            "cases": module.CASE_RECORDS, "invalid_policy_cases": module.POLICY_ERROR_RECORDS,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return int(not result.wasSuccessful())
    # Run B's own unmodified tests. Guard actual external execution even if a B test
    # accidentally misses one of its own collection mocks. No verdict function is replaced.
    with (patch("subprocess.Popen", side_effect=AssertionError("Actual process forbidden")) as process,
          patch("socket.socket", side_effect=AssertionError("Network forbidden")) as network,
          patch("os.system", side_effect=AssertionError("Shell forbidden")) as shell):
        sys.path.insert(0, str(latest / "checks/account"))
        suite = unittest.defaultTestLoader.discover(str(latest / "checks/account"),
                                                     pattern="test_ssh_check.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        process.assert_not_called()
        network.assert_not_called()
        shell.assert_not_called()
    return int(not result.wasSuccessful())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", choices=("latest", "b-unit"))
    options = parser.parse_args()
    if options.worker:
        return worker(options.worker)
    assert git("branch", "--show-current").decode().strip() == "feature/cvss-core-jhm-main-review"
    assert git("rev-parse", B_REF).decode().strip() == B_COMMIT, "Reinspect B if its ref changes"
    logs = HERE / "logs"
    logs.mkdir(exist_ok=True)
    tracked = git("ls-files").decode("utf-8").splitlines()
    tracked_before = {p: sha((ROOT / p).read_bytes()) for p in tracked}
    new_test = ROOT / "tests/test_latest_b_offline_integration.py"
    additions_before = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes())
                        for p in (new_test, Path(__file__).resolve())}
    meta = {"started_at_kst": now(), "head": git("rev-parse", "HEAD").decode().strip(),
        "branch": git("branch", "--show-current").decode().strip(),
        "b_ref": B_REF, "b_commit": B_COMMIT, "pinned_old_b": OLD_B, "pinned_old_c": OLD_C,
        "python": platform.python_version(), "os": platform.system(),
        "os_release": platform.release(), "architecture": platform.machine(),
        "jsonschema_version": importlib.metadata.version("jsonschema"),
        "ssh_vm_executed": False, "source_files": {}, "runs": [],
        "tracked_sha256_before": tracked_before, "new_test_runner_sha256": additions_before,
        "approval_context": {
            "b_policy_reference_claim": "2026-11-09 team-lead-approved criteria; policy_version 1.0 is file format only",
            "b_pr": "https://github.com/YJH-secure/SecureOps/pull/10",
            "main_checklist": "docs/security-policy/vulnerability-checklist-v1.1.md",
            "qualification": "B policy/code/tests/PR state approval; older main project-status still lists review pending. This is interface validation, not a new operational policy approval.",
        }}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    for name in ("SECUREOPS_B_SOURCE_ROOT", "SECUREOPS_C_SOURCE_ROOT", "SECUREOPS_LATEST_B_SOURCE_ROOT"):
        env.pop(name, None)
    replacements = [(str(ROOT), "<REPO>"), (str(Path(tempfile.gettempdir())), "<TEMP>"),
                    (str(Path(sys.executable).parent.parent), "<PYTHON_INSTALL>")]

    def clean(text):
        for path, marker in replacements:
            for value in (path, path.replace("\\", "/"), path.replace("\\", "\\\\")):
                text = text.replace(value, marker)
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def run(label, arguments, environment, scope):
        started = now()
        completed = subprocess.run([sys.executable, "-B", "-X", "utf8", *arguments],
            cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = clean(completed.stdout.decode("utf-8", errors="replace"))
        count = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", output)
        numbers = {name: int(found[1]) if (found := re.search(name + r"=(\d+)", output)) else 0
                   for name in ("skipped", "failures", "errors")}
        command = "python -B -X utf8 " + " ".join(arguments)
        record = dict(label=label, command=command, scope=scope, started_at_kst=started,
            finished_at_kst=now(), exit_code=completed.returncode,
            tests=int(count[1]) if count else None, seconds=float(count[2]) if count else None,
            raw_process_output_sha256=sha(completed.stdout), log=f"logs/{label}.log", **numbers)
        record["passed"] = record["tests"] - numbers["skipped"] if completed.returncode == 0 and count else None
        (HERE / record["log"]).write_bytes((f"Started (KST): {started}\nCommand: {command}\n"
            f"Scope: {scope}\nExit code: {completed.returncode}\n\n" + output).encode("utf-8"))
        meta["runs"].append(record)
        print(json.dumps(record, ensure_ascii=False))

    def suite(label, pattern, environment, scope):
        run(label, ["-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"], environment, scope)

    with tempfile.TemporaryDirectory(prefix="secureops-latest-b-") as directory:
        temporary = Path(directory)
        replacements.insert(0, (str(temporary), "<SOURCE_EXPORT>"))
        latest, baseline = temporary / "latest", temporary / "baseline"
        for path in B_FILES:
            content = git("show", B_COMMIT + ":" + path)
            destination = latest / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            meta["source_files"][path] = {"commit": B_COMMIT, "sha256": sha(content)}
        # Evidence copy only; no files are added under checks/account in the D checkout.
        (HERE / "source-policy.json").write_bytes((latest / B_FILES[1]).read_bytes())
        historical_sources = {OLD_B: ["checks/account/ssh_check.py"], OLD_C: [
            "checks/system/file_check.py", "checks/system/common.py",
            "checks/system/policy_rules.py", "checks/system/link_check.py"]}
        meta["pinned_source_sha256"] = {}
        for commit, paths in historical_sources.items():
            for path in paths:
                content = git("show", commit + ":" + path)
                destination = baseline / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                meta["pinned_source_sha256"][path] = {"commit": commit, "sha256": sha(content)}
        current_env = dict(env, SECUREOPS_LATEST_B_SOURCE_ROOT=str(latest))
        baseline_env = dict(env, SECUREOPS_B_SOURCE_ROOT=str(baseline), SECUREOPS_C_SOURCE_ROOT=str(baseline))
        all_env = dict(baseline_env, SECUREOPS_LATEST_B_SOURCE_ROOT=str(latest))
        relative = Path(__file__).relative_to(ROOT).as_posix()
        run("01-latest-b-to-d", [relative, "--worker", "latest"], current_env, "Actual latest B + exact policy -> D v1.1")
        run("02-b-unit-unchanged", [relative, "--worker", "b-unit"], current_env, "Unmodified B unit tests, actual execution guarded")
        suite("03-cvss-regression", "test_cvss*.py", env, "Existing 52 CVSS/v1.2 tests")
        suite("04-v11-core-regression", "test_core*.py", env, "Existing 70 D v1.1 core tests")
        suite("05-v11-remote-regression", "test_remote_result.py", env, "Existing 14 remote JSON tests")
        suite("06-pinned-bc-regression", "test_bc_offline_integration.py", baseline_env, "Historical B/C commits only")
        suite("07-full-without-bc", "test*.py", env, "No B/C source; separate missing-source skips")
        suite("08-full-pinned-bc-and-latest-b", "test*.py", all_env,
              "Historical B/C regression + separately named current B integration")
        assert all(sha((latest / p).read_bytes()) == v["sha256"] for p, v in meta["source_files"].items())
    meta["tracked_files_unchanged"] = all(sha((ROOT / p).read_bytes()) == value for p, value in tracked_before.items())
    meta["new_test_runner_unchanged_during_run"] = all(sha((ROOT / p).read_bytes()) == value for p, value in additions_before.items())
    meta["tracked_git_diff"] = git("diff", "--name-only").decode()
    meta["log_encoding"] = "UTF-8; CRLF/CR normalized to LF; raw stdout SHA-256 recorded"
    meta["finished_at_kst"] = now()
    (HERE / "environment-and-results.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return int(any(row["exit_code"] for row in meta["runs"]) or
               not meta["tracked_files_unchanged"] or not meta["new_test_runner_unchanged_during_run"])


if __name__ == "__main__":
    raise SystemExit(main())
