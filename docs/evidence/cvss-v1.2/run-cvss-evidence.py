"""Reproduce CVSS/v1.2 evidence without altering historic v1.1 evidence.

Run from the repository root:
    python -B -X utf8 docs/evidence/cvss-v1.2/run-cvss-evidence.py
Only reads local Git objects; no fetch, server collection or SSH execution.
"""

import ast
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


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
POLICY_COMMIT = "0647f7e0de104c2a7196d34ccd6143f22731a0c3"
POLICY_PATHS = (
    "docs/security-policy/cvss-scoring-policy-v1.2.md",
    "docs/architecture/json-result-contract-v1.2.md",
    "docs/architecture/json-result-schema-v1.2.schema.json",
    "tests/fixtures/sample-result-v1.2-MOCK.json",
)


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def sha(content):
    return hashlib.sha256(content).hexdigest()


def main():
    (OUT / "logs").mkdir(parents=True, exist_ok=True)
    substitutions = [(str(ROOT), "<REPO>"), (str(Path(tempfile.gettempdir())), "<TEMP>"),
                     (str(Path(sys.executable).parent.parent), "<PYTHON_INSTALL>")]

    def clean(text):
        for original, marker in substitutions:
            for value in (original, original.replace("\\", "/"), original.replace("\\", "\\\\")):
                text = text.replace(value, marker)
        return text

    meta = {"started_at_kst": now(), "branch": git("branch", "--show-current").decode().strip(),
            "head": git("rev-parse", "HEAD").decode().strip(), "uncommitted_implementation": True,
            "initial_status": clean(git("status", "--short", "--branch").decode("utf-8")),
            "python": platform.python_version(), "implementation": platform.python_implementation(),
            "os": platform.system(), "release": platform.release(), "architecture": platform.machine(),
            "policy_pr": "https://github.com/YJH-secure/SecureOps/pull/18",
            "core_pr": "https://github.com/YJH-secure/SecureOps/pull/8",
            "policy_commit": POLICY_COMMIT, "network_fetch": False, "ssh_vm_executed": False,
            "runs": [], "policy_files": {}, "bc_sources": {}}
    meta["branch_refs"] = {name: git("rev-parse", name).decode().strip()
                           for name in ("feature/core-jhm", "feature/cvss-core-jhm", "main")}
    try:
        meta["jsonschema_version"] = importlib.metadata.version("jsonschema")
        from jsonschema import FormatChecker
        meta["jsonschema_date_time_checker_available"] = "date-time" in FormatChecker.checkers
    except importlib.metadata.PackageNotFoundError:
        meta["jsonschema_version"] = None
    for path in POLICY_PATHS:
        content = (ROOT / path).read_bytes()
        meta["policy_files"][path] = {"sha256": sha(content),
            "matches_pr18_commit": content == git("show", POLICY_COMMIT + ":" + path)}

    protected = git("ls-tree", "-r", "--name-only", "HEAD", "tests", "checks", "core/legacy.py").decode().splitlines()
    changed = set(git("diff", "--name-only", "HEAD", "--", "tests", "checks", "core/legacy.py").decode().splitlines())
    meta["preservation_comparison"] = "git diff HEAD; respects checkout CRLF/LF normalization"
    meta["preserved_existing_files"] = {p: p not in changed for p in protected}
    old_ast = ast.parse(git("show", "HEAD:core/main.py").decode("utf-8"))
    new_ast = ast.parse((ROOT / "core/main.py").read_text(encoding="utf-8"))
    old_fn = next(n for n in ast.walk(old_ast) if isinstance(n, ast.FunctionDef) and n.name == "_validate_report")
    new_fn = next(n for n in ast.walk(new_ast) if isinstance(n, ast.FunctionDef) and n.name == "_validate_report_v11")
    new_fn.name = old_fn.name
    meta["v11_validator_body_preserved"] = ast.dump(old_fn) == ast.dump(new_fn)
    inputs = [*ROOT.joinpath("core").glob("*.py"), *ROOT.joinpath("tests").rglob("*.py"),
              *ROOT.joinpath("tests").rglob("*.json"), ROOT / "requirements-test.txt",
              *[ROOT / p for p in POLICY_PATHS], Path(__file__).resolve()]
    meta["tested_file_sha256"] = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in inputs}

    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    env.pop("SECUREOPS_B_SOURCE_ROOT", None)
    env.pop("SECUREOPS_C_SOURCE_ROOT", None)

    def run(label, arguments, environment, mode):
        started = now()
        completed = subprocess.run([sys.executable, "-B", "-X", "utf8", *arguments],
            cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = clean(completed.stdout.decode("utf-8", errors="replace"))
        count = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", output)
        skipped = re.search(r"skipped=(\d+)", output)
        failure = re.search(r"failures=(\d+)", output)
        error = re.search(r"errors=(\d+)", output)
        command = "python -B -X utf8 " + " ".join(arguments)
        record = {"label": label, "command": command, "mode": mode,
                  "started_at_kst": started, "finished_at_kst": now(),
                  "exit_code": completed.returncode,
                  "tests": int(count[1]) if count else None,
                  "seconds": float(count[2]) if count else None,
                  "skipped": int(skipped[1]) if skipped else 0,
                  "failures": int(failure[1]) if failure else 0,
                  "errors": int(error[1]) if error else 0,
                  "log": f"logs/{label}.log"}
        if record["tests"] is not None and completed.returncode == 0:
            record["passed"] = record["tests"] - record["skipped"] - record["failures"] - record["errors"]
        else:
            # unittest failure/error totals can count subTests, not just methods.
            record["passed"] = None
        (OUT / record["log"]).write_text(
            f"Started (KST): {started}\nCommand: {command}\nMode: {mode}\n"
            f"Exit code: {completed.returncode}\n\n{output}", encoding="utf-8")
        meta["runs"].append(record)
        print(json.dumps(record, ensure_ascii=False))

    def suite(label, pattern, environment=env, mode="D worktree; synthetic inputs"):
        run(label, ["-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"], environment, mode)

    suite("01-cvss-official", "test_cvss.py")
    suite("02-json-v12", "test_cvss_v12.py")
    suite("09-explicit-assessment", "test_cvss_assessment.py")
    suite("03-v11-core-regression", "test_core*.py")
    suite("04-v11-remote-regression", "test_remote_result.py")
    suite("05-full-worktree", "test*.py")
    sources = {
        # Pin the sources used for the original 87-test regression baseline.
        # Current B has a changed policy interface; its failure evidence is retained separately.
        "B": ("cfbd37b4dbd102ec894a2150d47f751ad5c74afa", ["checks/account/ssh_check.py"]),
        "C": ("6bb330feccfc6541bc145db9b6e18f24b4bce394", ["checks/system/file_check.py",
              "checks/system/common.py", "checks/system/policy_rules.py", "checks/system/link_check.py"]),
    }
    try:
        with tempfile.TemporaryDirectory(prefix="secureops-cvss-bc-") as directory:
            temporary = Path(directory)
            substitutions.insert(0, (str(temporary), "<BC_SOURCE_ROOT>"))
            for area, (ref, paths) in sources.items():
                commit = git("rev-parse", ref).decode().strip()
                entry = {"ref": ref, "commit": commit, "sha256": {}}
                meta["bc_sources"][area] = entry
                for path in paths:
                    content = git("show", commit + ":" + path)
                    destination = temporary / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    entry["sha256"][path] = sha(content)
            offline_env = dict(env, SECUREOPS_B_SOURCE_ROOT=str(temporary), SECUREOPS_C_SOURCE_ROOT=str(temporary))
            mode = "Actual B/C v1.1 functions; synthetic observations; no collection/SSH/VM"
            suite("06-actual-bc-v11-offline", "test_bc_offline_integration.py", offline_env, mode)
            suite("07-full-with-bc", "test*.py", offline_env, mode)
    except subprocess.CalledProcessError:
        meta["bc_not_executed_reason"] = "Local B/C source objects unavailable; offline runs not executed"
    run("08-v12-cli-mock", ["core/main.py", "tests/fixtures/sample-result-v1.2-MOCK.json"], env,
        "Adopted v1.2 MOCK fixture; no actual detections")
    meta["official_v11_mock_commit"] = git("rev-parse", "origin/main").decode().strip()
    meta["tested_files_unchanged_during_run"] = all(
        sha((ROOT / p).read_bytes()) == digest for p, digest in meta["tested_file_sha256"].items())
    meta["finished_at_kst"] = now()
    (OUT / "environment-and-results.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return int(any(row["exit_code"] for row in meta["runs"])
               or not meta["tested_files_unchanged_during_run"]
               or not all(meta["preserved_existing_files"].values())
               or not meta["v11_validator_body_preserved"]
               or not all(p["matches_pr18_commit"] for p in meta["policy_files"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
