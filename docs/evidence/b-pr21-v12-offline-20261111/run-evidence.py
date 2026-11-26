"""New processes; fixed PR #21 source; no SSH/VM or historical evidence edits."""
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
ROOT = HERE.parents[2]
B_COMMIT = "9f58ee2efca3189866548219e05b732d254e279f"
sys.path.insert(0, str(ROOT))


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def worker(kind):
    if kind == "integration":
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_b_pr21_v12_offline_integration.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if result.wasSuccessful() and not result.skipped:
            from core.storage import ReportStore
            records = sys.modules["test_b_pr21_v12_offline_integration"].CASE_RECORDS
            store = ReportStore(HERE / "saved-reports")
            for row in records:
                path = store.save(row["d_report"])
                assert store.load("mock-b-pr21", row["d_report"]["scan_id"]) == row["d_report"]
                row["saved_path"] = path.relative_to(HERE).as_posix()
                row["saved_sha256"] = sha(path)
            assert len(store.history("mock-b-pr21")) == len(records)
            (HERE / "actual-b-results-and-d-reports.json").write_bytes(
                (json.dumps(records, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    else:
        directory = Path(os.environ["SECUREOPS_B_PR21_SOURCE_ROOT"]) / "checks/account"
        sys.path.insert(0, str(directory))
        suite = unittest.defaultTestLoader.discover(str(directory), pattern="test_ssh_check.py")
        # Original B unit test mocks still work; any real fallback must fail.
        with patch("subprocess.Popen", side_effect=AssertionError("External process forbidden")) as process, \
             patch("os.system", side_effect=AssertionError("External process forbidden")) as system, \
             patch("socket.socket", side_effect=AssertionError("Network forbidden")) as network:
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            process.assert_not_called()
            system.assert_not_called()
            network.assert_not_called()
    return int(not result.wasSuccessful() or bool(result.skipped))


def main():
    global HERE
    parser = argparse.ArgumentParser()
    parser.add_argument("--b-source-root", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--worker", choices=("integration", "b-unit"))
    args = parser.parse_args()
    selected_output = args.output_dir or os.environ.get("SECUREOPS_PR21_EVIDENCE_OUTPUT")
    if selected_output:
        HERE = Path(selected_output).resolve()
        HERE.mkdir(parents=True, exist_ok=True)
    if args.worker:
        return worker(args.worker)
    if args.b_source_root is None:
        parser.error("--b-source-root required")
    if (HERE / "environment-and-results.json").exists() or (HERE / "saved-reports").exists():
        raise FileExistsError("Do not overwrite existing evidence")
    source = args.b_source_root.resolve()
    source_hashes = {}
    for name in ("checks/account/ssh_check.py", "checks/account/policies/ssh_policy.json", "checks/account/test_ssh_check.py"):
        expected = hashlib.sha256(git("show", B_COMMIT + ":" + name)).hexdigest()
        assert sha(source / name) == expected
        source_hashes[name] = expected
    tracked = git("ls-files").decode().splitlines()
    before = {name: sha(ROOT / name) for name in tracked}
    data = {"started_at_kst": now(), "d_commit": git("rev-parse", "HEAD").decode().strip(),
            "origin_main": git("rev-parse", "origin/main").decode().strip(),
            "branch": git("branch", "--show-current").decode().strip(),
            "b_pr": 21, "b_branch": "feature/json-v1.2-cjw", "b_commit": B_COMMIT,
            "b_dependency_pr": 10, "b_dependency_commit": "3eda5a56ed3e9fd56d162676507c526ea0d1a1c1",
            "b_pr21_merged": False, "b_pr10_merged": False,
            "scope": "Fixed unmerged B PR source against D main; not official merged-main B integration",
            "b_source_sha256": source_hashes, "python": platform.python_version(),
            "platform": platform.system() + " " + platform.release(), "architecture": platform.machine(),
            "jsonschema": importlib.metadata.version("jsonschema"), "actual_ssh_vm": False, "runs": []}
    policy = json.loads((source / "checks/account/policies/ssh_policy.json").read_text(encoding="utf-8"))
    item = policy["policies"][0]
    data["policy_provenance"] = {"path": "checks/account/policies/ssh_policy.json", "commit": B_COMMIT,
        "policy_version": policy["policy_version"], "reference": item["reference"],
        "cvss_assessment": item["cvss_assessment"], "operational_policy_reapproved_by_d": False}
    (HERE / "logs").mkdir(exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    for key in ("SECUREOPS_B_SOURCE_ROOT", "SECUREOPS_C_SOURCE_ROOT", "SECUREOPS_LATEST_B_SOURCE_ROOT", "SECUREOPS_C_ZIP_SOURCE_ROOT", "SECUREOPS_B_PR21_SOURCE_ROOT"):
        env.pop(key, None)
    b_env = dict(env, SECUREOPS_B_PR21_SOURCE_ROOT=str(source), SECUREOPS_PR21_EVIDENCE_OUTPUT=str(HERE))
    replacements = [(str(ROOT), "<REPO>"), (str(source), "<B_PR21_SOURCE>"),
                    (tempfile.gettempdir(), "<TEMP>"), (str(Path.home()), "<USER_HOME>")]
    relative = Path(__file__).relative_to(ROOT).as_posix()

    def run(label, arguments, configured, scope):
        started = now()
        completed = subprocess.run([sys.executable, "-B", "-X", "utf8", *arguments], cwd=ROOT,
            env=configured, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = completed.stdout.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        for value, marker in replacements:
            for spelling in (value, value.replace("\\", "/"), value.replace("\\", "\\\\")):
                text = text.replace(spelling, marker)
        count = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", text)
        row = {"label": label, "command": "python -B -X utf8 " + " ".join(arguments),
               "scope": scope, "started_at_kst": started, "finished_at_kst": now(),
               "exit_code": completed.returncode, "tests": int(count[1]) if count else None,
               "log": "logs/" + label + ".log"}
        for key in ("skipped", "failures", "errors"):
            match = re.search(key + r"=(\d+)", text)
            row[key] = int(match[1]) if match else 0
        # Subtest errors can outnumber affected test methods. Do not infer a
        # method pass count from error events for an unsuccessful run.
        row["passed"] = row["tests"] - row["skipped"] if count and completed.returncode == 0 else None
        (HERE / row["log"]).write_bytes((json.dumps(row) + "\n\n" + text).encode("utf-8"))
        data["runs"].append(row)
        print(json.dumps(row), flush=True)

    run("01-b-pr21-to-d", [relative, "--worker", "integration"], b_env, "Actual B run_check with synthetic collection only")
    run("02-original-b-unit", [relative, "--worker", "b-unit"], b_env, "Unmodified B original 47 unit tests, process/network fallbacks blocked")
    run("03-default-d-full", ["-m", "unittest", "discover", "-s", "tests", "-v"], env, "D tests without external B sources")
    with tempfile.TemporaryDirectory(prefix="secureops-pr21-regression-") as folder:
        temporary = Path(folder)
        replacements.insert(0, (str(temporary), "<FIXED_GIT_EXPORT>"))
        baseline, latest = temporary / "baseline", temporary / "latest"
        refs = [(baseline, "cfbd37b4dbd102ec894a2150d47f751ad5c74afa", ["checks/account/ssh_check.py"]),
                (baseline, "6bb330feccfc6541bc145db9b6e18f24b4bce394", ["checks/system/" + name for name in ("file_check.py", "common.py", "policy_rules.py", "link_check.py")]),
                (latest, "3eda5a56ed3e9fd56d162676507c526ea0d1a1c1", ["checks/account/ssh_check.py", "checks/account/policies/ssh_policy.json"])]
        data["separate_regression_source_commits"] = list(dict.fromkeys(ref for _, ref, _ in refs))
        for destination, ref, paths in refs:
            for name in paths:
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(git("show", ref + ":" + name))
        full_env = dict(b_env, SECUREOPS_B_SOURCE_ROOT=str(baseline), SECUREOPS_C_SOURCE_ROOT=str(baseline), SECUREOPS_LATEST_B_SOURCE_ROOT=str(latest))
        run("04-d-full-with-fixed-sources", ["-m", "unittest", "discover", "-s", "tests", "-v"], full_env,
            "Existing D 149 plus new PR21 10; historical B/C and prior B kept separate")
    data["tracked_file_hashes_unchanged"] = all(sha(ROOT / name) == expected for name, expected in before.items())
    data["b_sources_unchanged"] = all(sha(source / name) == expected for name, expected in source_hashes.items())
    data["finished_at_kst"] = now()
    (HERE / "environment-and-results.json").write_bytes((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return int(any(r["exit_code"] for r in data["runs"]) or not data["tracked_file_hashes_unchanged"] or not data["b_sources_unchanged"])


if __name__ == "__main__":
    raise SystemExit(main())
