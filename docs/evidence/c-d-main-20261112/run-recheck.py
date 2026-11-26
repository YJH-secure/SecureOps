"""Official main C/D recheck. Never runs code from the supplied evidence ZIP."""
import argparse
import copy
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
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MAIN = "62d1bf72ef52c7455bc0c2dd624206eb8350f925"
sys.path.insert(0, str(ROOT))


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def git(*args):
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(ROOT), *args], cwd=ROOT)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot():
    return {name: sha(ROOT / name) for name in git("ls-files").decode().splitlines()}


def write(name, data):
    (HERE / name).write_bytes((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def worker(kind):
    pattern = "test_c_zip_v12_integration.py" if kind == "pr20" else "test_c_pr27_independent.py"
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern=pattern)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped:
        return 1
    from core.storage import ReportStore
    if kind == "pr20":
        evidence = sys.modules["test_c_zip_v12_integration"].EVIDENCE
        store = ReportStore(HERE / "pr20-reports")
        for key in ("report_v11", "report_v12"):
            report = evidence[key]
            store.save(report)
            assert store.load(report["target_id"], report["scan_id"]) == report
        write("pr20-results.json", evidence)
    else:
        module = sys.modules["test_c_pr27_independent"]
        store = ReportStore(HERE / "independent-reports")
        for row in module.RECORDS:
            report = row["report"]
            store.save(report)
            assert store.load(report["target_id"], report["scan_id"]) == report
        write("independent-results.json", module.RECORDS)
        # One additional roundtrip of the four real module outputs, not a
        # fabricated fifth diagnosis and not an extra unittest method.
        case = module.OfficialCIndependentTests()
        case.setUp()
        try:
            legacy = case.generate()[:4]
            exported = [case.adapter.adapt_result(item, "1.2") for item in legacy]
            before = copy.deepcopy(exported)
            from core.runner import run_target
            from core.remote_result import parse_result_json
            outcome = run_target(account_checks=[], system_checks=[
                lambda item=item: parse_result_json(json.dumps(item, ensure_ascii=False), exit_code=0,
                    execution_succeeded=True, schema_version="1.2") for item in exported],
                target_id="main-four-module-MOCK", os="ubuntu-24.04", mode="mock", schema_version="1.2",
                scan_id="main-four-module-62d1bf7", scanned_at="2026-11-12T12:00:00+09:00",
                output_root=HERE / "four-module-store")
            loaded = ReportStore(outcome.path.parent).load("main-four-module-MOCK", outcome.report["scan_id"])
            assert loaded == outcome.report and loaded["results"] == exported == before
            assert [r["status"] for r in exported] == ["pass", "vulnerable", "error", "needs_review"]
            assert outcome.summary["metrics"]["pass_rate"] == "50.0%"
            write("four-module-results.json", {"actual_c_v11": legacy, "actual_c_v12": exported,
                "report": loaded, "summary": outcome.summary, "reloaded_equal": True,
                "diagnostic_error_json_received": True, "synthetic_input_only": True})
        finally:
            case.doCleanups()
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", choices=("pr20", "independent"))
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker)
    if (HERE / "environment-and-results.json").exists():
        raise FileExistsError("Preserve prior execution evidence")
    assert git("rev-parse", "HEAD").decode().strip() == MAIN
    before = snapshot()
    for name in before:
        assert git("show", MAIN + ":" + name).replace(b"\r\n", b"\n") == (ROOT / name).read_bytes().replace(b"\r\n", b"\n"), name
    data = {"started_at_kst": now(), "c_and_d_commit": MAIN, "source_kind": "Official main Git worktree",
        "python": platform.python_version(), "platform": platform.system() + " " + platform.release(),
        "jsonschema": importlib.metadata.version("jsonschema"), "git_blob_content_verified": True,
        "tracked_sha256_before": before, "actual_ssh_vm": False, "zip_code_executed": False, "runs": []}
    (HERE / "logs").mkdir(exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    for name in list(env):
        if name.startswith("SECUREOPS_") or name == "PYTHONPATH":
            env.pop(name)
    relative = Path(__file__).relative_to(ROOT).as_posix()
    def run(label, args, selected, scope):
        started = now()
        done = subprocess.run([sys.executable, "-B", "-X", "utf8", *args], cwd=ROOT, env=selected,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = done.stdout.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        command = "python -B -X utf8 " + " ".join(args)
        for value, marker in ((str(ROOT), "<OFFICIAL_MAIN>"), (str(Path.home()), "<USER_HOME>")):
            for spelling in (value, value.replace("\\", "/"), value.replace("\\", "\\\\")):
                text = text.replace(spelling, marker)
                command = command.replace(spelling, marker)
        text = "\n".join(line.rstrip() for line in text.split("\n"))
        count = re.search(r"Ran (\d+) tests? in", text)
        row = {"label": label, "command": command, "scope": scope, "started_at_kst": started,
            "finished_at_kst": now(), "exit_code": done.returncode, "tests_run": int(count[1]) if count else None,
            "ok_method_lines": len(re.findall(r"^test.*\.\.\. ok$", text, re.M)), "log": "logs/" + label + ".log"}
        for key in ("failures", "errors", "skipped"):
            found = re.search(key + r"=(\d+)", text)
            row[key] = int(found[1]) if found else 0
        (HERE / row["log"]).write_bytes((json.dumps(row) + "\n\n" + text).encode("utf-8"))
        data["runs"].append(row)
        print(json.dumps(row), flush=True)
    run("01-c-unit", ["-m", "unittest", "discover", "-s", "checks/system/tests", "-v"], env, "Official main original C unit/regression")
    run("02-scenario-help", ["-m", "checks.system.verify_json_scenarios", "--help"], env, "Actual CLI options")
    run("03-c-scenarios", ["-m", "checks.system.verify_json_scenarios", "--code-commit", MAIN,
        "--d-root", str(ROOT), "--output-dir", str(HERE / "official-scenarios")], env, "C-authored verifier independently rerun by D")
    # Run pristine main discovery before placing the separate legacy D review tests.
    run("04-d-default", ["-m", "unittest", "discover", "-s", "tests", "-v"], env, "Pristine official main tests; no extra review files yet")
    run("05-d-source-specified", ["-m", "unittest", "discover", "-s", "tests", "-v"], dict(env, SECUREOPS_D_SOURCE=str(ROOT)), "Pristine main tests plus enabled E integration")
    sources = {
        "test_c_zip_v12_integration.py": Path("<PR20_CHECKOUT>/tests/test_c_zip_v12_integration.py"),
        "test_c_pr27_independent.py": Path("<D_INDEPENDENT_CHECKOUT>/tests/test_c_pr27_independent.py"),
    }
    copied = {}
    for name, source in sources.items():
        destination = ROOT / "tests" / name
        assert not destination.exists()
        destination.write_bytes(source.read_bytes())
        assert sha(destination) == sha(source)
        copied[name] = sha(source)
    data["unchanged_review_test_sha256"] = copied
    official = dict(env, SECUREOPS_C_ZIP_SOURCE_ROOT=str(ROOT), SECUREOPS_C_PR27_SOURCE_ROOT=str(ROOT))
    run("06-pr20-nine", [relative, "--worker", "pr20"], official, "Original PR20 9 methods unchanged; official main source")
    run("07-d-independent-eight", [relative, "--worker", "independent"], official, "Original D independent 8 methods unchanged plus separate four-module roundtrip")
    data["tracked_files_unchanged"] = before == snapshot()
    data["finished_at_kst"] = now()
    write("environment-and-results.json", data)
    return int(any(r["exit_code"] for r in data["runs"]) or not data["tracked_files_unchanged"])


if __name__ == "__main__":
    raise SystemExit(main())
