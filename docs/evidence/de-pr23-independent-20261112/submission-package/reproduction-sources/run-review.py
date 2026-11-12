"""Read-only official sources, new processes and separate D/E evidence stores."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
D_ROOT = HERE.parents[2]
D_SHA = "62d1bf72ef52c7455bc0c2dd624206eb8350f925"
E_SHA = "b0ef73a1613ebc40fdd596edcbaf0413d32309b8"


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def git(root, *args):
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(root), *args], cwd=root)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {name: sha(root / name) for name in git(root, "ls-files").decode().splitlines()}


def worker(kind, e_root):
    import core.main
    import core.storage
    import remediation
    assert Path(core.main.__file__).resolve().is_relative_to(D_ROOT)
    assert Path(core.storage.__file__).resolve().is_relative_to(D_ROOT)
    assert Path(remediation.__file__).resolve().is_relative_to(e_root)
    sys.path[:0] = [str(e_root / "tests"), str(D_ROOT / "tests")]
    loader = unittest.TestLoader()
    if kind == "c-fw-log":
        suite = loader.loadTestsFromNames(["checks.system.tests.test_firewall_check", "checks.system.tests.test_log_check"])
    else:
        directory, pattern = {
            "e-remediation": (e_root / "tests", "test_remediation*.py"),
            "e-history": (e_root / "tests", "test_execution_history*.py"),
            "d-cvss": (D_ROOT / "tests", "test_cvss*.py"),
            "d-full": (D_ROOT / "tests", "test*.py"),
            "independent": (D_ROOT / "tests", "test_de_pr23_independent.py"),
        }[kind]
        # Duplicate test filenames exist in both repos. The requested suite's
        # directory must lead sys.path even when it was already present.
        sys.path.insert(0, str(directory))
        suite = loader.discover(str(directory), pattern=pattern, top_level_dir=str(directory))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if kind == "independent" and result.wasSuccessful() and not result.skipped:
        from core.storage import ReportStore
        from remediation import ExecutionHistoryStore
        records = sys.modules["test_de_pr23_independent"].RECORDS
        d_store = ReportStore(HERE / "d-diagnoses")
        e_store = ExecutionHistoryStore(HERE / "e-executions")
        for row in records:
            execution = row["e_execution"]
            original = json.loads(json.dumps(execution, allow_nan=False))
            e_store.save(execution)
            # E history explicitly serializes dry-run tuples as JSON arrays.
            assert e_store.load(execution["execution_id"]) == original
            assert json.loads(json.dumps(execution, allow_nan=False)) == original
            for report in row["d_reports"]:
                d_store.save(report)
                assert d_store.load(report["target_id"], report["scan_id"]) == report
        (HERE / "independent-results.json").write_bytes((json.dumps(records, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    provenance = {}
    for name, module in sorted(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and (name.startswith("core.") or name.startswith("remediation")):
            resolved = Path(path).resolve()
            owner = D_ROOT if name.startswith("core.") else e_root
            assert resolved.is_relative_to(owner), (name, "wrong source checkout")
            provenance[name] = {"checkout": "D_MAIN" if owner == D_ROOT else "E_PR23", "path": resolved.relative_to(owner).as_posix(), "sha256": sha(resolved)}
    (HERE / ("imports-" + kind + ".json")).write_bytes((json.dumps(provenance, indent=2) + "\n").encode())
    return int(not result.wasSuccessful() or bool(result.skipped))


def main():
    global HERE
    parser = argparse.ArgumentParser()
    parser.add_argument("--e-root", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--worker", choices=("e-remediation", "e-history", "d-cvss", "c-fw-log", "d-full", "independent"))
    args = parser.parse_args()
    output = args.output_dir or os.environ.get("SECUREOPS_DE_EVIDENCE_OUTPUT")
    if output:
        HERE = Path(output).resolve()
        HERE.mkdir(parents=True, exist_ok=True)
    e_root = args.e_root.resolve()
    if args.worker:
        return worker(args.worker, e_root)
    if (HERE / "environment-and-results.json").exists():
        raise FileExistsError("Do not overwrite run evidence")
    assert git(D_ROOT, "rev-parse", "HEAD").decode().strip() == D_SHA
    assert git(e_root, "rev-parse", "HEAD").decode().strip() == E_SHA
    before_d, before_e = snapshot(D_ROOT), snapshot(e_root)
    for root, commit, values in ((D_ROOT, D_SHA, before_d), (e_root, E_SHA, before_e)):
        for name in values:
            assert git(root, "show", commit + ":" + name).replace(b"\r\n", b"\n") == (root / name).read_bytes().replace(b"\r\n", b"\n"), name
    data = {"started_at_kst": now(), "d_main_commit": D_SHA, "e_pr23_head": E_SHA,
        "python": platform.python_version(), "platform": platform.system() + " " + platform.release(),
        "jsonschema": importlib.metadata.version("jsonschema"), "actual_ssh_vm": False,
        "source_git_blobs_verified": True, "d_tracked_sha256": before_d, "e_tracked_sha256": before_e,
        "e_code_vs_readme_commit_diff": git(e_root, "diff", "--name-status", "7730f4ff6d8fc666bd68093f072e7971c79e358a", E_SHA).decode().splitlines(),
        "runs": []}
    (HERE / "logs").mkdir(exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    for name in list(env):
        if name.startswith("SECUREOPS_"):
            env.pop(name)
    env.update(SECUREOPS_D_SOURCE=str(D_ROOT), SECUREOPS_REVIEW_D=str(D_ROOT), SECUREOPS_REVIEW_E=str(e_root),
               SECUREOPS_DE_EVIDENCE_OUTPUT=str(HERE))
    with tempfile.TemporaryDirectory(prefix="secureops-de-bootstrap-") as folder:
        bootstrap = Path(folder)
        # Also apply source selection in original E tests' CLI subprocesses.
        (bootstrap / "sitecustomize.py").write_text(
            "import os,sys,importlib.util\nfrom pathlib import Path\n"
            "d=Path(os.environ['SECUREOPS_D_SOURCE']); e=Path(os.environ['SECUREOPS_REVIEW_E'])\n"
            "sys.path.insert(0,str(d))\nimport core.main,core.storage\n"
            "s=importlib.util.spec_from_file_location('remediation',e/'remediation/__init__.py',submodule_search_locations=[str(e/'remediation')])\n"
            "m=importlib.util.module_from_spec(s);sys.modules['remediation']=m;s.loader.exec_module(m)\n",
            encoding="utf-8")
        env["PYTHONPATH"] = os.pathsep.join([str(bootstrap), str(D_ROOT), str(e_root / "tests"), str(D_ROOT / "tests")])
        relative = Path(__file__).relative_to(D_ROOT).as_posix()
        for index, kind in enumerate(("e-remediation", "e-history", "d-cvss", "c-fw-log", "independent", "d-full"), 1):
            arguments = ["-B", "-X", "utf8", relative, "--e-root", str(e_root), "--worker", kind]
            started = now()
            completed = subprocess.run([sys.executable, *arguments], cwd=D_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            text = completed.stdout.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            for value, marker in ((str(D_ROOT), "<D_MAIN>"), (str(e_root), "<E_PR23>"), (str(bootstrap), "<BOOTSTRAP>"), (tempfile.gettempdir(), "<TEMP>"), (str(Path.home()), "<USER_HOME>")):
                for spelling in (value, value.replace("\\", "/"), value.replace("\\", "\\\\")):
                    text = text.replace(spelling, marker)
            text = "\n".join(line.rstrip() for line in text.split("\n"))
            match = re.search(r"Ran (\d+) tests? in", text)
            row = {"group": kind, "command": "python -B -X utf8 " + relative + " --e-root <E_PR23> --worker " + kind,
                "started_at_kst": started, "finished_at_kst": now(), "exit_code": completed.returncode,
                "tests_run": int(match[1]) if match else None,
                "ok_method_lines": len(re.findall(r"^test.*\.\.\. ok$", text, re.M)),
                "log": "logs/" + str(index).zfill(2) + "-" + kind + ".log"}
            for key in ("failures", "errors", "skipped"):
                found = re.search(key + r"=(\d+)", text)
                row[key] = int(found[1]) if found else 0
            (HERE / row["log"]).write_bytes((json.dumps(row) + "\n\n" + text).encode())
            data["runs"].append(row)
            print(json.dumps(row), flush=True)
    data["d_tracked_unchanged"] = before_d == snapshot(D_ROOT)
    data["e_tracked_unchanged"] = before_e == snapshot(e_root)
    data["finished_at_kst"] = now()
    (HERE / "environment-and-results.json").write_bytes((json.dumps(data, indent=2) + "\n").encode())
    return int(any(row["exit_code"] for row in data["runs"]) or not data["d_tracked_unchanged"] or not data["e_tracked_unchanged"])


if __name__ == "__main__":
    raise SystemExit(main())
