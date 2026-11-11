"""C ZIP -> D offline evidence. Never execute the ZIP's VM verification script.

python -B -X utf8 docs/evidence/c-v12-zip-mock-20261110/run-c-zip-evidence.py --c-source-root <EXTRACTED_ROOT>
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
import zipfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
D_BASE = "f7e4f16d94e68e408087de2cf34a9337a4f63ddf"
D_PR_HEAD = "8ae2ca1ba09f45c6b0f4a6c49a6a1572f0caca95"
ZIP_SHA256 = "636bca49f28eca129ad973fd0479d7d8b87acc7513ec7fa41b2b4485781999c8"
OLD_B = "cfbd37b4dbd102ec894a2150d47f751ad5c74afa"
OLD_C = "6bb330feccfc6541bc145db9b6e18f24b4bce394"
LATEST_B = "3eda5a56ed3e9fd56d162676507c526ea0d1a1c1"
sys.path.insert(0, str(ROOT))


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*arguments):
    return subprocess.run(["git", *arguments], cwd=ROOT, check=True, capture_output=True).stdout


def worker():
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_c_zip_v12_integration.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful() and not result.skipped:
        from core.storage import ReportStore
        evidence = sys.modules["test_c_zip_v12_integration"].EVIDENCE
        (HERE / "c-results-and-d-summary.json").write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # Preserve actual D reports and perform another real save/load roundtrip.
        store = ReportStore(HERE / "saved-reports")
        saved = {}
        for name in ("report_v11", "report_v12"):
            report = evidence[name]
            path = store.save(report)
            reloaded = store.load(report["target_id"], report["scan_id"])
            assert reloaded == report
            saved[name] = {"path": path.relative_to(HERE).as_posix(), "reloaded_equal": True,
                           "sha256": sha(path.read_bytes()), "schema_version": report["schema_version"]}
        (HERE / "saved-report-verification.json").write_text(
            json.dumps(saved, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return int(not result.wasSuccessful() or bool(result.skipped))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--c-source-root", type=Path)
    parser.add_argument("--zip-file", type=Path, default=Path.home() / "Downloads/SecureOps_C_v12_VM.zip")
    args = parser.parse_args()
    if args.worker:
        return worker()
    if args.c_source_root is None:
        parser.error("--c-source-root is required for the provided ZIP source")
    source = args.c_source_root.resolve()
    assert git("rev-parse", "HEAD").decode().strip() == D_BASE
    assert git("branch", "--show-current").decode().strip() == "feature/c-d-v12-mock-review"
    assert sha(args.zip_file.read_bytes()) == ZIP_SHA256
    # Refuse to overwrite evidence from a previous run. Use a new evidence output directory for another run.
    if (HERE / "environment-and-results.json").exists() or (HERE / "saved-reports").exists():
        raise FileExistsError("Existing run evidence must not be overwritten")
    source_before = {p.relative_to(source).as_posix(): sha(p.read_bytes())
                     for p in source.rglob("*") if p.is_file()}
    with zipfile.ZipFile(args.zip_file) as archive:
        expected = {Path(item.filename).relative_to("SecureOps_C_v12_VM").as_posix(): sha(archive.read(item))
                    for item in archive.infolist() if not item.is_dir()}
    assert source_before == expected
    tracked = git("ls-files").decode("utf-8").splitlines()
    before = {p: sha((ROOT / p).read_bytes()) for p in tracked}
    (HERE / "logs").mkdir(exist_ok=True)
    metadata = {"started_at_kst": now(), "d_base_commit": D_BASE, "d_pr19_head": D_PR_HEAD,
        "pr19_merged": True, "branch": "feature/c-d-v12-mock-review",
        "c_source_kind": "provided ZIP, not an official Git commit", "zip_filename": args.zip_file.name,
        "zip_sha256": ZIP_SHA256, "c_source_sha256": source_before,
        "python": platform.python_version(), "os": platform.system(), "release": platform.release(),
        "architecture": platform.machine(), "jsonschema": importlib.metadata.version("jsonschema"),
        "ssh_vm_executed": False, "c_vm_verification_script_executed": False,
        "tracked_file_sha256_before": before, "runs": [],
        "development_probe": {"tests": 9, "failure_events": 14,
            "cause": "Initial new D harness blocked LOG metadata discovery inside its synthetic temp config tree.",
            "resolution": "Changed only the new harness to supply metadata confined to that tree.",
            "production_code_changed": False, "initial_full_log_retained": False}}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    for name in ("SECUREOPS_B_SOURCE_ROOT", "SECUREOPS_C_SOURCE_ROOT", "SECUREOPS_LATEST_B_SOURCE_ROOT",
                 "SECUREOPS_C_ZIP_SOURCE_ROOT"):
        env.pop(name, None)
    replacements = [(str(ROOT), "<REPO>"), (str(source), "<C_ZIP_SOURCE>"),
                    (str(Path(tempfile.gettempdir())), "<TEMP>"),
                    (str(Path(sys.executable).parent.parent), "<PYTHON_INSTALL>")]

    def clean(text):
        for path, marker in replacements:
            for value in (path, path.replace("\\", "/"), path.replace("\\", "\\\\")):
                text = text.replace(value, marker)
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def run(label, arguments, configured, scope):
        started = now()
        completed = subprocess.run([sys.executable, "-B", "-X", "utf8", *arguments],
            cwd=ROOT, env=configured, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = clean(completed.stdout.decode("utf-8", errors="replace"))
        count = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", output)
        numbers = {key: int(m[1]) if (m := re.search(key + r"=(\d+)", output)) else 0
                   for key in ("skipped", "failures", "errors")}
        row = {"label": label, "command": "python -B -X utf8 " + " ".join(arguments),
               "scope": scope, "started_at_kst": started, "finished_at_kst": now(),
               "exit_code": completed.returncode, "tests": int(count[1]) if count else None,
               "seconds": float(count[2]) if count else None, "log": f"logs/{label}.log", **numbers}
        row["passed"] = row["tests"] - row["skipped"] if count and completed.returncode == 0 else None
        (HERE / row["log"]).write_bytes((f"Started (KST): {started}\nCommand: {row['command']}\n"
            f"Scope: {scope}\nExit code: {row['exit_code']}\n\n" + output).encode("utf-8"))
        metadata["runs"].append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)

    c_env = dict(env, SECUREOPS_C_ZIP_SOURCE_ROOT=str(source))
    relative = Path(__file__).relative_to(ROOT).as_posix()
    run("01-c-zip-to-d", [relative, "--worker"], c_env,
        "Actual supplied C diagnosis/adapter functions; synthetic inputs; v1.1/v1.2")
    run("02-default-full", ["-m", "unittest", "discover", "-s", "tests", "-v"], env,
        "All external B/C source variables removed")
    with tempfile.TemporaryDirectory(prefix="secureops-c-d-regression-") as folder:
        temporary = Path(folder)
        replacements.insert(0, (str(temporary), "<GIT_SOURCE_EXPORT>"))
        baseline, latest = temporary / "baseline", temporary / "latest"
        for destination_root, commit, paths in (
            (baseline, OLD_B, ["checks/account/ssh_check.py"]),
            (baseline, OLD_C, ["checks/system/file_check.py", "checks/system/common.py",
                              "checks/system/policy_rules.py", "checks/system/link_check.py"]),
            (latest, LATEST_B, ["checks/account/ssh_check.py", "checks/account/policies/ssh_policy.json"])):
            for path in paths:
                content = git("show", commit + ":" + path)
                destination = destination_root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
        all_env = dict(c_env, SECUREOPS_B_SOURCE_ROOT=str(baseline),
                       SECUREOPS_C_SOURCE_ROOT=str(baseline), SECUREOPS_LATEST_B_SOURCE_ROOT=str(latest))
        run("03-full-all-offline", ["-m", "unittest", "discover", "-s", "tests", "-v"], all_env,
            "Existing D 149 regressions plus 9 C ZIP tests; separately isolated source roots")
    metadata["tracked_files_unchanged"] = all(sha((ROOT / p).read_bytes()) == value for p, value in before.items())
    metadata["c_source_unchanged"] = source_before == {
        p.relative_to(source).as_posix(): sha(p.read_bytes()) for p in source.rglob("*") if p.is_file()}
    metadata["zip_unchanged"] = sha(args.zip_file.read_bytes()) == ZIP_SHA256
    metadata["finished_at_kst"] = now()
    (HERE / "environment-and-results.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
                                                        encoding="utf-8")
    return int(any(r["exit_code"] for r in metadata["runs"]) or
               not all(metadata[k] for k in ("tracked_files_unchanged", "c_source_unchanged", "zip_unchanged")))


if __name__ == "__main__":
    raise SystemExit(main())
