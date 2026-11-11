"""Submission checks; preserves earlier evidence and never runs remote collectors.

python -B -X utf8 docs/evidence/c-v12-zip-mock-20261110/submission-20261111/rerun.py --c-source-root <EXTRACTED_ROOT> --zip-file <ZIP>
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

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--c-source-root", required=True, type=Path)
    parser.add_argument("--zip-file", required=True, type=Path)
    args = parser.parse_args()
    output = HERE / "results.json"
    if output.exists():
        raise FileExistsError("Preserve existing evidence; choose a fresh submission directory")
    source = args.c_source_root.resolve()
    manifest = json.loads((HERE.parent / "zip-inspection.json").read_text(encoding="utf-8"))
    assert sha(args.zip_file) == manifest["zip_sha256"]
    for name, expected in manifest["files"].items():
        assert sha(source / Path(name).relative_to("SecureOps_C_v12_VM")) == expected
    preserved = [ROOT / p for p in git("ls-files").decode().splitlines()]
    preserved += [p for p in HERE.parent.rglob("*") if p.is_file() and HERE not in p.parents]
    preserved.append(ROOT / "tests/test_c_zip_v12_integration.py")
    before = {p: sha(p) for p in preserved}
    data = {"started_at_kst": now(), "base_commit": git("rev-parse", "HEAD").decode().strip(),
            "origin_main": git("rev-parse", "origin/main").decode().strip(),
            "branch": git("branch", "--show-current").decode().strip(),
            "python": platform.python_version(), "platform": platform.system() + " " + platform.release(),
            "jsonschema": importlib.metadata.version("jsonschema"),
            "c_source_kind": "supplied ZIP; not official C Git verification",
            "zip_sha256": manifest["zip_sha256"], "c_files_hash_matched": len(manifest["files"]),
            "actual_ssh_vm": False, "runs": []}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    for key in ("SECUREOPS_B_SOURCE_ROOT", "SECUREOPS_C_SOURCE_ROOT", "SECUREOPS_LATEST_B_SOURCE_ROOT", "SECUREOPS_C_ZIP_SOURCE_ROOT"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="secureops-draft-check-") as temporary:
        export = Path(temporary)
        baseline, latest = export / "baseline", export / "latest"
        refs = [(baseline, "cfbd37b4dbd102ec894a2150d47f751ad5c74afa", ["checks/account/ssh_check.py"]),
                (baseline, "6bb330feccfc6541bc145db9b6e18f24b4bce394", ["checks/system/" + p for p in ("file_check.py", "common.py", "policy_rules.py", "link_check.py")]),
                (latest, "3eda5a56ed3e9fd56d162676507c526ea0d1a1c1", ["checks/account/ssh_check.py", "checks/account/policies/ssh_policy.json"])]
        data["git_source_commits"] = list(dict.fromkeys(ref for _, ref, _ in refs))
        for destination, ref, paths in refs:
            for name in paths:
                p = destination / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(git("show", ref + ":" + name))
        c_env = dict(env, SECUREOPS_C_ZIP_SOURCE_ROOT=str(source))
        full_env = dict(c_env, SECUREOPS_B_SOURCE_ROOT=str(baseline), SECUREOPS_C_SOURCE_ROOT=str(baseline), SECUREOPS_LATEST_B_SOURCE_ROOT=str(latest))
        for label, pattern, configured in [("01-c-zip-nine", "test_c_zip_v12_integration.py", c_env),
                                           ("02-default-full", "test*.py", env),
                                           ("03-all-offline", "test*.py", full_env)]:
            command = ["-B", "-X", "utf8", "-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"]
            started = now()
            completed = subprocess.run([sys.executable, *command], cwd=ROOT, env=configured, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            text = completed.stdout.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            for value, replacement in [(str(export), "<GIT_EXPORT>"), (str(source), "<C_ZIP_SOURCE>"), (str(ROOT), "<REPO>"), (tempfile.gettempdir(), "<TEMP>"), (str(Path.home()), "<USER_HOME>")]:
                for spelling in (value, value.replace("\\", "/"), value.replace("\\", "\\\\")):
                    text = text.replace(spelling, replacement)
            count = re.search(r"Ran (\d+) tests? in", text)
            assert count, text[-2000:]
            row = {"command": "python " + " ".join(command), "started_at_kst": started,
                   "finished_at_kst": now(), "exit_code": completed.returncode, "tests": int(count[1]),
                   "log": label + ".log"}
            for key in ("skipped", "failures", "errors"):
                match = re.search(key + r"=(\d+)", text)
                row[key] = int(match[1]) if match else 0
            row["passed"] = row["tests"] - sum(row[k] for k in ("skipped", "failures", "errors"))
            (HERE / row["log"]).write_bytes((json.dumps(row) + "\n\n" + text).encode("utf-8"))
            data["runs"].append(row)
            print(json.dumps(row), flush=True)
    data["existing_files_unchanged"] = all(sha(p) == value for p, value in before.items())
    data["zip_unchanged"] = sha(args.zip_file) == manifest["zip_sha256"]
    data["finished_at_kst"] = now()
    output.write_bytes((json.dumps(data, indent=2) + "\n").encode("utf-8"))
    return int(not data["existing_files_unchanged"] or not data["zip_unchanged"] or any(r["exit_code"] for r in data["runs"]))


if __name__ == "__main__":
    raise SystemExit(main())
