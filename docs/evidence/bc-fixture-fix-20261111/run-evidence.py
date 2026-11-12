"""Before/after fixture evidence; does not modify tests or operational sources."""
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

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = "66495d0506391a7a259accf558c822d28be3b219"
TARGET = "tests/test_bc_offline_integration.py"


def now():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec="seconds")


def git(*args):
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(ROOT), *args], cwd=ROOT)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("before", "after"))
    args = parser.parse_args()
    destination = HERE / (args.phase + "-results.json")
    if destination.exists():
        raise FileExistsError("Preserve existing evidence")
    assert git("rev-parse", "HEAD").decode().strip() == BASE
    names = git("ls-files").decode().splitlines()
    before = {name: sha(ROOT / name) for name in names}
    data = {"phase": args.phase, "base_commit": BASE, "started_at_kst": now(),
        "python": platform.python_version(), "platform": platform.system() + " " + platform.release(),
        "jsonschema": importlib.metadata.version("jsonschema"),
        "fixture_sha256": before[TARGET], "external_source_variables_cleared": True,
        "actual_ssh_vm": False, "runs": []}
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    for name in list(environment):
        if name.startswith("SECUREOPS_") and ("SOURCE" in name or "EVIDENCE" in name):
            environment.pop(name)
    commands = [(args.phase + "-target", ["-m", "unittest", "discover", "-s", "tests", "-p", "test_bc_offline_integration.py", "-v"], environment)]
    if args.phase == "after":
        commands += [("after-default-full", ["-m", "unittest", "discover", "-s", "tests", "-v"], environment),
                     ("after-full-with-d-source", ["-m", "unittest", "discover", "-s", "tests", "-v"], dict(environment, SECUREOPS_D_SOURCE=str(ROOT)))]
    (HERE / "logs").mkdir(exist_ok=True)
    for label, arguments, selected in commands:
        started = now()
        completed = subprocess.run([sys.executable, "-B", "-X", "utf8", *arguments], cwd=ROOT, env=selected,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = completed.stdout.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        for value, replacement in ((str(ROOT), "<REPO>"), (str(Path.home()), "<USER_HOME>")):
            for spelling in (value, value.replace("\\", "/"), value.replace("\\", "\\\\")):
                text = text.replace(spelling, replacement)
        # Presentation only: remove trailing spaces; keep traceback content.
        sanitized_stdout_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
        text = "\n".join(line.rstrip() for line in text.split("\n"))
        count = re.search(r"Ran (\d+) tests? in", text)
        row = {"label": label, "command": "python -B -X utf8 " + " ".join(arguments),
               "started_at_kst": started, "finished_at_kst": now(), "exit_code": completed.returncode,
               "tests_run": int(count[1]) if count else None,
               "ok_method_lines": len(re.findall(r"^test.*\.\.\. ok$", text, re.M)),
               "log": "logs/" + label + ".log",
               "sanitized_stdout_sha256_before_space_trim": sanitized_stdout_sha256,
               "log_normalization": "UTF-8/LF; private path placeholders; trailing spaces removed",
               "explicit_d_source": label == "after-full-with-d-source"}
        for key in ("failures", "errors", "skipped"):
            match = re.search(key + r"=(\d+)", text)
            row[key] = int(match[1]) if match else 0
        row["error_headings"] = re.findall(r"^ERROR: (.+)$", text, re.M)
        (HERE / row["log"]).write_bytes((json.dumps(row) + "\n\n" + text).encode("utf-8"))
        data["runs"].append(row)
        print(json.dumps(row), flush=True)
        if args.phase == "after" and completed.returncode:
            data["unexpected_failure_stop"] = True
            break
    data["tracked_files_unchanged_during_test"] = all(sha(ROOT / name) == value for name, value in before.items())
    data["finished_at_kst"] = now()
    destination.write_bytes((json.dumps(data, indent=2) + "\n").encode())
    if args.phase == "before":
        row = data["runs"][0]
        return int(not (row["errors"] == 6 and row["failures"] == 0 and row["tests_run"] == 3))
    return int(any(row["exit_code"] for row in data["runs"]) or not data["tracked_files_unchanged_during_test"])


if __name__ == "__main__":
    raise SystemExit(main())
