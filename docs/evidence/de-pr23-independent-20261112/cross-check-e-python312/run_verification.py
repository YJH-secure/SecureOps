"""Run from the temporary, combined Git checkout. Logs go next to this script."""
from datetime import datetime, timedelta, timezone
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

from jsonschema import Draft202012Validator


MAIN = "62d1bf72ef52c7455bc0c2dd624206eb8350f925"
PR = "b0ef73a1613ebc40fdd596edcbaf0413d32309b8"
TREE = "6f98efbf940ef05a8d3307835a059990c408de85"
KST = timezone(timedelta(hours=9))
ARTIFACTS = Path(__file__).resolve().parent


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def discover(pattern):
    return ["-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"]


def redact(text):
    for path, replacement in ((Path.cwd(), "<VERIFY_ROOT>"), (ARTIFACTS, "<EVIDENCE_DIR>"),
                              (Path(os.environ["TEMP"]), "<TEMP>"), (Path.home(), "<USER_HOME>")):
        for spelling in (str(path), path.as_posix()):
            text = re.sub(re.escape(spelling), lambda _: replacement, text, flags=re.I)
    return re.sub(r"(?i)[A-Z]:[/\\]Users[/\\][^/\\\r\n\"']+", "<USER_HOME>", text)


def run_group(name, args, expected):
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=os.pathsep.join(
        (str(Path.cwd()), os.environ.get("PYTHONPATH", ""))))
    env.pop("SECUREOPS_D_SOURCE", None)
    cmd = ["-B", *args]
    p = subprocess.run([sys.executable, *cmd], env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
    summaries = re.findall(r"^Ran (\d+) tests? in .*\n\s*([^\n]+)", p.stdout, flags=re.M)
    counts = {"ran": 0, "passed": 0, "failures": 0, "errors": 0, "skipped": 0}
    for number, result in summaries:
        parsed = {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", result)}
        counts["ran"] += int(number)
        for key in ("failures", "errors", "skipped"):
            counts[key] += parsed.get(key, 0)
        if result.startswith(("OK", "FAILED")):
            counts["passed"] += max(0, int(number) - sum(parsed.values()))
    display = "python " + " ".join('"' + a + '"' if "*" in a or " " in a else a for a in cmd)
    display = redact(display)
    (ARTIFACTS / f"{name}.log").write_text(
        f"$ {display}\nExit code: {p.returncode}\n\n" + redact(p.stdout), encoding="utf-8",
    )
    print(f"{name}: {counts}, exit={p.returncode}", flush=True)
    return dict(name=name, command=display, expected=expected, exit_code=p.returncode, **counts)


def main():
    if (git("rev-parse", "HEAD") != PR or git("rev-parse", "MERGE_HEAD") != MAIN
            or git("write-tree") != TREE or git("diff", "--name-only")):
        raise SystemExit("Verification checkout does not match the pinned tree.")
    checker = Draft202012Validator.FORMAT_CHECKER
    if checker.conforms("not-a-date", "date-time"):
        raise SystemExit("jsonschema date-time validation is unavailable.")
    started = datetime.now(KST).isoformat()
    groups = [
        ("01-e-v11", ["tests/run_de_mock.py", "--d-ref", MAIN], 24),
        ("02-e-v12", discover("test_remediation_v12.py"), 18),
        ("03-e-execution", discover("test_remediation_execution_integration.py"), 19),
        ("04-d-cvss", discover("test_cvss*.py"), 52),
        ("05-b-contract", discover("test_remediation_b_v12_integration.py"), 4),
        ("06-e-history", discover("test_remediation_execution_history.py"), 20),
        ("07-e-store", discover("test_execution_history_store.py"), 18),
        ("08-c-firewall", ["-m", "unittest", "checks.system.tests.test_firewall_check", "-v"], 17),
        ("09-c-log", ["-m", "unittest", "checks.system.tests.test_log_check", "-v"], 12),
        ("10-e-history-fields", discover("test_execution_history_fields.py"), 10),
        ("11-e-history-versions", discover("test_execution_history_versions.py"), 10),
        ("12-full-mock-flow", [str(ARTIFACTS / "verify_flow.py")], 4),
    ]
    rows = [run_group(*group) for group in groups]
    out = dict(main_sha=MAIN, pr_sha=PR, combined_tree=TREE, started_kst=started,
               finished_kst=datetime.now(KST).isoformat(), os=platform.platform(),
               python=platform.python_version(), jsonschema=metadata.version("jsonschema"),
               groups=rows)
    (ARTIFACTS / "results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return int(any(row["exit_code"] or row["passed"] != row["expected"] for row in rows))


if __name__ == "__main__":
    sys.exit(main())
