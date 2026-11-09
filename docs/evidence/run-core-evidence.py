"""D 테스트 증거 재생성. 기능/테스트/정책 파일을 변경하지 않는다.

실행: python -B -X utf8 docs/evidence/run-core-evidence.py
네트워크 접근 없이 로컬 Git 추적 소스를 임시 디렉터리에 읽어 사용한다.
로그에서는 로컬 저장소/임시 디렉터리의 절대 경로를 치환한다.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/evidence"
LOGS = EVIDENCE / "logs"
KST = timezone(timedelta(hours=9))


def now():
    return datetime.now(KST).isoformat(timespec="seconds")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True).stdout


def fingerprints():
    paths = sorted([*ROOT.joinpath("core").glob("*.py"),
                    *ROOT.joinpath("tests").rglob("*.py"),
                    *ROOT.joinpath("tests").rglob("*.json")])
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths}


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    replacements = [(str(ROOT), "<REPO>"), (str(Path(tempfile.gettempdir())), "<TEMP>")]

    def sanitize(text):
        for path, marker in replacements:
            for variant in (path, path.replace("\\", "/"), path.replace("\\", "\\\\")):
                text = text.replace(variant, marker)
        return text

    metadata = {
        "started_at_kst": now(),
        "branch": git("branch", "--show-current").decode().strip(),
        "head": git("rev-parse", "HEAD").decode().strip(),
        "initial_git_status": sanitize(git("status", "--short", "--branch").decode("utf-8")),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "os": platform.system(), "os_release": platform.release(),
        "architecture": platform.machine(),
        "unittest": "Python standard library",
        "network_fetch": False, "ssh_vm_executed": False,
        "input_sha256_before": fingerprints(), "runs": [],
    }
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    for name in ("SECUREOPS_B_SOURCE_ROOT", "SECUREOPS_C_SOURCE_ROOT"):
        env.pop(name, None)

    def run(label, pattern, environment):
        arguments = ["-B", "-X", "utf8", "-m", "unittest", "discover",
                     "-s", "tests", "-p", pattern, "-v"]
        started = now()
        completed = subprocess.run([sys.executable, *arguments], cwd=ROOT, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = sanitize(completed.stdout.decode("utf-8", errors="replace"))
        command = "python " + " ".join(arguments)
        log_path = LOGS / (label + ".log")
        log_path.write_text(
            f"Started (KST): {started}\nCommand: {command}\n"
            f"B/C source mode: {'temporary local Git snapshot' if 'SECUREOPS_B_SOURCE_ROOT' in environment else 'current working tree'}\n"
            f"Exit code: {completed.returncode}\n\n{output}", encoding="utf-8")
        count = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", output)
        skipped = re.search(r"OK \(skipped=(\d+)\)", output)
        record = {"label": label, "command": command, "started_at_kst": started,
                  "finished_at_kst": now(), "exit_code": completed.returncode,
                  "discovered": int(count[1]) if count else None,
                  "seconds": float(count[2]) if count else None,
                  "skipped": int(skipped[1]) if skipped else 0,
                  "log": log_path.relative_to(EVIDENCE).as_posix()}
        metadata["runs"].append(record)
        print(json.dumps(record, ensure_ascii=False))

    for label, pattern in (
        ("01-mock-runner", "test_core_runner.py"),
        ("02-json-validation-aggregation", "test_core.py"),
        ("03-result-integration", "test_core_integration.py"),
        ("04-storage", "test_core_storage.py"),
        ("05-legacy", "test_core_legacy.py"),
        ("06-remote-json", "test_remote_result.py"),
        ("07-full-working-tree", "test*.py"),
    ):
        run(label, pattern, env)

    sources = {
        "B": ("origin/feature/account-check-cjw", ["checks/account/ssh_check.py"]),
        "C": ("origin/feature/system-check-ksh", ["checks/system/file_check.py",
              "checks/system/common.py", "checks/system/policy_rules.py", "checks/system/link_check.py"]),
    }
    metadata["bc_sources"] = {}
    try:
        with tempfile.TemporaryDirectory(prefix="secureops-bc-evidence-") as directory:
            snapshot = Path(directory)
            replacements.insert(0, (str(snapshot), "<BC_SOURCE_ROOT>"))
            for area, (ref, paths) in sources.items():
                commit = git("rev-parse", ref).decode().strip()
                entry = {"ref": ref, "commit": commit, "sha256": {}}
                metadata["bc_sources"][area] = entry
                for relative in paths:
                    content = git("show", f"{commit}:{relative}")
                    destination = snapshot / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    entry["sha256"][relative] = hashlib.sha256(content).hexdigest()
            offline_env = dict(env, SECUREOPS_B_SOURCE_ROOT=str(snapshot),
                               SECUREOPS_C_SOURCE_ROOT=str(snapshot))
            run("08-bc-offline-integration", "test_bc_offline_integration.py", offline_env)
            run("09-full-bc-offline", "test*.py", offline_env)
    except subprocess.CalledProcessError:
        # Git stderr나 환경변수를 남기지 않고 미실행 사유만 기록한다.
        metadata["bc_not_executed_reason"] = "로컬 B/C 추적 소스를 읽을 수 없어 오프라인 테스트 미실행."

    metadata["official_mock_ref"] = "origin/main"
    metadata["official_mock_commit"] = git("rev-parse", "origin/main").decode().strip()
    metadata["input_sha256_after"] = fingerprints()
    metadata["feature_and_test_inputs_unchanged"] = (
        metadata["input_sha256_before"] == metadata["input_sha256_after"])
    metadata["finished_at_kst"] = now()
    metadata["final_git_status"] = sanitize(git("status", "--short", "--branch").decode("utf-8"))
    (EVIDENCE / "environment-and-results.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return int(any(run["exit_code"] != 0 for run in metadata["runs"])
               or not metadata["feature_and_test_inputs_unchanged"])


if __name__ == "__main__":
    raise SystemExit(main())
