"""Read-only Git checks and an optional verified PR snapshot; never stage or commit.

Run from the review worktree:
python -B -X utf8 docs/evidence/cvss-v1.2/pr-preparation/verify-and-preserve.py
Add --archive-root PATH only to export into a new, nonexisting snapshot directory.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
BASE = "d1f7534b3d0d3b9978d15bbea3ae9633eaf43d75"
SELECTED = [
    "core/main.py", "core/runner.py", "core/storage.py", "core/remote_result.py",
    "core/cvss.py", "core/cvss_validation.py", "core/cvss_assessment.py",
    "tests/test_cvss.py", "tests/test_cvss_v12.py", "tests/test_cvss_assessment.py",
    "requirements-test.txt",
]


def git(*arguments):
    return subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive-root", type=Path)
    arguments = parser.parse_args()
    assert git("branch", "--show-current").strip() == "feature/cvss-core-jhm-main-review"
    assert git("rev-parse", "HEAD").strip() == BASE
    assert git("rev-parse", "origin/main").strip() == BASE
    assert not git("diff", "--cached", "--name-only").strip(), "Unexpected staged changes"
    git("diff", "--check")
    metadata_root = ROOT / "docs/evidence/cvss-v1.2/main-review-20261110"
    metadata = json.loads((metadata_root / "environment-and-results.json").read_text(encoding="utf-8"))
    transfer = json.loads((metadata_root / "transfer-manifest.json").read_text(encoding="utf-8"))
    assert metadata["main_review_verification_passed"]
    for name, digest in metadata["tested_file_sha256"].items():
        assert sha(ROOT / name) == digest, name
    assert sha(metadata_root / "run-main-review-evidence.py") == metadata["review_wrapper_sha256"]
    for name, digest in transfer["historical_evidence_sha256"].items():
        assert sha(ROOT / name) == digest, name
    for name, digest in transfer["tracked_main_sha256_before_transfer"].items():
        if name not in SELECTED[:4]:
            assert sha(ROOT / name) == digest, name
    changed = set(git("diff", "--name-only", "origin/main").splitlines())
    assert changed == set(SELECTED[:4])
    for name, expected in metadata["branch_refs"].items():
        assert git("rev-parse", name).strip() == expected

    evidence = ROOT / "docs/evidence/cvss-v1.2"
    logs = sorted(p.relative_to(ROOT).as_posix() for p in evidence.rglob("*.log") if p.is_file())
    assert len(logs) == 21, "Expected 11 historical plus 10 main-review logs"
    for name in logs:
        subprocess.run(["git", "check-ignore", "--quiet", name], cwd=ROOT, check=True)
    (HERE / "log-paths.txt").write_text("\n".join(logs) + "\n", encoding="utf-8")
    inventory_path = HERE / "file-inventory.json"
    files = sorted(set([ROOT / name for name in SELECTED] + [
        p for p in evidence.rglob("*") if p.is_file() and p != inventory_path]))
    digests = {p.relative_to(ROOT).as_posix(): sha(p) for p in files}
    inventory = {
        "base_commit": BASE, "branch": "feature/cvss-core-jhm-main-review",
        "source_test_dependency_count": len(SELECTED),
        "ignored_log_count": len(logs), "historical_logs": 11, "main_review_logs": 10,
        "candidate_count_including_inventory": len(files) + 1,
        "inventory_self_hash_excluded": True,
        "git_diff_check_exit_code": 0, "staging_performed": False,
        "policy_and_existing_tests_unchanged": True, "reviewed_files_still_match_tested_hashes": True,
        "git_diff_stat_origin_main": git("diff", "--stat", "origin/main"),
        "git_status": git("status", "--short", "--branch"),
        "sha256": digests,
    }
    inventory_path.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    files.append(inventory_path)
    if arguments.archive_root:
        archive = arguments.archive_root.absolute()
        if archive.exists():
            raise FileExistsError("Never overwrite an existing preserved snapshot")
        archive.mkdir(parents=True, exist_ok=False)
        before = {p.relative_to(ROOT).as_posix(): sha(p) for p in files}
        for path in files:
            destination = archive / "files" / path.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
        copied = sorted(p for p in (archive / "files").rglob("*") if p.is_file())
        actual = {p.relative_to(archive / "files").as_posix(): sha(p) for p in copied}
        assert actual == before
        assert all(sha(ROOT / name) == digest for name, digest in before.items())
        manifest = {
            "restore_base_commit": BASE, "review_branch": inventory["branch"],
            "file_count": len(before), "sha256_match": True, "source_unchanged": True,
            "ignored_log_count": len(logs), "git_metadata_included": False,
            "restoration": "Apply files/ over a checkout of restore_base_commit; Git history and pinned B/C objects are needed for offline tests.",
            "sha256": before,
        }
        (archive / "snapshot-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"archive": str(archive), "files": len(before),
                          "ignored_logs": len(logs), "sha256_match": True}))
    print("git diff --check: passed; no staging/commit/push/PR/merge/rebase performed")
    print(inventory["git_diff_stat_origin_main"])
    print(inventory["git_status"])


if __name__ == "__main__":
    main()
