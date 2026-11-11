"""Append latest-main verification without changing any historical evidence.

Run from this review worktree:
python -B -X utf8 docs/evidence/cvss-v1.2/main-review-20261110/run-main-review-evidence.py
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE_COMMIT = "d1f7534b3d0d3b9978d15bbea3ae9633eaf43d75"


def main():
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, check=True).stdout.decode().strip()
    if head != BASE_COMMIT:
        raise RuntimeError("Review HEAD differs from the approved main baseline")
    transfer = json.loads((HERE / "transfer-manifest.json").read_text(encoding="utf-8"))
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    for relative, digest in transfer["historical_evidence_sha256"].items():
        if sha(ROOT / relative) != digest:
            raise RuntimeError("Historical evidence changed")
    wrapper_before = sha(Path(__file__).resolve())
    historical_runner = HERE.parent / "run-cvss-evidence.py"
    spec = importlib.util.spec_from_file_location("_cvss_main_review_evidence", historical_runner)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Runtime configuration only: preserve the historical runner's source bytes.
    module.OUT = HERE
    module.POLICY_COMMIT = BASE_COMMIT
    result = module.main()
    metadata_path = HERE / "environment-and-results.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["historical_runner_exit_code"] = result
    metadata["policy_comparison_note"] = (
        "Historical collector compares raw Git LF blobs to CRLF checkout bytes. "
        "This review separately verifies canonical contents and exact pre/post checkout hashes.")
    for relative, record in metadata["policy_files"].items():
        blob = subprocess.run(["git", "show", BASE_COMMIT + ":" + relative],
                              cwd=ROOT, capture_output=True, check=True).stdout
        record["matches_main_after_checkout_newline_normalization"] = (
            (ROOT / relative).read_bytes().replace(b"\r\n", b"\n")
            == blob.replace(b"\r\n", b"\n"))
    metadata["verification_scope"] = "Latest origin/main review; independent from historical CVSS runs"
    metadata["main_review_base_commit"] = BASE_COMMIT
    metadata["historical_evidence_unchanged"] = all(
        sha(ROOT / relative) == digest
        for relative, digest in transfer["historical_evidence_sha256"].items())
    metadata["main_tracked_files_unchanged_except_selected_core"] = all(
        sha(ROOT / relative) == digest
        for relative, digest in transfer["tracked_main_sha256_before_transfer"].items()
        if relative not in transfer["modified_tracked_files"])
    metadata["review_wrapper_sha256"] = wrapper_before
    metadata["review_wrapper_unchanged_during_run"] = sha(Path(__file__).resolve()) == wrapper_before
    metadata["latest_bc_compatibility"] = (
        "Not retested in this run. Prior latest-B policy-input incompatibility remains unresolved. "
        "Passing offline suites use the recorded pinned historical B/C commits.")
    checks = [
        all(run["exit_code"] == 0 for run in metadata["runs"]),
        metadata["v11_validator_body_preserved"],
        metadata["tested_files_unchanged_during_run"],
        all(metadata["preserved_existing_files"].values()),
        all(record["matches_main_after_checkout_newline_normalization"]
            for record in metadata["policy_files"].values()),
        all(metadata[key] for key in (
        "historical_evidence_unchanged", "main_tracked_files_unchanged_except_selected_core",
        "review_wrapper_unchanged_during_run")),
    ]
    metadata["main_review_verification_passed"] = all(checks)
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return int(not metadata["main_review_verification_passed"])


if __name__ == "__main__":
    raise SystemExit(main())
