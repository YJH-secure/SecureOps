"""Package existing evidence without re-executing or changing old results."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil

HERE = Path(__file__).resolve().parent
OLD = HERE.parent
D_ROOT = HERE.parents[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ids(path):
    text = path.read_text(encoding="utf-8")
    return re.findall(r"^test\S+ \(([^)]+)\) \.\.\. ok$", text, re.M)


def write(name, value):
    (HERE / name).write_bytes((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--e-root", required=True, type=Path)
    args = parser.parse_args()
    e_root = args.e_root.resolve()
    if (HERE / "test-overlap.json").exists():
        raise FileExistsError("Preserve existing package results")
    metadata = json.loads((OLD / "final/environment-and-results.json").read_text(encoding="utf-8"))
    groups = {}
    inventory = []
    for row in metadata["runs"]:
        group = row["group"]
        test_ids = ids(OLD / "final" / row["log"])
        assert len(test_ids) == len(set(test_ids)) == row["tests_run"]
        assert row["exit_code"] == row["failures"] == row["errors"] == row["skipped"] == 0
        groups[group] = set(test_ids)
        for test_id in test_ids:
            module = test_id.rsplit(".", 2)[0]
            path = (module.replace(".", "/") + ".py") if module.startswith("checks.") else "tests/" + module + ".py"
            checkout = e_root if group in {"e-remediation", "e-history"} else D_ROOT
            source = checkout / path
            digest = hashlib.sha256(source.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            inventory.append({"group": group, "test_id": test_id,
                "source_checkout": "E_PR23" if checkout == e_root else "D_MAIN",
                "source_path": path, "source_sha256_lf": digest,
                "actual_command": row["command"], "original_log": row["log"],
                "run_started_at_kst": row["started_at_kst"], "result": "ok"})
    existing = set().union(*(groups[name] for name in ("e-remediation", "e-history", "d-cvss", "c-fw-log")))
    independent = groups["independent"]
    whole = groups["d-full"]
    union = existing | independent | whole
    comparisons = {
        "old_204_unique_ids": len(existing), "independent_unique_ids": len(independent),
        "combined_full_unique_ids": len(whole), "old204_intersect_full": len(existing & whole),
        "independent_intersect_full": len(independent & whole),
        "old204_intersect_independent": len(existing & independent),
        "occurrences_across_six_runs": len(inventory), "unique_ids_across_six_runs": len(union),
        "unique_id_and_source_file_variants": len({(r["test_id"], r["source_sha256_lf"]) for r in inventory}),
        "full_only_vs_204_and_independent": len(whole - existing - independent),
    }
    assert comparisons["old_204_unique_ids"] == 204
    assert comparisons["independent_unique_ids"] == 8
    assert comparisons["combined_full_unique_ids"] == 181
    pairwise = {}
    for name, values in groups.items():
        pairwise[name] = {other: len(values & other_values) for other, other_values in groups.items()}
    write("test-id-inventory.json", {"kind": "IDs parsed from existing actual final logs; not a new execution", "tests": inventory})
    write("test-overlap.json", {"counts": comparisons, "pairwise_intersections": pairwise,
        "old204_ids": sorted(existing), "full_overlap_with_old204_ids": sorted(existing & whole),
        "independent_ids": sorted(independent), "full_only_ids": sorted(whole - existing - independent)})
    # Inspect E's public original evidence, without copying private old logs.
    public = e_root / "reports/e-history-final-main-6bf80bb-20261111"
    public_rows = json.loads((public / "results.json").read_text(encoding="utf-8"))
    public_ids = set()
    public_logs = []
    for path in sorted(public.glob("*.log")):
        found = ids(path)
        if found:
            public_ids.update(found)
            public_logs.append({"path": path.relative_to(e_root).as_posix(), "sha256": sha(path), "ok_ids": len(found)})
    write("e-author-comparison.json", {
        "author_reported_204": 204, "author_reported_python": "3.12.14",
        "author_reported_jsonschema": "4.26.0", "author_latest_test_code_commit": "7730f4ff6d8fc666bd68093f072e7971c79e358a",
        "public_184_metadata_tested_head": public_rows.get("tested_head"),
        "public_184_metadata_d_main": public_rows.get("main_sha"),
        "public_raw_ok_ids_found": len(public_ids), "public_logs": public_logs,
        "public_ids_also_in_d_204": len(public_ids & existing),
        "public_ids_missing_from_d_204": sorted(public_ids - existing),
        "d_204_ids_not_in_public_184": sorted(existing - public_ids),
        "public_complete_latest_204_raw_stdout_available": False,
        "latest_204_original_run_time_and_interpreter_hash_independently_verified": False,
        "evidence_limit": "README/PR reports 204; public complete logs cover older 184. New 20 IDs and current code can be inspected; private final stdout is unavailable.",
    })
    # Byte-identical copies of final evidence, not relabeled as new runs.
    copied = []
    for source in sorted((OLD / "final").rglob("*")):
        if not source.is_file():
            continue
        destination = HERE / "python-3.14" / source.relative_to(OLD / "final")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        assert sha(source) == sha(destination)
        copied.append({"path": destination.relative_to(HERE).as_posix(), "sha256": sha(destination)})
    write("copied-evidence-manifest.json", {"kind": "Existing 3.14 final evidence copied exactly, not rerun", "files": copied})
    baseline = json.loads((HERE / "preservation-baseline.json").read_text())
    for path, digest in baseline["existing_files"].items():
        assert sha(D_ROOT / path) == digest, path
    write("package-build-result.json", {"built_at_utc": datetime.now(timezone.utc).isoformat(),
        "old_evidence_files_unchanged": len(baseline["existing_files"]),
        "copied_final_files": len(copied), "old_results_modified": False,
        "new_test_execution_performed_by_this_builder": False, "overlap": comparisons})
    print(json.dumps(comparisons, indent=2))
    print("Author public raw IDs:", len(public_ids), "Copied final files:", len(copied))


if __name__ == "__main__":
    main()
