import json
import re
import os
from dataclasses import dataclass
from pathlib import Path

from common.ssh_client import SSHCollectionError, run_readonly
from checks.account.ssh_check import (
    load_policy, check_ssh_01, to_result_v1_2,
    make_result, RECOMMENDATIONS
)
from core.remote_result import parse_result_json
from core.main import DiagnosisAggregator
from core.storage import ReportStore

CONFIG = Path.home() / "SecureOps-local-config" / "targets.json"
# Inject an administrator-approved private root; no production path is assumed.
RESULT_DIR = None


@dataclass(frozen=True)
class StoredReport:
    path: Path
    report: dict
    summary: dict


class ReportPersistenceError(RuntimeError):
    """Sanitized storage failure, retaining the D-generated scan ID."""

    def __init__(self, stage, target_id, scan_id, save_outcome, reason):
        self.stage = stage
        self.target_id = target_id
        self.scan_id = scan_id
        self.save_outcome = save_outcome
        self.reason = reason
        super().__init__(f"Report persistence failed at {stage}")


def read_targets():
    with CONFIG.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Invalid configuration object")

    if data.get("schema_version") != "1":
        raise ValueError("Unsupported config version")

    if not isinstance(data.get("targets"), list):
        raise ValueError("Invalid targets list")

    targets = []
    seen = set()

    for target in data["targets"]:
        if not isinstance(target, dict):
            raise ValueError("Invalid target object")

        name = target.get("target_id")

        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,50}", name
        ):
            raise ValueError("Invalid target ID")

        if name in seen:
            raise ValueError("Duplicate target ID")

        seen.add(name)

        for field in ("host", "username", "os_hint", "ssh01_context"):
            value = target.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Invalid {field}: {name}")

        port = target.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"Invalid SSH port: {name}")

        if type(target.get("enabled")) is not bool:
            raise ValueError(f"Invalid enabled flag: {name}")

        if target["enabled"]:
            targets.append(target)

    return targets


def diagnose(target, policy):
    remote = run_readonly(
        target_id=target["target_id"],
        host=target["host"],
        username=target["username"],
        port=target["port"],
        operation="ssh01",
    )

    if remote.get("target_id") != target["target_id"] or remote.get("operation") != "ssh01":
        raise ValueError("SSH response identity mismatch")

    if type(remote["exit_code"]) is not int or remote["exit_code"] != 0:
        raise ValueError("SSH command failed")

    raw = json.loads(remote["stdout"])

    if not isinstance(raw, dict) or raw.get("check_id") != "SSH-01":
        raise ValueError("Invalid SSH-01 response")

    if raw.get("context") != target["ssh01_context"]:
        raise ValueError("SSH evaluation context mismatch")

    allowed = {
        "no", "yes", "without-password",
        "prohibit-password", "forced-commands-only"
    }

    if (
        raw.get("global_value") not in allowed
        or raw.get("root_value") not in allowed
    ):
        raise ValueError("Unsupported SSH setting")

    global_output = (
        f'permitrootlogin {raw["global_value"]}\n'
    )
    root_output = (
        f'permitrootlogin {raw["root_value"]}\n'
    )

    inputs = {
        "policy": policy,
        "sshd_output": global_output,
        "root_output": root_output,
        "config_text": "",
    }

    legacy = check_ssh_01(
        policy,
        global_output,
        config_text="",
        root_output=root_output,
    )

    # Full Match configuration has not been collected.
    # A single safe context cannot prove a global PASS.
    if legacy["status"] == "pass":
        legacy["status"] = "needs_review"
        legacy["evidence"] += (
            "; full Match configuration not collected"
        )
        legacy["recommendation"] = RECOMMENDATIONS["needs_review"]

    item = to_result_v1_2(legacy, inputs)

    details = item.setdefault("details", {})
    details.pop("match_rules", None)
    details["match_rules_collected"] = False

    return item


def save_report(target, item, *, output_root=None):
    wire = json.dumps(
        item, ensure_ascii=False, allow_nan=False
    )

    received = parse_result_json(
        wire,
        exit_code=0,
        execution_succeeded=True,
        schema_version="1.2",
    )

    report = DiagnosisAggregator.from_results(
        [received],
        [],
        target_id=target["target_id"],
        os=target["os_hint"],
        schema_version="1.2",
    )

    data = report.get_report()

    summary = report.aggregate_results()
    stage = "initialize"
    save_outcome = "not_attempted"
    try:
        root = output_root if output_root is not None else RESULT_DIR
        if root is None:
            root = os.environ.get("SECUREOPS_REPORT_ROOT")
        if not root:
            raise ValueError("An approved report root is required")
        store = ReportStore(root)
        stage = "save"
        # An exception can occur after publication: file absence is not implied.
        save_outcome = "unconfirmed"
        output = store.save(data)
        save_outcome = "confirmed"
        stage = "load"
        saved = store.load(data["target_id"], data["scan_id"])
        stage = "verify"
        if saved != data:
            raise ValueError("Saved report verification failed")
    except Exception as error:
        reason = "persistence_error"
        if stage == "save" and isinstance(error, FileExistsError):
            reason = "scan_id_conflict"
        elif isinstance(error, PermissionError):
            reason = "permission_denied"
        elif stage == "verify":
            reason = "report_mismatch"
        raise ReportPersistenceError(
            stage, data["target_id"], data["scan_id"], save_outcome, reason,
        ) from None

    return StoredReport(output, saved, summary)


def main(*, output_root=None):
    targets = read_targets()
    policy = load_policy()

    print("Enabled targets:", len(targets))

    outcomes = []
    for target in targets:
        collection_succeeded = True
        try:
            item = diagnose(target, policy)
        except (
            SSHCollectionError,
            ValueError,
            KeyError,
            TypeError,
            OSError,
        ):
            collection_succeeded = False
            item = to_result_v1_2(
                make_result(
                    "error",
                    policy["severity"],
                    "SSH-01 remote collection failed",
                ),
                {"policy": policy},
            )

        outcome = {
            "target_id": target["target_id"],
            "collection_succeeded": collection_succeeded,
            "diagnosis_status": item["status"],
            "scan_id": None,
            "save_outcome": "not_attempted",
            "load_succeeded": False,
            "storage_stage": None,
            "storage_error": None,
        }
        try:
            stored = save_report(target, item, output_root=output_root)
        except ReportPersistenceError as exc:
            outcome.update(scan_id=exc.scan_id, save_outcome=exc.save_outcome,
                           storage_stage=exc.stage, storage_error=exc.reason)
            print(f'{target["target_id"]}: persistence failed at {exc.stage} ({exc.reason}); scan_id={exc.scan_id}')
        except (ValueError, KeyError, TypeError, OSError, RecursionError):
            outcome["storage_stage"] = "validation"
            print(f'{target["target_id"]}: result validation failed')
        else:
            outcome.update(scan_id=stored.report["scan_id"],
                           save_outcome="confirmed", load_succeeded=True,
                           storage_stage="complete")
            print(f'{target["target_id"]}: {item["status"]} | verified scan_id={stored.report["scan_id"]}')
        outcomes.append(outcome)

    print("Central SSH-01 run completed")
    return outcomes


if __name__ == "__main__":
    try:
        outcomes = main()
    except (ValueError, KeyError, TypeError, OSError):
        print("Central SSH-01 configuration failed")
        raise SystemExit(1) from None
    raise SystemExit(0 if all(
        row["collection_succeeded"] and row["load_succeeded"] for row in outcomes
    ) else 1)
