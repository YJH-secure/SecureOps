import json
import re
from pathlib import Path

from common.ssh_client import SSHCollectionError, run_readonly
from checks.account.ssh_check import (
    load_policy, check_ssh_01, to_result_v1_2,
    make_result, RECOMMENDATIONS
)
from core.remote_result import parse_result_json
from core.main import DiagnosisAggregator

CONFIG = Path.home() / "SecureOps-local-config" / "targets.json"
RESULT_DIR = Path.home() / "SecureOps-results"


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

    if remote["exit_code"] != 0:
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


def save_report(target, item):
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

    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    filename = (
        f'SSH01_{target["target_id"]}_{data["scan_id"]}.json'
    )
    output = RESULT_DIR / filename

    with output.open("x", encoding="utf-8") as f:
        f.write(report.to_json() + "\n")

    with output.open("r", encoding="utf-8") as f:
        saved = json.load(f)

    if saved != data:
        raise ValueError("Saved report verification failed")

    return output


def main():
    targets = read_targets()
    policy = load_policy()

    print("Enabled targets:", len(targets))

    for target in targets:
        try:
            item = diagnose(target, policy)
        except (
            SSHCollectionError,
            ValueError,
            KeyError,
            TypeError,
            OSError,
        ) as exc:
            item = to_result_v1_2(
                make_result(
                    "error",
                    policy["severity"],
                    "SSH-01 remote collection failed: "
                    + type(exc).__name__,
                ),
                {"policy": policy},
            )

        output = save_report(target, item)

        print(
            f'{target["target_id"]}: '
            f'{item["status"]} | '
            f'saved: {output.name}'
        )

    print("Central SSH-01 run completed")


if __name__ == "__main__":
    main()
