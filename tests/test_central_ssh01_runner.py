import io
import json
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import central_ssh01_runner as runner
from common.ssh_client import SSHCollectionError
from core.storage import ReportStore


CONTEXT = "user=root,host=198.51.100.5,addr=198.51.100.5"

BASE = {
    "target_id": "mock-linux",
    "host": "192.0.2.10",
    "port": 22,
    "username": "secureops-scan",
    "os_hint": "ubuntu-22.04.5",
    "ssh01_context": CONTEXT,
    "enabled": True,
}


def ssh_response(target_id, value):
    return {
        "target_id": target_id,
        "operation": "ssh01",
        "exit_code": 0,
        "stdout": json.dumps({
            "check_id": "SSH-01",
            "global_value": value,
            "root_value": value,
            "context": CONTEXT,
        }),
    }


def execute_mock(targets, fake_ssh):
    with TemporaryDirectory() as directory:
        submitted = {}
        real_save = ReportStore.save

        def capture_save(store, report):
            submitted[(report["target_id"], report["scan_id"])] = deepcopy(report)
            return real_save(store, report)

        with (
            patch.object(runner, "read_targets", return_value=targets),
            patch.object(runner, "run_readonly", side_effect=fake_ssh),
            patch.object(runner, "RESULT_DIR", Path(directory)),
            patch.object(ReportStore, "save", capture_save),
            redirect_stdout(io.StringIO()),
        ):
            outcomes = runner.main()

        reports = {}

        store = ReportStore(directory)
        for outcome in outcomes:
            if outcome["save_outcome"] != "confirmed" or not outcome["load_succeeded"]:
                raise AssertionError("Expected verified report persistence")
            data = store.load(outcome["target_id"], outcome["scan_id"])
            if data != submitted[(outcome["target_id"], outcome["scan_id"])]:
                raise AssertionError("Loaded report differs from submitted report")
            if store.history(outcome["target_id"]) != [data]:
                raise AssertionError("Expected one immutable report per target")
            reports[data["target_id"]] = data

        return reports


class TestCentralSSH01Runner(unittest.TestCase):

    def test_vulnerable_configuration(self):
        target = dict(BASE)

        def fake_ssh(**kwargs):
            return ssh_response(
                kwargs["target_id"], "without-password"
            )

        reports = execute_mock([target], fake_ssh)

        self.assertEqual(len(reports), 1)

        data = reports["mock-linux"]
        item = data["results"][0]

        self.assertEqual(data["schema_version"], "1.2")
        self.assertEqual(item["check_id"], "SSH-01")
        self.assertEqual(item["status"], "vulnerable")

    def test_safe_setting_requires_match_review(self):
        target = dict(BASE)

        def fake_ssh(**kwargs):
            return ssh_response(kwargs["target_id"], "no")

        reports = execute_mock([target], fake_ssh)

        item = reports["mock-linux"]["results"][0]

        self.assertEqual(item["status"], "needs_review")
        self.assertFalse(
            item["details"]["match_rules_collected"]
        )

    def test_failure_does_not_stop_other_target(self):
        down = dict(
            BASE, target_id="mock-down", host="192.0.2.11"
        )
        up = dict(
            BASE, target_id="mock-up", host="192.0.2.12"
        )

        def fake_ssh(**kwargs):
            if kwargs["target_id"] == "mock-down":
                raise SSHCollectionError("Simulated SSH failure")

            return ssh_response(
                kwargs["target_id"], "without-password"
            )

        reports = execute_mock([down, up], fake_ssh)

        self.assertEqual(len(reports), 2)

        self.assertEqual(
            reports["mock-down"]["results"][0]["status"],
            "error",
        )

        self.assertEqual(
            reports["mock-up"]["results"][0]["status"],
            "vulnerable",
        )

        self.assertNotEqual(
            reports["mock-down"]["scan_id"],
            reports["mock-up"]["scan_id"],
        )


if __name__ == "__main__":
    unittest.main()
