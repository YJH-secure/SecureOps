"""15 offline acceptance cases; real B/D/store, SSH boundary and explicit faults only."""

from contextlib import redirect_stdout
from datetime import datetime, timedelta
from hashlib import sha256
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import UUID

import central_ssh01_runner as runner
from common.ssh_client import SSHCollectionError
from core.storage import ReportStore


CONTEXT = "user=root,host=mock-client,addr=192.0.2.1"
TARGET = {
    "target_id": "mock-ubuntu", "host": "192.0.2.10", "username": "mock-scan",
    "port": 22, "os_hint": "ubuntu-22.04.5", "ssh01_context": CONTEXT,
    "enabled": True,
}


def response(target_id, value="without-password", exit_code=0):
    return {
        "target_id": target_id, "operation": "ssh01", "exit_code": exit_code,
        "stdout": json.dumps({"check_id": "SSH-01", "global_value": value,
                              "root_value": value, "context": CONTEXT}),
    }


class TestCentralReportStoreAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "reports"
        self.policy = runner.load_policy()
        self.target = dict(TARGET)

    def item(self, value="without-password"):
        with patch.object(runner, "run_readonly", return_value=response(self.target["target_id"], value)):
            return runner.diagnose(self.target, self.policy)

    def execute(self, targets=None, collect=None, output_root=None):
        targets = targets if targets is not None else [self.target]
        config = self.base / "targets.json"
        config.write_text(json.dumps({"schema_version": "1", "targets": targets}), encoding="utf-8")
        collect = collect or (lambda **kw: response(kw["target_id"]))
        stdout = io.StringIO()
        with patch.object(runner, "CONFIG", config), patch.object(runner, "run_readonly", side_effect=collect), redirect_stdout(stdout):
            rows = runner.main(output_root=output_root if output_root is not None else self.root)
        self.record({"outcomes": rows, "stdout": stdout.getvalue()})
        return rows, stdout.getvalue()

    def record(self, value):
        destination = os.environ.get("SECUREOPS_ACCEPTANCE_EVIDENCE")
        if destination:
            folder = Path(destination)
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / (self._testMethodName + ".json")
            entries = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
            entries.append(value)
            path.write_text(json.dumps(entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def assert_nulls(self, item, assessment):
        self.assertEqual(item["cvss"]["assessment_status"], assessment)
        for key in ("version", "vector", "base_score", "rating", "source"):
            self.assertIsNone(item["cvss"][key])

    def test_01_collection_b_d_store(self):
        rows, _ = self.execute()
        self.assertTrue(rows[0]["collection_succeeded"])
        self.assertEqual(rows[0]["storage_stage"], "complete")
        report = ReportStore(self.root).load(self.target["target_id"], rows[0]["scan_id"])
        self.assertEqual(report["schema_version"], "1.2")
        self.assertEqual(report["results"][0]["check_id"], "SSH-01")
        self.record({"report": report})

    def test_02_load_original_identity(self):
        item = self.item()
        stored = runner.save_report(self.target, item, output_root=self.root)
        loaded = ReportStore(self.root).load(self.target["target_id"], stored.report["scan_id"])
        self.assertEqual(loaded, stored.report)
        self.assertEqual(loaded["results"], [item])
        self.assertEqual(stored.path, self.root / (sha256(loaded["scan_id"].encode()).hexdigest() + ".json"))
        item["details"]["global_value"] = "changed-after-save"
        self.assertNotEqual(item, loaded["results"][0])
        self.record({"report": loaded, "summary": stored.summary})

    def test_03_ssh_connection_failure_error(self):
        def fail(**kw):
            raise SSHCollectionError("sensitive-output-sentinel")
        rows, text = self.execute(collect=fail)
        row = rows[0]
        self.assertFalse(row["collection_succeeded"])
        self.assertTrue(row["load_succeeded"])
        item = ReportStore(self.root).load(row["target_id"], row["scan_id"])["results"][0]
        self.assertEqual(item["status"], "error")
        self.assert_nulls(item, "not_applicable")
        self.assertNotIn("sensitive-output-sentinel", text + json.dumps(item))

    def test_04_nonzero_command_error(self):
        rows, _ = self.execute(collect=lambda **kw: response(kw["target_id"], exit_code=1))
        row = rows[0]
        self.assertFalse(row["collection_succeeded"])
        self.assertEqual(row["diagnosis_status"], "error")
        self.assertTrue(row["load_succeeded"])
        item = ReportStore(self.root).load(row["target_id"], row["scan_id"])["results"][0]
        self.assert_nulls(item, "not_applicable")

    def test_05_vulnerable_pending_null(self):
        item = self.item("prohibit-password")
        stored = runner.save_report(self.target, item, output_root=self.root)
        self.assertEqual(stored.report["results"][0], item)
        self.assertEqual(item["status"], "vulnerable")
        self.assert_nulls(item, "pending")
        self.assertEqual(stored.summary["metrics"]["vulnerable_count"], 1)
        self.assertEqual(stored.summary["cvss_assessment_breakdown"]["pending"], 1)
        self.assertNotIn("severity", item)
        self.record({"report": stored.report, "summary": stored.summary})

    def test_06_needs_review_details(self):
        item = self.item("no")
        stored = runner.save_report(self.target, item, output_root=self.root)
        self.assertEqual(item["status"], "needs_review")
        self.assert_nulls(item, "not_applicable")
        self.assertEqual(item["details"], {"setting": "permitrootlogin", "expected": "no",
            "global_value": "no", "root_value": "no", "root_evaluation": "sshd -T -C user=root",
            "match_rules_collected": False})
        self.assertEqual(stored.report["results"][0], item)
        self.assertEqual(stored.summary["metrics"]["needs_review_count"], 1)
        self.record({"report": stored.report, "summary": stored.summary})

    def test_07_diagnosis_error_vs_storage_error(self):
        def fail(**kw):
            raise SSHCollectionError("not logged")
        diagnostic, _ = self.execute(collect=fail)
        self.assertEqual(diagnostic[0]["diagnosis_status"], "error")
        self.assertEqual(diagnostic[0]["storage_stage"], "complete")
        blocked = self.base / "not-a-directory"
        blocked.write_text("fixture", encoding="utf-8")
        storage, _ = self.execute(output_root=blocked)
        self.assertEqual(storage[0]["diagnosis_status"], "vulnerable")
        self.assertTrue(storage[0]["collection_succeeded"])
        self.assertEqual(storage[0]["storage_stage"], "initialize")
        self.assertFalse(storage[0]["load_succeeded"])

    def test_08_save_failure_not_success(self):
        with patch.object(ReportStore, "save", side_effect=PermissionError("sensitive-path-sentinel")):
            rows, text = self.execute()
        row = rows[0]
        self.assertEqual(row["storage_stage"], "save")
        self.assertEqual(row["save_outcome"], "unconfirmed")
        self.assertFalse(row["load_succeeded"])
        self.assertNotIn("verified scan_id=", text)
        self.assertNotIn("sensitive-path-sentinel", text)
        self.assertEqual(list(self.root.glob("*.json")), [])

    def test_09_load_failure_scan_id_retained(self):
        targets = [dict(self.target, target_id="mock-load-failed"), dict(self.target, target_id="mock-next")]
        real_load = ReportStore.load
        def selective_load(store, target_id, scan_id):
            if target_id == "mock-load-failed":
                raise OSError("sensitive-path-sentinel")
            return real_load(store, target_id, scan_id)
        with patch.object(ReportStore, "load", selective_load):
            rows, text = self.execute(targets)
        row = rows[0]
        self.assertEqual(row["storage_stage"], "load")
        self.assertEqual(row["save_outcome"], "confirmed")
        self.assertFalse(row["load_succeeded"])
        UUID(row["scan_id"])
        original = ReportStore(self.root).load(row["target_id"], row["scan_id"])
        self.assertEqual(original["scan_id"], row["scan_id"])
        self.assertEqual(len(list(self.root.glob("*.json"))), 2)
        self.assertNotIn("verified scan_id=" + row["scan_id"], text)
        self.assertTrue(rows[1]["load_succeeded"])
        self.assertNotIn("sensitive-path-sentinel", text)
        self.record({"saved_report_recovered_with_same_id": original})

    def test_10_duplicate_scan_id_preserves_original(self):
        fixed = UUID("17dfb849-bfaf-45c0-ac35-54901e58bfa3")
        with patch("core.main.uuid4", return_value=fixed):
            first = runner.save_report(self.target, self.item(), output_root=self.root)
            before = first.path.read_bytes()
            with self.assertRaises(runner.ReportPersistenceError) as caught:
                runner.save_report(self.target, self.item("no"), output_root=self.root)
        self.assertEqual(caught.exception.stage, "save")
        self.assertEqual(caught.exception.reason, "scan_id_conflict")
        self.assertEqual(caught.exception.scan_id, str(fixed))
        self.assertEqual(first.path.read_bytes(), before)
        self.assertEqual(ReportStore(self.root).load(self.target["target_id"], str(fixed)), first.report)
        self.assertEqual(len(list(self.root.glob("*.json"))), 1)

    def test_11_target_id_mismatch(self):
        with patch.object(runner, "run_readonly", return_value=response("different-target")):
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                runner.diagnose(self.target, self.policy)
        stored = runner.save_report(self.target, self.item(), output_root=self.root)
        with self.assertRaises(ValueError):
            ReportStore(self.root).load("different-target", stored.report["scan_id"])

    def test_12_os_metadata_preserved(self):
        self.target["os_hint"] = "rocky-9.4"
        stored = runner.save_report(self.target, self.item(), output_root=self.root)
        self.assertEqual(stored.report["os"], self.target["os_hint"])
        self.assertEqual(stored.summary["target_info"]["os"], "rocky-9.4")
        self.assertEqual(stored.report["target_id"], self.target["target_id"])
        self.assertNotIn("ip_address", stored.report)
        self.assertNotIn(self.target["host"], json.dumps(stored.report))
        self.record({"report": stored.report, "os_source": "synthetic configured os_hint; not detected OS"})

    def test_13_uuid_utc_auto_generation(self):
        before = datetime.now().astimezone()
        first = runner.save_report(self.target, self.item(), output_root=self.root)
        second = runner.save_report(self.target, self.item(), output_root=self.root)
        after = datetime.now().astimezone()
        for stored in (first, second):
            self.assertEqual(UUID(stored.report["scan_id"]).version, 4)
            timestamp = datetime.fromisoformat(stored.report["scanned_at"])
            self.assertEqual(timestamp.utcoffset(), timedelta(0))
            self.assertLessEqual(before, timestamp)
            self.assertLessEqual(timestamp, after)
        self.assertNotEqual(first.report["scan_id"], second.report["scan_id"])
        self.record({"reports": [first.report, second.report]})

    def test_14_ssh_failure_next_target(self):
        targets = [dict(self.target, target_id="mock-down"), dict(self.target, target_id="mock-up")]
        def collect(**kw):
            if kw["target_id"] == "mock-down":
                raise SSHCollectionError("sensitive-output-sentinel")
            return response(kw["target_id"])
        rows, _ = self.execute(targets, collect)
        self.assertEqual([r["diagnosis_status"] for r in rows], ["error", "vulnerable"])
        self.assertTrue(all(r["load_succeeded"] for r in rows))
        self.assertNotEqual(rows[0]["scan_id"], rows[1]["scan_id"])
        self.assertEqual(len(list(self.root.glob("*.json"))), 2)

    def test_15_save_failure_next_target(self):
        targets = [dict(self.target, target_id="mock-blocked"), dict(self.target, target_id="mock-up")]
        real_save = ReportStore.save
        def selective_save(store, report):
            if report["target_id"] == "mock-blocked":
                raise PermissionError("sensitive-path-sentinel")
            return real_save(store, report)
        with patch.object(ReportStore, "save", selective_save):
            rows, text = self.execute(targets)
        self.assertEqual([r["storage_stage"] for r in rows], ["save", "complete"])
        self.assertFalse(rows[0]["load_succeeded"])
        self.assertTrue(rows[1]["load_succeeded"])
        self.assertTrue(all(r["collection_succeeded"] for r in rows))
        self.assertEqual(ReportStore(self.root).load(rows[1]["target_id"], rows[1]["scan_id"])["results"][0]["status"], "vulnerable")
        self.assertNotIn("sensitive-path-sentinel", text)
        self.assertEqual(len(list(self.root.glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
