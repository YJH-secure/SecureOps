import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core.storage import ReportStore


class ReportStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = ReportStore(Path(self.directory.name) / "private")
        self.report = {
            "schema_version": "1.1", "scan_id": "first", "target_id": "mock-server",
            "os": "ubuntu-24.04", "scanned_at": "2026-11-06T10:00:00+09:00",
            "results": [{"check_id": "FILE-01", "status": "needs_review", "severity": "high",
                         "evidence": "MOCK: review", "recommendation": "MOCK: confirm policy",
                         "details": {"files": [{"path": "/etc/shadow", "mode": "0640"}]}}],
        }

    def test_roundtrip_and_original_preservation(self):
        original = copy.deepcopy(self.report)
        path = self.store.save(self.report)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), original)
        self.assertEqual(self.store.load("mock-server", "first"), original)
        self.assertEqual(self.report, original)
        loaded = self.store.load("mock-server", "first")
        loaded["results"][0]["details"]["files"].clear()
        self.assertEqual(self.store.load("mock-server", "first"), original)

    def test_duplicate_and_other_target_same_scan(self):
        path = self.store.save(self.report)
        content = path.read_bytes()
        for target in ("mock-server", "other-server"):
            self.report["target_id"] = target
            with self.assertRaises(FileExistsError):
                self.store.save(self.report)
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual(list(self.store.root.glob("*.tmp")), [])

    def test_file_collision(self):
        path = self.store._path("first")
        path.write_text("existing", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            self.store.save(self.report)
        self.assertEqual(path.read_text(encoding="utf-8"), "existing")

    def test_history_and_matching(self):
        self.store.save(self.report)
        second = copy.deepcopy(self.report)
        second.update(scan_id="second", scanned_at="2026-11-06T11:00:00+09:00")
        second["results"][0]["status"] = "pass"
        second["results"].append({**second["results"][0], "check_id": "LOG-01"})
        self.store.save(second)
        third = copy.deepcopy(second)
        third.update(scan_id="third", target_id="other")
        self.store.save(third)
        self.assertEqual([r["scan_id"] for r in self.store.history("mock-server")], ["first", "second"])
        self.assertEqual(self.store.history("missing"), [])
        matched = self.store.match_results("mock-server", "first", "second")
        self.assertEqual(matched["FILE-01"]["before"]["status"], "needs_review")
        self.assertEqual(matched["FILE-01"]["after"]["status"], "pass")
        self.assertIsNone(matched["LOG-01"]["before"])
        with self.assertRaises(ValueError):
            self.store.match_results("mock-server", "first", "first")

    def test_bad_report_and_legacy_rejected_before_writes(self):
        for change in ({"schema_version": "1.0"}, {"results": []}, {"extra": "value"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.store.save({**self.report, **change})
        self.assertEqual(list(self.store.root.iterdir()), [])

    def test_write_and_publish_failures(self):
        original_path = self.store.save(self.report)
        content = original_path.read_bytes()
        self.report["scan_id"] = "second"
        for operation in ("os.fsync", "os.link"):
            with self.subTest(operation=operation):
                with patch("core.storage." + operation, side_effect=OSError("simulated failure")):
                    with self.assertRaises(OSError):
                        self.store.save(self.report)
                self.assertEqual(original_path.read_bytes(), content)
                self.assertFalse(self.store._path("second").exists())
                self.assertEqual(list(self.store.root.glob("*.tmp")), [])

    def test_concurrent_duplicate(self):
        def save_once(_):
            try:
                self.store.save(self.report)
                return "saved"
            except FileExistsError:
                return "duplicate"
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(save_once, range(2)))
        self.assertCountEqual(outcomes, ["saved", "duplicate"])
        self.assertEqual(self.store.load("mock-server", "first"), self.report)

    def test_path_injection_cannot_escape(self):
        self.report.update(scan_id="../../escape:C:\\secret", target_id="../server")
        path = self.store.save(self.report)
        self.assertEqual(path.parent, self.store.root)
        self.assertEqual(len(path.stem), 64)
        self.assertEqual(self.store.load("../server", self.report["scan_id"]), self.report)

    def test_sensitive_values_rejected_without_echo(self):
        for content in ({"token": "synthetic-secret"}, {"nested": [{"cookie": "synthetic-secret"}]},
                        {"text": "password=synthetic-secret"},
                        {"text": "-----BEGIN OPENSSH PRIVATE KEY-----"}):
            self.report["results"][0]["details"] = content
            with self.subTest(content=content), self.assertRaises(ValueError) as raised:
                self.store.save(self.report)
            self.assertNotIn("synthetic-secret", str(raised.exception))
        self.assertEqual(list(self.store.root.iterdir()), [])

    def test_missing_wrong_target_and_corruption(self):
        with self.assertRaises(FileNotFoundError):
            self.store.load("mock-server", "missing")
        path = self.store.save(self.report)
        with self.assertRaises(ValueError):
            self.store.load("wrong", "first")
        path.write_text("{", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.load("mock-server", "first")
        with self.assertRaises(ValueError):
            self.store.history("mock-server")

    def test_wrong_filename_and_non_json_details(self):
        path = self.store.save(self.report)
        path.rename(self.store._path("wrong"))
        with self.assertRaises(ValueError):
            self.store.history("mock-server")
        self.report["results"][0]["details"] = {"bad": (1, 2)}
        with self.assertRaises(TypeError):
            self.store.save(self.report)


if __name__ == "__main__":
    unittest.main()
