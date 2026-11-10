"""D→E→D MOCK 연동. D 원본은 작업 폴더 밖의 임시 디렉터리에 준비한다.

D 기준 커밋: 994d20c1d7a914ba8a77ab9e89ea7080c16e171e (PR #8).
SECUREOPS_D_SOURCE에 이 커밋의 core/를 포함한 디렉터리를 지정한다.
이 값이 없으면 테스트를 명시적으로 건너뛴다. 보고서 저장소는 테스트마다
TemporaryDirectory로 생성·제거하며, E 조치 실행 이력은 저장하지 않는다.
"""

from copy import deepcopy
from importlib import import_module
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from remediation import Approval, MockBackend, Remediator, build_plan


class CoreRemediationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get("SECUREOPS_D_SOURCE")
        if not source:
            raise unittest.SkipTest("SECUREOPS_D_SOURCE에 고정된 D 소스 경로를 지정해야 합니다")
        root = Path(source).resolve()
        for name in ("main.py", "storage.py"):
            if not (root / "core" / name).is_file():
                raise RuntimeError(f"D 소스 누락: core/{name}")

        # 준비한 D 원본을 직접 import한다. E 브랜치에 D 파일을 복사하지 않는다.
        sys.path.insert(0, str(root))
        try:
            main = import_module("core.main")
            storage = import_module("core.storage")
        finally:
            sys.path.remove(str(root))
        for module in (main, storage):
            if not Path(module.__file__).resolve().is_relative_to(root):
                raise RuntimeError("준비한 D 소스와 실제 import 경로가 다릅니다")
        cls.Aggregator = main.DiagnosisAggregator
        cls.ReportStore = storage.ReportStore

    def setUp(self):
        self.directory = TemporaryDirectory(prefix="secureops-de-mock-")
        self.addCleanup(self.directory.cleanup)
        self.store = self.ReportStore(self.directory.name)
        self.item = {
            "check_id": "SSH-01",
            "status": "vulnerable",
            "severity": "high",
            "evidence": "MOCK: effective PermitRootLogin yes",
            "recommendation": "MOCK: request administrator approval",
        }

    def run_scenario(self, *, status="vulnerable", approved=True, fail_at=()):
        item = dict(self.item, status=status)
        before = self.Aggregator.from_results(
            [item], [], target_id="de-test-MOCK", os="ubuntu-24.04",
            scanned_at="2026-11-01T00:00:00Z",
        ).get_report()
        self.store.save(before)
        incoming = self.store.load(before["target_id"], before["scan_id"])
        original = deepcopy(incoming)

        # D가 검증·저장한 보고서를 E의 기존 인터페이스에 전달한다.
        plan = build_plan(incoming, "SSH-01")
        approval = Approval(
            "de-approval-MOCK", "de-admin-MOCK", plan.target_id, plan.scan_id,
            plan.plan_id, "2099-01-01T00:00:00Z", approved,
        )
        engine = Remediator(
            allowed_targets={plan.target_id}, allowed_checks={"SSH-01"},
            verify_approval=lambda record: record == approval,
        )
        backend = MockBackend(
            target_id=plan.target_id, os=plan.os, files={}, fail_at=fail_at,
            access_verified=True, snapshot_verified=True, include_verified=True,
        )
        result = engine.run(incoming, plan, backend=backend, approval=approval, dry_run=False)
        self.assertEqual(incoming, original)
        return before, result, backend

    def test_success_report_is_saved_and_reloaded_by_d(self):
        before, result, backend = self.run_scenario()
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["backup"], "success")
        self.assertEqual(result["rollback"], "not_needed")
        after = result["after_report"]

        # E 실행 이력 전체가 아니라 재진단 보고서만 D의 기존 저장소에 저장한다.
        self.store.save(after)
        loaded = self.store.load(before["target_id"], after["scan_id"])
        self.assertEqual(loaded, after)
        self.assertEqual(loaded["target_id"], before["target_id"])
        self.assertNotEqual(loaded["scan_id"], before["scan_id"])
        self.assertEqual(before["results"][0]["status"], "vulnerable")
        self.assertEqual(loaded["results"][0]["status"], "pass")
        self.assertTrue(result["comparison"]["improved"])
        matched = self.store.match_results(before["target_id"], before["scan_id"], loaded["scan_id"])
        self.assertEqual(matched["SSH-01"]["before"]["status"], "vulnerable")
        self.assertEqual(matched["SSH-01"]["after"]["status"], "pass")
        self.assertEqual(self.store.load(before["target_id"], before["scan_id"]), before)
        self.assertEqual(len(self.store.history(before["target_id"])), 2)
        self.assertLess(backend.events.index("backup"), backend.events.index("apply"))
        with self.assertRaises(FileExistsError):
            self.store.save(after)

    def test_no_after_report_for_rejection_exclusion_or_apply_failure(self):
        cases = (
            ({"approved": False}, "rejected", "not_needed"),
            ({"status": "needs_review"}, "skipped", "not_needed"),
            ({"fail_at": {"apply"}}, "failed", "verified"),
        )
        for options, outcome, rollback in cases:
            with self.subTest(outcome=outcome):
                before, result, backend = self.run_scenario(**options)
                self.assertEqual(result["outcome"], outcome)
                self.assertEqual(result["rollback"], rollback)
                self.assertIsNone(result["after_report"])
                self.assertEqual(self.store.load(before["target_id"], before["scan_id"]), before)
                if outcome != "failed":
                    self.assertEqual(backend.events, [])
                else:
                    self.assertEqual(backend.root_login, "yes")
                    self.assertIn("verify_service", result["completed_steps"])


if __name__ == "__main__":
    unittest.main()
