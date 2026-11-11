"""B/C 실제 판정 함수와 D 계층의 오프라인 통합 회귀 테스트.

확인할 수 없는 데스크탑 원본을 복원한 코드가 아니라 새로 작성한 테스트다.
기본적으로 현재 저장소의 B/C 소스를 사용한다. 별도 소스 트리는
SECUREOPS_B_SOURCE_ROOT / SECUREOPS_C_SOURCE_ROOT에 저장소 루트를 지정한다.
테스트는 Git 조회, 정책 파일 읽기, 서버 수집, 외부 명령을 수행하지 않는다.
정책의 approved 값은 테스트용 합성이며 실제 운영 승인을 의미하지 않는다.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, call, patch

from core.main import DiagnosisAggregator
from core.remote_result import parse_result_json
from core.runner import run_target
from core.storage import ReportStore


ROOT = Path(__file__).resolve().parents[1]


def _load_module(name, path):
    if not path.is_file():
        raise unittest.SkipTest(f"B/C 소스 없음: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        raise unittest.SkipTest(f"B/C 소스 또는 의존 패키지 없음: {exc.name} ({path})") from exc
    return module


class BCOfflineIntegrationTests(unittest.TestCase):
    def setUp(self):
        # 별도 패키지 이름으로 불러와 checks 및 다른 테스트의 import를 방해하지 않는다.
        modules = patch.dict(sys.modules)
        modules.start()
        self.addCleanup(modules.stop)
        b_root = Path(os.environ.get("SECUREOPS_B_SOURCE_ROOT", ROOT))
        c_root = Path(os.environ.get("SECUREOPS_C_SOURCE_ROOT", ROOT))
        self.b = _load_module("_bc_offline_ssh", b_root / "checks/account/ssh_check.py")
        package = types.ModuleType("_bc_offline_system")
        package.__path__ = [str(c_root / "checks/system")]
        sys.modules[package.__name__] = package
        self.c = _load_module(package.__name__ + ".file_check",
                              c_root / "checks/system/file_check.py")

        # 모든 시나리오에서 실수로 수집 경로에 들어가면 실패시킨다.
        for module, names in ((self.b, ("find_sshd", "get_sshd_output", "read_config_text")),
                              (self.c, ("collect_file_info", "environment_info"))):
            for name in names:
                guard = patch.object(module, name, side_effect=AssertionError("실제 수집 금지"))
                mocked = guard.start()
                self.addCleanup(guard.stop)
                self.addCleanup(mocked.assert_not_called)
        for target in ("subprocess.Popen", "os.system", "socket.socket"):
            guard = patch(target, side_effect=AssertionError("외부 명령·네트워크 금지"))
            mocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mocked.assert_not_called)

        self.b_policy = {
            "check_id": "SSH-01", "description": "MOCK SSH policy", "severity": "high",
            "criteria": {"type": "sshd_effective_setting", "operator": "equals",
                         "setting": "PermitRootLogin", "expected": "no",
                         "vulnerable_values": {
                             "yes": "root login is allowed with password and public key authentication",
                             "prohibit-password": "root login is allowed with public key authentication (password login blocked)",
                             "without-password": "legacy name of prohibit-password; root login is allowed with public key authentication",
                             "forced-commands-only": "root login is allowed with public key authentication for forced commands only",
                         },
                         "test_connection": {"user": "root", "host": "mock-offline.invalid",
                                             "addr": "192.0.2.10"}},
        }
        self.c_policy = {
            "check_id": "FILE-01", "description": "MOCK file policy", "severity": "high",
            "criteria": {"files": [
                {"path": "/etc/passwd", "expected_uid": 0, "reference_gid": 0,
                 "allowed_permission_bits": "0644", "approval_status": "approved"},
                {"path": "/etc/shadow", "expected_uid": 0, "reference_gid": 0,
                 "allowed_permission_bits": "0600", "approval_status": "approved"},
            ]},
        }
        self.observations = {
            "/etc/passwd": {"path": "/etc/passwd", "uid": 0, "gid": 0,
                            "mode": "0644", "file_type": "regular",
                            "acl": {"state": "collected",
                                    "raw": "user::rw-\ngroup::r--\nother::r--\n"}},
            "/etc/shadow": {"path": "/etc/shadow", "uid": 0, "gid": 0,
                            "mode": "0600", "file_type": "regular",
                            "acl": {"state": "collected",
                                    "raw": "user::rw-\ngroup::---\nother::---\n"}},
        }
        self.environment = {"id": "ubuntu", "version_id": "24.04",
                            "named_groups": {}, "group_lookup_state": "collected"}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output_root = Path(directory.name)

    def _run(self, sshd_output="permitrootlogin no\n", scan_id="offline-bc"):
        inputs = (self.b_policy, self.c_policy, self.observations, self.environment)
        before = copy.deepcopy(inputs)
        originals = []
        snapshots = []
        collector = Mock(side_effect=lambda path: self.observations[path])

        def receive(callback):
            # 실제 판정 결과를 JSON 전송 형태로 왕복하되 전송 계층은 호출하지 않는다.
            item = callback()
            originals.append(item)
            snapshots.append(copy.deepcopy(item))
            parsed = parse_result_json(json.dumps(item, ensure_ascii=False),
                                       exit_code=0, execution_succeeded=True)
            self.assertEqual(parsed, item)
            return parsed

        result = run_target(
            account_checks=[lambda: receive(lambda: self.b.check_ssh_01(
                self.b_policy, sshd_output, config_text=""))],
            system_checks=[lambda: receive(lambda: self.c.run(
                self.c_policy, collector=collector, environment=self.environment))],
            target_id="offline-synthetic", os="ubuntu-24.04", mode="mock",
            output_root=self.output_root, scan_id=scan_id,
            scanned_at="2026-11-09T10:00:00+09:00",
        )
        self.assertEqual(collector.call_args_list, [call(path) for path in self.observations])
        self.assertEqual(inputs, before, "B/C 입력 정책·관측값·환경은 보존되어야 한다")
        self.assertEqual(originals, snapshots, "B/C 반환 원본은 보존되어야 한다")
        self.assertEqual(result.report["results"], snapshots)
        self.assertEqual(result.report["schema_version"], "1.1")
        self.assertEqual(result.path.parent, self.output_root / "mock")
        self.assertNotIn("metrics", result.report)
        loaded = DiagnosisAggregator(str(result.path))
        self.assertEqual(loaded.get_report(), result.report)
        self.assertEqual(loaded.aggregate_results(), result.summary)
        self.assertEqual(ReportStore(result.path.parent).load("offline-synthetic", scan_id),
                         result.report)
        self.assertEqual(json.loads(result.path.read_text(encoding="utf-8")), result.report)
        return result, originals

    def _assert_counts(self, result, *, passed, vulnerable=0, error=0, review=0):
        metrics = result.summary["metrics"]
        for key, expected in {"total_items": 2, "pass_count": passed,
                              "vulnerable_count": vulnerable, "error_count": error,
                              "needs_review_count": review, "na_count": 0,
                              "evaluable_items": passed + vulnerable}.items():
            self.assertEqual(metrics[key], expected, key)
        rate = (f"{round(passed / (passed + vulnerable) * 100, 1)}%"
                if passed + vulnerable else "N/A (계산 불가)")
        self.assertEqual(metrics["pass_rate"], rate)
        self.assertEqual(result.summary["severity_breakdown"],
                         {"critical": 0, "high": vulnerable, "medium": 0, "low": 0})

    def test_actual_bc_functions_to_validated_report_summary_and_storage(self):
        result, _ = self._run(sshd_output="permitrootlogin yes\n")
        self.assertEqual([r["check_id"] for r in result.report["results"]], ["SSH-01", "FILE-01"])
        self.assertEqual([r["status"] for r in result.report["results"]], ["vulnerable", "pass"])
        self._assert_counts(result, passed=1, vulnerable=1)

    def test_file_details_and_inputs_preserved_without_shared_mutation(self):
        shadow = self.c_policy["criteria"]["files"][1]
        shadow.update(expected_uid=None, reference_gid=None, allowed_permission_bits=None,
                      approval_status="pending")
        result, originals = self._run()
        details = result.report["results"][1]["details"]
        self.assertEqual(details, originals[1]["details"])
        self.assertEqual(details["environment"], self.environment)
        self.assertEqual([f["status"] for f in details["files"]], ["pass", "needs_review"])
        for item in details["files"]:
            self.assertEqual(item["actual"], self.observations[item["path"]])
            self.assertTrue(item["checks"])
        self._assert_counts(result, passed=1, review=1)
        expected = copy.deepcopy(result.report)
        originals[1]["details"]["files"].clear()
        self.observations["/etc/passwd"]["acl"]["raw"] = "MOCK changed after run"
        self.assertEqual(result.report, expected)
        self.assertEqual(DiagnosisAggregator(str(result.path)).get_report(), expected)
        result.report["results"][1]["details"]["files"].clear()
        self.assertEqual(DiagnosisAggregator(str(result.path)).get_report(), expected)

    def test_pass_error_and_needs_review_are_counted_independently(self):
        for index, (ssh, file_state, statuses, counts) in enumerate((
            ("", "pending", ["error", "needs_review"], dict(passed=0, error=1, review=1)),
            ("permitrootlogin no\n", "error", ["pass", "error"], dict(passed=1, error=1)),
            ("permitrootlogin prohibit-password\n", "pass", ["vulnerable", "pass"],
             dict(passed=1, vulnerable=1)),
            ("permitrootlogin no\n", "pass", ["pass", "pass"], dict(passed=2)),
        )):
            with self.subTest(statuses=statuses):
                policy = copy.deepcopy(self.c_policy)
                observations = copy.deepcopy(self.observations)
                try:
                    if file_state == "pending":
                        self.c_policy["criteria"]["files"][1].update(
                            expected_uid=None, reference_gid=None, allowed_permission_bits=None,
                            approval_status="pending")
                    elif file_state == "error":
                        self.observations["/etc/shadow"]["acl"] = {
                            "state": "error", "detail": "MOCK unavailable ACL"}
                    result, _ = self._run(ssh, scan_id=f"offline-status-{index}")
                    self.assertEqual([r["status"] for r in result.report["results"]], statuses)
                    self._assert_counts(result, **counts)
                finally:
                    self.c_policy, self.observations = policy, observations


if __name__ == "__main__":
    unittest.main()
