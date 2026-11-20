"""
중앙 연동 어댑터 Mock 테스트

실제 서버에 접속하거나 명령을 실행하지 않습니다.
가짜 수집 payload를 만들어 어댑터에 넣고 확인합니다.
  1) 같은 데이터면 기존 단독 실행(run_check)과 판정이 같은지
  2) 수집 실패를 빈 값이나 pass로 추정하지 않는지 (특히 SSH-02 설정 파일 읽기 실패)
  3) 정책에 없는 계정·경로는 판정에 쓰지 않는지

실행: python -m unittest test_central_adapter -v
"""

import json
import os
import tempfile
import unittest
from unittest import mock

import acc_password_check as acc01
import central_adapter as adapter
import ssh_auth_check
from test_account_checks import (ERROR, FakeSystem, GOOD_AGING, ROCKY_SYSTEM_AUTH_FAILLOCK,
                                 rocky_fs, ubuntu_fs, ubuntu_vm_fs)
from test_ssh_auth_check import make_output

CONTEXT = {"host": "192.0.2.10", "addr": "192.0.2.10"}   # 문서용 IP (실제 서버 아님)
SSH_POLICY = ssh_auth_check.load_policy()
SSH_USERS = SSH_POLICY["criteria"]["test_connection"]["users"]
GOOD_SSHD = make_output(allowusers=["secureops-scan", "secureops-fix"])

CHAGE_GOOD = (
    "Last password change\t\t\t\t\t: Nov 12, 2026\n"
    "Password expires\t\t\t\t\t: Feb 10, 2027\n"
    "Minimum number of days between password change\t\t: 1\n"
    "Maximum number of days between password change\t\t: 90\n"
    "Number of days of warning before password expires\t: 7\n"
)


# ---------- 가짜 수집 기록 만들기 ----------
def ok(text):
    return {"state": "ok", "text": text}


# 테스트용 파일 사전(None=없음, ERROR=읽기 실패)을 수집 기록 사전으로 바꿉니다.
def to_records(fs):
    records = {}
    for path, value in fs.items():
        if value is ERROR:
            records[path] = {"state": "error"}
        elif value is None:
            records[path] = {"state": "missing"}
        else:
            records[path] = ok(value)
    return records


def acc_payload(fs, conf_d=None, chage=None):
    fs = dict(fs, **(conf_d or {}))
    records = to_records(fs)
    return {
        "os_release": records.pop("/etc/os-release"),
        "files": records,
        "pwquality_conf_d": {"state": "ok", "paths": sorted(conf_d or {})},
        "chage": chage or {},
    }


def ssh_payload(**changes):
    payload = {
        "sshd_installed": True,
        "sshd_T": ok(GOOD_SSHD),
        "sshd_config": ok(""),
        "sshd_T_C": {user: ok(GOOD_SSHD) for user in SSH_USERS},
    }
    payload.update(changes)
    return payload


# 실제 명령이 실행되면 바로 실패하도록 막고 어댑터를 부릅니다.
def judge(check_id, payload, context=None, version="1.1", policy_path=None):
    with mock.patch("subprocess.run", side_effect=AssertionError("no real command")):
        return adapter.judge_payload(check_id, payload, context,
                                     policy_path=policy_path, result_version=version)


# ==================================================
# 수집 기록 -> 상태값
# ==================================================
class RecordTest(unittest.TestCase):
    def test_state_mapping(self):
        cases = [
            (ok("x"), ("ok", "x")),
            ({"state": "missing"}, ("missing", None)),
            ({"state": "error"}, ("error", None)),
            ({"state": "timeout"}, ("error", None)),
            ({"state": "truncated", "text": "part"}, ("error", None)),   # 절단 출력은 쓰지 않음
            ({"state": "unknown"}, ("error", None)),
            ({"state": "ok"}, ("error", None)),                          # ok인데 내용 없음
            ({"state": "ok", "text": "x", "exit_code": 0}, ("ok", "x")),
            ({"state": "ok", "text": "x", "exit_code": 1}, ("error", None)),     # ok와 종료 코드 불일치
            ({"state": "ok", "text": "x", "exit_code": None}, ("error", None)),  # 종료 코드 미확인
            ({"state": "ok", "text": "x", "exit_code": False}, ("error", None)), # bool은 종료 코드 아님
            ({"state": "ok", "text": "x", "exit_code": "0"}, ("error", None)),
            ({"state": "ok", "text": "x", "timeout": True}, ("error", None)),
            ({"state": "ok", "text": "x", "truncated": True}, ("error", None)),
            ({"state": "ok", "text": "x", "timeout": False, "truncated": False}, ("ok", "x")),
            (None, ("error", None)),
            ("text", ("error", None)),
        ]
        for record, expected in cases:
            with self.subTest(record=record):
                self.assertEqual(adapter.normalize_record(record), expected)


# ==================================================
# SSH-02
# ==================================================
class SshAdapterTest(unittest.TestCase):
    def test_same_result_as_direct_judge(self):
        direct = ssh_auth_check.check_ssh_02(SSH_POLICY, GOOD_SSHD, "",
                                             {u: GOOD_SSHD for u in SSH_USERS})
        result = judge("SSH-02", ssh_payload(), CONTEXT)
        self.assertEqual(result, direct)
        self.assertEqual(result["status"], "pass")

    def test_config_read_failure_is_error_not_empty_config(self):
        # 판정 함수에 빈 설정을 직접 넣으면 pass가 나오는 상황 (발견 사항)
        direct = ssh_auth_check.check_ssh_02(SSH_POLICY, GOOD_SSHD, "",
                                             {u: GOOD_SSHD for u in SSH_USERS})
        self.assertEqual(direct["status"], "pass")
        # 어댑터는 읽기 실패를 먼저 error로 막아야 함
        for record in ({"state": "error"}, {"state": "timeout"}, {"state": "missing"},
                       {"state": "truncated"}, None):
            with self.subTest(record=record):
                payload = ssh_payload(sshd_config=record)
                if record is None:
                    del payload["sshd_config"]
                result = judge("SSH-02", payload, CONTEXT)
                self.assertEqual(result["status"], "error")
                self.assertIn("sshd configuration", result["evidence"])

    def test_context_is_required_and_validated(self):
        for context in (None, {}, {"host": "h"}, {"host": "a,b", "addr": "192.0.2.10"},
                        {"host": "h", "addr": "192.0.2.10 x"}):
            with self.subTest(context=context):
                self.assertEqual(judge("SSH-02", ssh_payload(), context)["status"], "error")

    def test_sshd_not_installed(self):
        self.assertEqual(judge("SSH-02", ssh_payload(sshd_installed=False), CONTEXT)["status"],
                         "not_applicable")

    def test_global_collection_failure(self):
        result = judge("SSH-02", ssh_payload(sshd_T={"state": "timeout"}), CONTEXT)
        self.assertEqual(result["status"], "error")

    def test_only_policy_users_are_used(self):
        outputs = {SSH_USERS[0]: ok(GOOD_SSHD), "attacker": ok(make_output(passwordauthentication="yes"))}
        result = judge("SSH-02", ssh_payload(sshd_T_C=outputs), CONTEXT)
        self.assertEqual(result["details"]["users"], SSH_USERS)        # 정책 계정만
        missing = [f for f in result["details"]["findings"] if f["setting"] == "sshd -T -C"]
        self.assertEqual([f["user"] for f in missing], SSH_USERS[1:])   # 수집 안 된 계정은 error 항목
        self.assertEqual(result["status"], "error")

    def test_item_error_and_overall_status_are_different(self):
        # 효민님 독립 검증 R5: 한 계정 수집 실패 + 다른 계정 취약 -> 전체 vulnerable, 실패는 항목에 남음
        outputs = {SSH_USERS[0]: {"state": "timeout"},
                   SSH_USERS[1]: ok(make_output(passwordauthentication="yes"))}
        result = judge("SSH-02", ssh_payload(sshd_T_C=outputs), CONTEXT)
        self.assertEqual(result["status"], "vulnerable")
        statuses = {f["status"] for f in result["details"]["findings"]}
        self.assertIn("error", statuses)

    def test_v1_2_format(self):
        result = judge("SSH-02", ssh_payload(sshd_T_C={u: ok(make_output(passwordauthentication="yes"))
                                                       for u in SSH_USERS}), CONTEXT, version="1.2")
        self.assertEqual(result["status"], "vulnerable")
        self.assertNotIn("severity", result)
        self.assertEqual(result["cvss"]["assessment_status"], "pending")
        self.assertIsNone(result["cvss"]["base_score"])


# ==================================================
# ACC-01
# ==================================================
class Acc01AdapterTest(unittest.TestCase):
    def setUp(self):
        # 대화형 계정 1개(user1)를 넣은 임시 정책 (실제 정책 파일은 바꾸지 않음)
        with open(acc01.POLICY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        data["policies"][0]["criteria"]["interactive_accounts"] = ["user1"]
        handle, self.policy_path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def tearDown(self):
        os.remove(self.policy_path)

    def test_same_result_as_run_check(self):
        cases = {
            "good": (ubuntu_fs(), {}),
            "vm_default": (ubuntu_vm_fs(), {}),
            "conf_d": (ubuntu_fs(), {"/etc/security/pwquality.conf.d/50-local.conf": "minlen = 12\n"}),
            "rocky": (rocky_fs(ROCKY_SYSTEM_AUTH_FAILLOCK), {}),
        }
        for name, (fs, conf_d) in cases.items():
            with self.subTest(case=name):
                with FakeSystem(fs, conf_d, {"user1": GOOD_AGING}):
                    expected = acc01.run_check(self.policy_path)
                payload = acc_payload(fs, conf_d, {"user1": ok(CHAGE_GOOD)})
                self.assertEqual(judge("ACC-01", payload, policy_path=self.policy_path), expected)

    def test_pwquality_conf_missing_uses_defaults(self):
        fs = ubuntu_fs(**{"/etc/security/pwquality.conf": None})
        result = judge("ACC-01", acc_payload(fs, chage={"user1": ok(CHAGE_GOOD)}), policy_path=self.policy_path)
        self.assertNotEqual(result["status"], "error")

    def test_required_file_not_sent_is_error(self):
        payload = acc_payload(ubuntu_fs(), chage={"user1": ok(CHAGE_GOOD)})
        del payload["files"]["/etc/login.defs"]       # 보냈는데 없음인지 알 수 없음 -> error
        self.assertEqual(judge("ACC-01", payload, policy_path=self.policy_path)["status"], "error")

    def test_conf_d_listing_failure_is_error(self):
        payload = acc_payload(ubuntu_fs(), chage={"user1": ok(CHAGE_GOOD)})
        payload["pwquality_conf_d"] = {"state": "error"}
        self.assertEqual(judge("ACC-01", payload, policy_path=self.policy_path)["status"], "error")

    def test_invalid_conf_d_entries_are_error(self):
        # 효민님 독립 검증 R2·R3: 이상한 항목을 조용히 버리거나 그대로 쓰지 않고 error
        bad_entries = [
            [1],                                                    # 숫자 항목 (R2)
            [None],
            ["/etc/security/pwquality.conf.d/../outside.conf"],     # 경로 우회 (R3)
            ["/etc/security/pwquality.conf.d/./50.conf"],
            ["/etc/security/pwquality.conf.d//50.conf"],
            ["/etc/security/pwquality.conf.d/sub/50.conf"],         # 하위 폴더
            ["/tmp/evil.conf"],                                     # 다른 폴더
            ["/etc/security/pwquality.conf.d/50.txt"],              # 확장자
            ["/etc/security/pwquality.conf.d/50.conf", 1],          # 정상 + 이상 섞임
        ]
        for paths in bad_entries:
            with self.subTest(paths=paths):
                payload = acc_payload(ubuntu_fs(), chage={"user1": ok(CHAGE_GOOD)})
                payload["pwquality_conf_d"]["paths"] = paths
                for p in paths:
                    if isinstance(p, str):
                        payload["files"][p] = ok("minlen = 12\n")
                result = judge("ACC-01", payload, policy_path=self.policy_path)
                self.assertEqual(result["status"], "error")
                self.assertIn("Invalid entry", result["evidence"])

    def test_valid_conf_d_entry_is_used(self):
        conf = "/etc/security/pwquality.conf.d/50-local.conf"
        payload = acc_payload(ubuntu_fs(), {conf: "minlen = 12\n"}, {"user1": ok(CHAGE_GOOD)})
        result = judge("ACC-01", payload, policy_path=self.policy_path)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["details"]["pwquality_effective"]
                         ["/etc/pam.d/common-password"]["minlen"], "12")

    def test_conf_d_listing_with_failed_execution_is_error(self):
        payload = acc_payload(ubuntu_fs(), chage={"user1": ok(CHAGE_GOOD)})
        payload["pwquality_conf_d"]["exit_code"] = 2
        self.assertEqual(judge("ACC-01", payload, policy_path=self.policy_path)["status"], "error")

    def test_chage_failure_is_needs_review(self):
        for record in ({"state": "error"}, {"state": "timeout"}, ok("unexpected format\n"), None):
            with self.subTest(record=record):
                chage = {} if record is None else {"user1": record}
                result = judge("ACC-01", acc_payload(ubuntu_fs(), chage=chage), policy_path=self.policy_path)
                self.assertEqual(result["status"], "needs_review")

    def test_only_policy_accounts_are_used(self):
        chage = {"user1": ok(CHAGE_GOOD), "root": ok(CHAGE_GOOD.replace(": 90", ": 99999"))}
        result = judge("ACC-01", acc_payload(ubuntu_fs(), chage=chage), policy_path=self.policy_path)
        self.assertEqual(result["details"]["accounts"], ["user1"])
        self.assertEqual(result["status"], "pass")

    def test_empty_account_list_is_needs_review(self):
        # 실제 정책(interactive_accounts 빈 목록) 그대로
        result = judge("ACC-01", acc_payload(ubuntu_fs()))
        self.assertEqual(result["status"], "needs_review")

    def test_os_checks(self):
        # 지원 대상이 아닌 OS (확인됨) -> not_applicable
        # OS를 알 수 없음 (읽기 실패, ID 없음) -> error
        cases = [
            (ok('ID=debian\nVERSION_ID="12"\n'), "not_applicable"),
            ({"state": "error"}, "error"),
            (ok('NAME="Something"\nVERSION_ID="1"\n'), "error"),
            (ok(""), "error"),
        ]
        for check_id in ("ACC-01", "ACC-02"):
            for record, expected in cases:
                with self.subTest(check_id=check_id, record=record):
                    payload = acc_payload(ubuntu_fs())
                    payload["os_release"] = record
                    self.assertEqual(judge(check_id, payload)["status"], expected)


# ==================================================
# ACC-02
# ==================================================
class Acc02AdapterTest(unittest.TestCase):
    def test_same_result_as_run_check(self):
        import acc_lockout_check as acc02
        cases = {
            "good": ubuntu_fs(),
            "vm_default": ubuntu_vm_fs(),
            "faillock_conf_missing": ubuntu_fs(**{"/etc/security/faillock.conf": None}),
            "faillock_conf_error": ubuntu_fs(**{"/etc/security/faillock.conf": ERROR}),
            "rocky": rocky_fs(ROCKY_SYSTEM_AUTH_FAILLOCK),
        }
        for name, fs in cases.items():
            with self.subTest(case=name):
                with FakeSystem(fs):
                    expected = acc02.run_check()
                self.assertEqual(judge("ACC-02", acc_payload(fs)), expected)


# ==================================================
# 입구 함수
# ==================================================
class EntryTest(unittest.TestCase):
    def test_caller_mistakes_raise(self):
        # 호출 실수는 종류와 상관없이 ValueError (효민님 독립 검증 R4)
        for kwargs in ({"check_id": "SSH-01"}, {"check_id": []}, {"check_id": None},
                       {"check_id": "ACC-02", "result_version": "2.0"},
                       {"check_id": "ACC-02", "result_version": []}):
            with self.subTest(kwargs=kwargs):
                check_id = kwargs.pop("check_id")
                with self.assertRaises(ValueError):
                    adapter.judge_payload(check_id, {}, **kwargs)

    def test_options_are_keyword_only(self):
        # 효민님 독립 검증 R1: 네 번째 위치 인자로 버전을 넘기는 실수를 막음
        with self.assertRaises(TypeError):
            adapter.judge_payload("ACC-02", {}, None, "1.1")

    def test_broken_payload_never_raises(self):
        for check_id in ("SSH-02", "ACC-01", "ACC-02"):
            for payload in (None, [], "x", {"files": "x", "os_release": ok("ID=ubuntu\n")},
                            {"os_release": ok("ID=ubuntu\n"), "pwquality_conf_d": {"state": "ok", "paths": [1]}}):
                with self.subTest(check_id=check_id, payload=payload):
                    result = judge(check_id, payload, CONTEXT, version="1.2")
                    self.assertEqual(result["status"], "error")
                    self.assertEqual(result["check_id"], check_id)

    def test_policy_load_failure(self):
        result = judge("ACC-02", acc_payload(ubuntu_fs()), policy_path="/no/such/policy.json", version="1.2")
        self.assertEqual(result["status"], "error")
        self.assertIn("Policy load failed", result["evidence"])
        self.assertEqual(result["cvss"]["assessment_status"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
