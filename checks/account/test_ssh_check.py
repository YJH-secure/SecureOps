"""
ssh_check.py가 제대로 동작하는지 검사하는 테스트 파일입니다.

실제 서버 없이 가짜 입력(Mock)을 넣어서 결과를 확인합니다.
실행 방법: python test_ssh_check.py
모두 통과하면 마지막에 OK가 나옵니다.
"""

import copy       # 값을 안전하게 복사하기
import json       # 테스트용 JSON 글자 만들기
import os         # 파일 경로 만들기
import subprocess
import tempfile   # 잠깐 쓰고 지워지는 임시 폴더 만들기
import unittest   # 파이썬 기본 테스트 도구
from unittest import mock  # 진짜 함수를 잠깐 가짜 함수로 바꾸는 도구

import ssh_check  # 검사할 대상 파일을 가져옵니다.


# 실제 정책 파일을 기준으로 테스트합니다. (판정 기준을 코드에 중복으로 적지 않기 위해)
POLICY = ssh_check.load_policy()

V1_1_FIELDS = {"check_id", "status", "severity", "evidence", "recommendation"}


# 판정 함수를 짧게 부르기 위한 도우미 함수
def judge(global_value, config="", root_value=None):
    sshd_output = f"permitrootlogin {global_value}\n" if global_value else ""
    root_output = None if root_value is None else f"permitrootlogin {root_value}\n"
    return ssh_check.check_ssh_01(POLICY, sshd_output, config, root_output)


class ApprovedCriteriaTest(unittest.TestCase):
    # 2026-11-09 팀장 승인 기준: no만 pass, 나머지 4개 값은 vulnerable

    def test_no_is_pass(self):
        self.assertEqual(judge("no", root_value="no")["status"], "pass")

    def test_four_values_are_vulnerable(self):
        for value in ("yes", "prohibit-password", "without-password", "forced-commands-only"):
            with self.subTest(value=value):
                self.assertEqual(judge(value, root_value=value)["status"], "vulnerable")

    def test_evidence_has_value_and_violation_reason(self):
        # 실제 설정값과 위반 사유가 구분되어 기록되어야 합니다.
        evidence = judge("prohibit-password", root_value="prohibit-password")["evidence"]
        self.assertIn("permitrootlogin prohibit-password", evidence)
        self.assertIn("violation:", evidence)
        self.assertIn("public key", evidence)
        self.assertNotIn("allowed with password", evidence)

        forced = judge("forced-commands-only", root_value="forced-commands-only")["evidence"]
        self.assertIn("forced commands only", forced)

    def test_unknown_value_is_needs_review(self):
        self.assertEqual(judge("strange", root_value="strange")["status"], "needs_review")

    def test_empty_or_missing_output_is_error(self):
        self.assertEqual(judge("")["status"], "error")
        self.assertEqual(ssh_check.check_ssh_01(POLICY, "port 22\n")["status"], "error")
        self.assertEqual(judge("no", root_value="")["status"], "error")

    def test_without_root_output_and_no_match_uses_global(self):
        self.assertEqual(judge("no")["status"], "pass")
        self.assertEqual(judge("yes")["status"], "vulnerable")

    def test_result_has_only_contract_fields(self):
        # 결과에 규격 v1.1의 5개 필드만 있는지 확인합니다.
        for status_value in ("no", "yes", "strange"):
            result = judge(status_value, root_value=status_value)
            self.assertEqual(set(result), V1_1_FIELDS)
            self.assertTrue(result["recommendation"])


class MatchRuleTest(unittest.TestCase):
    # 팀장 승인 Match 기준

    def test_unrelated_match_keeps_judgement(self):
        # SSH-01과 관계없는 Match 설정은 기존 판정 유지
        config = "PermitRootLogin no\nMatch User alice\n    X11Forwarding no\n"
        self.assertEqual(judge("no", config, root_value="no")["status"], "pass")

    def test_match_for_other_user_is_ignored(self):
        # 다른 사용자에게만 적용되는 Match는 root와 무관
        config = "PermitRootLogin no\nMatch User alice,bob Address 10.0.0.0/8\n    PermitRootLogin yes\n"
        self.assertEqual(judge("no", config, root_value="no")["status"], "pass")

    def test_match_user_root_blocks_root(self):
        # 기본은 yes지만 Match User root에서 no가 검증되면 pass
        config = "PermitRootLogin yes\nMatch User root\n    PermitRootLogin no\n"
        self.assertEqual(judge("yes", config, root_value="no")["status"], "pass")

    def test_match_user_root_allows_root(self):
        # 실제 root 조건에서 허용이 확인되면 vulnerable
        config = "PermitRootLogin no\nMatch User root\n    PermitRootLogin yes\n"
        self.assertEqual(judge("no", config, root_value="yes")["status"], "vulnerable")

    def test_confirmed_vulnerable_is_not_hidden_by_match(self):
        # 명확히 확인된 취약 설정이 Match 존재만으로 needs_review가 되면 안 됨
        config = "PermitRootLogin yes\nMatch Address 10.0.0.5\n    PermitRootLogin no\n"
        self.assertEqual(judge("yes", config, root_value="yes")["status"], "vulnerable")

    def test_address_match_that_may_allow_root_is_review(self):
        # 테스트 조건에서는 no지만, 특정 주소에서는 yes가 될 수 있으면 needs_review
        config = "PermitRootLogin no\nMatch Address 10.0.0.5\n    PermitRootLogin yes\n"
        result = judge("no", config, root_value="no")
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("address", result["evidence"])

    def test_negated_address_match_is_review(self):
        # 기본 yes + 일부 주소 외에는 no: 테스트 조건은 no지만 다른 주소에서 yes 가능
        config = "PermitRootLogin yes\nMatch Address !10.0.0.0/8\n    PermitRootLogin no\n"
        self.assertEqual(judge("yes", config, root_value="no")["status"], "needs_review")

    def test_address_match_that_only_blocks_is_pass(self):
        # 모든 경우의 값이 no라면 pass
        config = "PermitRootLogin no\nMatch Address 10.0.0.5\n    PermitRootLogin no\n"
        self.assertEqual(judge("no", config, root_value="no")["status"], "pass")

    def test_match_without_root_output_is_review(self):
        config = "PermitRootLogin no\nMatch User root\n    PermitRootLogin yes\n"
        self.assertEqual(judge("no", config)["status"], "needs_review")

    def test_user_match_hidden_by_address_match_is_review(self):
        # 회귀 테스트: 테스트 주소에서는 Address Match(no)가 먼저 적용되어 no로 보이지만,
        # 다른 주소에서는 Match User root(yes)가 적용될 수 있으므로 pass가 되면 안 됨
        config = (
            "PermitRootLogin no\n"
            "Match Address 192.0.2.10\n    PermitRootLogin no\n"
            "Match User root\n    PermitRootLogin yes\n"
        )
        self.assertEqual(judge("no", config, root_value="no")["status"], "needs_review")

    def test_host_match_that_may_allow_root_is_review(self):
        # Host 조건도 Address와 같이 접속 조건으로 취급
        config = "PermitRootLogin no\nMatch Host admin-pc\n    PermitRootLogin prohibit-password\n"
        self.assertEqual(judge("no", config, root_value="no")["status"], "needs_review")

    def test_conditional_match_never_wrong_pass(self):
        # 회귀 테스트: 조건부 Match에서 root 허용 값이 하나라도 가능하면 pass가 나오면 안 됨
        allowing = ("yes", "prohibit-password", "without-password", "forced-commands-only")
        for keyword in ("Address 10.0.0.5", "Host admin-pc", "LocalPort 2222", "User root Address 10.0.0.5"):
            for value in allowing:
                with self.subTest(keyword=keyword, value=value):
                    config = f"PermitRootLogin no\nMatch {keyword}\n    PermitRootLogin {value}\n"
                    self.assertNotEqual(judge("no", config, root_value="no")["status"], "pass")

    def test_equals_sign_syntax(self):
        config = "PermitRootLogin=no\nMatch Address=10.0.0.5\n    PermitRootLogin=yes\n"
        self.assertEqual(judge("no", config, root_value="no")["status"], "needs_review")

    def test_include_with_match(self):
        # Include로 연결된 파일 안의 Match 설정도 찾는지 확인
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, "a.conf"), "w") as f:
                f.write("Match Address 10.0.0.5\n  PermitRootLogin yes\n")
            main = os.path.join(folder, "sshd_config")
            with open(main, "w") as f:
                f.write(f"Include {folder}/*.conf\n")
            rules = ssh_check.find_match_rules(ssh_check.read_config_text(main), "permitrootlogin")
            self.assertEqual(rules, [{"keywords": {"address"}, "value": "yes"}])


class PolicyTest(unittest.TestCase):
    # 음성 테스트: 일부러 잘못된 정책을 넣어 error로 처리하는지 확인

    def run_with(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "policy.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            return ssh_check.run_check(path)

    def bad_policy(self, change):
        policy = copy.deepcopy(POLICY)
        change(policy)
        return json.dumps({"policy_version": "1.0", "policies": [policy]})

    def test_real_policy_file_loads(self):
        self.assertEqual(POLICY["check_id"], "SSH-01")
        self.assertEqual(POLICY["criteria"]["expected"], "no")

    def test_bad_policies_are_errors(self):
        cases = [
            "{broken json",
            json.dumps({"policy_version": "1.0"}),
            json.dumps({"policy_version": "1.0", "policies": [POLICY, POLICY]}),
            self.bad_policy(lambda p: p.pop("description")),
            self.bad_policy(lambda p: p.update(severity="HIGH")),
            self.bad_policy(lambda p: p["criteria"].update(type="unknown")),
            self.bad_policy(lambda p: p["criteria"].update(operator="contains")),
            self.bad_policy(lambda p: p["criteria"].pop("vulnerable_values")),
            self.bad_policy(lambda p: p["criteria"].update(vulnerable_values={"no": "conflict"})),
            self.bad_policy(lambda p: p["criteria"]["vulnerable_values"].update(yes="")),
            self.bad_policy(lambda p: p["criteria"].pop("test_connection")),
            self.bad_policy(lambda p: p["criteria"]["test_connection"].update(addr="1.1.1.1,user=x")),
            self.bad_policy(lambda p: p["criteria"]["test_connection"].update(user="cju")),
            self.bad_policy(lambda p: p["criteria"]["test_connection"].update(user="ROOT")),
        ]
        for text in cases:
            with self.subTest(text=text[:60]):
                result = self.run_with(text)
                self.assertEqual(result["status"], "error")
                self.assertEqual(set(result), V1_1_FIELDS)

    def test_non_root_test_user_is_policy_error(self):
        # SSH-01은 root 진단이므로 test_connection.user가 root가 아니면 정책 오류
        result = self.run_with(self.bad_policy(lambda p: p["criteria"]["test_connection"].update(user="alice")))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["evidence"], "Policy load failed: ValueError")

    def test_missing_policy_file_hides_path(self):
        result = ssh_check.run_check("/no/such/file.json")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["evidence"], "Policy load failed: FileNotFoundError")


class CollectTest(unittest.TestCase):
    # 서버 설정을 읽는 단계에서 생기는 문제와 명령 형식을 검사

    def test_sshd_not_installed(self):
        with mock.patch.object(ssh_check, "find_sshd", return_value=None):
            self.assertEqual(ssh_check.run_check()["status"], "not_applicable")

    def test_sshd_failed(self):
        with mock.patch.object(ssh_check, "find_sshd", return_value="/x"), \
             mock.patch.object(ssh_check, "get_sshd_output", return_value=None):
            self.assertEqual(ssh_check.run_check()["status"], "error")

    def test_config_read_failed(self):
        with mock.patch.object(ssh_check, "find_sshd", return_value="/x"), \
             mock.patch.object(ssh_check, "get_sshd_output", return_value="permitrootlogin no\n"), \
             mock.patch.object(ssh_check, "read_config_text", return_value=None):
            self.assertEqual(ssh_check.run_check()["status"], "error")

    def test_root_condition_failed(self):
        # sshd -T는 성공했지만 sshd -T -C가 실패하면 error
        def fake(sshd, connection_spec=None):
            return None if connection_spec else "permitrootlogin no\n"
        with mock.patch.object(ssh_check, "find_sshd", return_value="/x"), \
             mock.patch.object(ssh_check, "get_sshd_output", side_effect=fake), \
             mock.patch.object(ssh_check, "read_config_text", return_value=""):
            self.assertEqual(ssh_check.run_check()["status"], "error")

    def test_run_check_uses_root_condition(self):
        # 전체 설정은 yes여도 root 조건에서 no가 확인되고 Match User root만 있으면 pass
        def fake(sshd, connection_spec=None):
            return "permitrootlogin no\n" if connection_spec else "permitrootlogin yes\n"
        config = "PermitRootLogin yes\nMatch User root\n    PermitRootLogin no\n"
        with mock.patch.object(ssh_check, "find_sshd", return_value="/x"), \
             mock.patch.object(ssh_check, "get_sshd_output", side_effect=fake), \
             mock.patch.object(ssh_check, "read_config_text", return_value=config):
            self.assertEqual(ssh_check.run_check()["status"], "pass")

    def test_connection_spec_comes_from_policy(self):
        self.assertEqual(
            ssh_check.build_connection_spec(POLICY["criteria"]["test_connection"]),
            "user=root,host=secureops-check,addr=192.0.2.10",
        )

    def run_with_override(self, **override):
        # 실제 실행 대신 -C에 넘어가는 조건을 기록하는 가짜 함수
        specs = []
        def fake(sshd, connection_spec=None):
            specs.append(connection_spec)
            return "permitrootlogin no\n"
        with mock.patch.object(ssh_check, "find_sshd", return_value="/x"), \
             mock.patch.object(ssh_check, "get_sshd_output", side_effect=fake), \
             mock.patch.object(ssh_check, "read_config_text", return_value=""):
            result = ssh_check.run_check(**override)
        return result, specs

    def test_runtime_override_of_host_and_addr(self):
        # 실제 환경에서는 실행할 때 host, addr를 따로 지정할 수 있음
        result, specs = self.run_with_override(host="admin-pc", addr="10.0.0.5")
        self.assertEqual(result["status"], "pass")
        self.assertIn("user=root,host=admin-pc,addr=10.0.0.5", specs)

    def test_invalid_override_is_error(self):
        result, specs = self.run_with_override(addr="10.0.0.5,user=alice")
        self.assertEqual(result["status"], "error")
        self.assertEqual(specs, [])

    def test_command_uses_dash_c(self):
        # 실제 실행되는 명령이 sshd -T -C <조건> 형식인지 확인 (명령은 실행하지 않음)
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="permitrootlogin no\n")
        with mock.patch.object(ssh_check.subprocess, "run", return_value=completed) as run:
            ssh_check.get_sshd_output("/usr/sbin/sshd", "user=root,host=h,addr=192.0.2.10")
        self.assertEqual(run.call_args[0][0], ["/usr/sbin/sshd", "-T", "-C", "user=root,host=h,addr=192.0.2.10"])


if __name__ == "__main__":
    unittest.main()