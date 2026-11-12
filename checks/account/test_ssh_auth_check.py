"""
SSH-02 Mock 테스트

실제 서버에 접속하거나 명령을 실행하지 않습니다.
sshd -T 결과를 "가짜 글자"로 만들어 판정 함수에 넣고, 결과가 정책대로 나오는지 확인합니다.

실행: python -m unittest test_ssh_auth_check -v
"""

import json
import os
import re
import tempfile
import unittest
from unittest import mock

import ssh_auth_check
import ssh_check

POLICY = ssh_auth_check.load_policy()
USERS = POLICY["criteria"]["test_connection"]["users"]

# 정책을 모두 만족하는 sshd -T 결과 (기본값)
GOOD_SETTINGS = {
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "pubkeyauthentication": "yes",
    "permitemptypasswords": "no",
    "hostbasedauthentication": "no",
    "gssapiauthentication": "no",
    "kerberosauthentication": "no",
    "authenticationmethods": "any",
    "usepam": "yes",
    "maxauthtries": "6",
}


# 기본값에서 일부만 바꾼 가짜 sshd -T 결과를 만듭니다.
#   allowusers=["a", "b"] 처럼 주면 값 하나당 한 줄로 출력 (실제 sshd -T와 같은 형식)
def make_output(allowusers=None, allowgroups=None, remove=(), **changes):
    settings = dict(GOOD_SETTINGS, **changes)
    lines = [f"{k} {v}" for k, v in settings.items() if k not in remove]
    lines += [f"allowusers {u}" for u in (allowusers or [])]
    lines += [f"allowgroups {g}" for g in (allowgroups or [])]
    return "\n".join(lines) + "\n"


APPROVED_USERS = ["secureops-scan", "secureops-fix"]


# 모든 테스트 계정에 같은 결과를 넣고 판정합니다.
def judge(user_output, config_text="", global_output=None):
    outputs = {user: user_output for user in USERS}
    return ssh_auth_check.check_ssh_02(POLICY, global_output or user_output, config_text, outputs)


def finding(result, setting):
    return [f for f in result["details"]["findings"] if f["setting"] == setting]


# ---------- 정책 파일 ----------
class PolicyTest(unittest.TestCase):
    def test_policy_matches_approved_criteria(self):
        expected = {k: v["expected"] for k, v in POLICY["criteria"]["settings"].items()}
        self.assertEqual(expected, {
            "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
            "pubkeyauthentication": "yes", "permitemptypasswords": "no",
            "hostbasedauthentication": "no", "gssapiauthentication": "no",
            "kerberosauthentication": "no",
        })
        self.assertEqual(POLICY["criteria"]["authentication_methods"]["approved_methods"], ["publickey"])
        self.assertEqual(POLICY["criteria"]["access_control"]["approved_accounts"], APPROVED_USERS)
        self.assertEqual(POLICY["criteria"]["access_control"]["pending_accounts"], ["user1"])
        self.assertEqual(POLICY["severity"], "medium")
        self.assertEqual(POLICY["cvss_assessment"]["vulnerable_assessment_status"], "pending")

    def _write_policy(self, mutate):
        with open(ssh_auth_check.POLICY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        mutate(data["policies"][0])
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, tmp)
        tmp.close()
        self.addCleanup(os.remove, tmp.name)
        return tmp.name

    def test_invalid_policies_rejected(self):
        mutations = {
            "bad expected": lambda p: p["criteria"]["settings"]["passwordauthentication"].update(expected="maybe"),
            "no settings": lambda p: p["criteria"].update(settings={}),
            "bad type": lambda p: p["criteria"].update(type="sshd_effective_setting"),
            "unknown method": lambda p: p["criteria"]["authentication_methods"].update(approved_methods=["magic"]),
            "user with comma": lambda p: p["criteria"]["test_connection"].update(users=["a,b"]),
            "empty users": lambda p: p["criteria"]["test_connection"].update(users=[]),
            "bad cvss": lambda p: p["cvss_assessment"].update(vulnerable_assessment_status="scored"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    ssh_auth_check.load_policy(self._write_policy(mutate))


# ---------- 7개 인증 설정 ----------
class SettingsTest(unittest.TestCase):
    def test_all_good_with_approved_allowusers_is_pass(self):
        result = judge(make_output(allowusers=APPROVED_USERS))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["severity"], "medium")

    def test_each_wrong_setting_is_vulnerable(self):
        for setting, rule in POLICY["criteria"]["settings"].items():
            wrong = "yes" if rule["expected"] == "no" else "no"
            with self.subTest(setting):
                result = judge(make_output(allowusers=APPROVED_USERS, **{setting: wrong}))
                self.assertEqual(result["status"], "vulnerable")
                self.assertIn(f"{setting} {wrong}", result["evidence"])
                self.assertEqual(finding(result, setting)[0]["reason"], rule["reason"])

    def test_missing_setting_is_error(self):
        result = judge(make_output(allowusers=APPROVED_USERS, remove=("kerberosauthentication",)))
        self.assertEqual(result["status"], "error")

    def test_vulnerable_wins_over_needs_review(self):
        # 현재 VM과 같은 상황: 비밀번호 인증 yes + AllowUsers 미설정
        result = judge(make_output(passwordauthentication="yes"))
        self.assertEqual(result["status"], "vulnerable")
        self.assertEqual(finding(result, "allowusers/allowgroups")[0]["status"], "needs_review")


# ---------- AuthenticationMethods ----------
class AuthenticationMethodsTest(unittest.TestCase):
    def status_for(self, methods, **changes):
        result = judge(make_output(allowusers=APPROVED_USERS, authenticationmethods=methods, **changes))
        return finding(result, "authenticationmethods")[0]["status"]

    def test_any_is_pass(self):
        self.assertEqual(self.status_for("any"), "pass")

    def test_publickey_only_is_pass(self):
        self.assertEqual(self.status_for("publickey"), "pass")

    def test_disabled_password_path_is_not_active(self):
        # password 경로가 있어도 passwordauthentication no면 실제로 쓸 수 없음
        self.assertEqual(self.status_for("publickey password"), "pass")

    def test_active_unapproved_method_is_vulnerable(self):
        self.assertEqual(self.status_for("publickey,keyboard-interactive:pam",
                                         kbdinteractiveauthentication="yes"), "vulnerable")

    def test_gssapi_path_enabled_is_vulnerable(self):
        self.assertEqual(self.status_for("gssapi-with-mic", gssapiauthentication="yes"), "vulnerable")

    def test_no_usable_path_needs_review(self):
        self.assertEqual(self.status_for("password"), "needs_review")

    def test_unknown_method_needs_review(self):
        self.assertEqual(self.status_for("publickey,magic"), "needs_review")


# ---------- AllowUsers / AllowGroups ----------
class AccessControlTest(unittest.TestCase):
    def access(self, **kwargs):
        result = judge(make_output(**kwargs))
        return result, finding(result, "allowusers/allowgroups")[0]

    def test_not_set_is_needs_review_not_vulnerable(self):
        result, f = self.access()
        self.assertEqual(f["status"], "needs_review")
        self.assertEqual(result["status"], "needs_review")

    def test_approved_accounts_only_is_pass(self):
        self.assertEqual(self.access(allowusers=APPROVED_USERS)[1]["status"], "pass")

    def test_user_at_host_form_is_supported(self):
        self.assertEqual(self.access(allowusers=["secureops-scan@10.0.0.0/8"])[1]["status"], "pass")

    def test_pending_account_needs_review(self):
        f = self.access(allowusers=APPROVED_USERS + ["user1"])[1]
        self.assertEqual(f["status"], "needs_review")
        self.assertIn("pending confirmation: user1", f["reason"])

    def test_unknown_account_needs_review(self):
        self.assertEqual(self.access(allowusers=["cju"])[1]["status"], "needs_review")

    def test_allowgroups_only_needs_review(self):
        self.assertEqual(self.access(allowgroups=["sshusers"])[1]["status"], "needs_review")


# ---------- Match 블록 ----------
class MatchTest(unittest.TestCase):
    def test_address_match_with_bad_value_needs_review(self):
        config = "PasswordAuthentication no\nMatch Address 10.0.0.5\n    PasswordAuthentication yes\n"
        result = judge(make_output(allowusers=APPROVED_USERS), config)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(finding(result, "passwordauthentication")[0]["status"], "needs_review")

    def test_address_match_with_same_value_is_pass(self):
        config = "Match Address 10.0.0.5\n    PasswordAuthentication no\n"
        self.assertEqual(judge(make_output(allowusers=APPROVED_USERS), config)["status"], "pass")

    def test_user_match_is_judged_from_effective_output(self):
        # Match User는 sshd -T -C user=... 결과에 이미 반영되므로 그 값으로 판정
        config = "Match User secureops-fix\n    PasswordAuthentication yes\n"
        outputs = {
            "secureops-scan": make_output(allowusers=APPROVED_USERS),
            "secureops-fix": make_output(allowusers=APPROVED_USERS, passwordauthentication="yes"),
        }
        result = ssh_auth_check.check_ssh_02(POLICY, outputs["secureops-scan"], config, outputs)
        self.assertEqual(result["status"], "vulnerable")
        bad = [f for f in finding(result, "passwordauthentication") if f["status"] == "vulnerable"]
        self.assertEqual([f["user"] for f in bad], ["secureops-fix"])

    def test_address_match_on_allowusers_needs_review(self):
        config = "Match Address 10.0.0.0/8\n    AllowUsers secureops-scan cju\n"
        result = judge(make_output(allowusers=APPROVED_USERS), config)
        self.assertEqual(finding(result, "allowusers/allowgroups")[0]["status"], "needs_review")


# ---------- 수집 단계 (명령 실행은 모두 가짜) ----------
class CollectTest(unittest.TestCase):
    def run_with(self, sshd="/usr/sbin/sshd", outputs=None, config="", **kwargs):
        good = make_output(allowusers=APPROVED_USERS)
        outputs = outputs or {}

        def fake_output(_sshd, spec=None):
            return outputs.get(spec, good)

        with mock.patch.object(ssh_check, "find_sshd", return_value=sshd), \
             mock.patch.object(ssh_check, "get_sshd_output", side_effect=fake_output) as get, \
             mock.patch.object(ssh_check, "read_config_text", return_value=config):
            return ssh_auth_check.run_check(**kwargs), get

    def test_pass_and_commands_are_read_only(self):
        result, get = self.run_with()
        self.assertEqual(result["status"], "pass")
        specs = [c.args[1] if len(c.args) > 1 else None for c in get.call_args_list]
        self.assertEqual(specs[0], None)   # 첫 번째: sshd -T
        self.assertEqual(specs[1:], [f"user={u},host=secureops-check,addr=192.0.2.10" for u in USERS])

    def test_sshd_not_installed(self):
        self.assertEqual(self.run_with(sshd=None)[0]["status"], "not_applicable")

    def test_sshd_t_failed(self):
        self.assertEqual(self.run_with(outputs={None: None})[0]["status"], "error")

    def test_config_read_failed(self):
        self.assertEqual(self.run_with(config=None)[0]["status"], "error")

    def test_one_user_collect_failed(self):
        spec = "user=secureops-fix,host=secureops-check,addr=192.0.2.10"
        self.assertEqual(self.run_with(outputs={spec: None})[0]["status"], "error")

    def test_policy_load_failed(self):
        result, _ = self.run_with(policy_path="no-such-file.json")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["severity"], "medium")

    def test_user_override(self):
        result, get = self.run_with(users=["cju"])
        self.assertEqual(result["details"]["users"], ["cju"])
        self.assertEqual(get.call_args_list[1].args[1], "user=cju,host=secureops-check,addr=192.0.2.10")

    def test_invalid_override_is_error(self):
        self.assertEqual(self.run_with(users=["cju,root"])[0]["status"], "error")
        self.assertEqual(self.run_with(addr="1.2.3.4 x")[0]["status"], "error")


# ---------- 결과 형식 v1.1 / v1.2 ----------
class ResultFormatTest(unittest.TestCase):
    SECRET_TEXT = re.compile(r"\b(?:password|token|api[_-]?key|secret|cookie)\s*[:=]\s*\S+", re.I)

    def run_version(self, version, **changes):
        good = make_output(allowusers=APPROVED_USERS, **changes)
        with mock.patch.object(ssh_check, "find_sshd", return_value="/usr/sbin/sshd"), \
             mock.patch.object(ssh_check, "get_sshd_output", return_value=good), \
             mock.patch.object(ssh_check, "read_config_text", return_value=""):
            return ssh_auth_check.run_check(result_version=version)

    def test_v1_1_fields(self):
        result = self.run_version("1.1")
        self.assertEqual(set(result) - {"details"},
                         {"check_id", "status", "severity", "evidence", "recommendation"})
        self.assertEqual(result["check_id"], "SSH-02")

    def test_v1_2_vulnerable_is_pending(self):
        result = self.run_version("1.2", passwordauthentication="yes")
        self.assertNotIn("severity", result)
        self.assertEqual(result["cvss"]["assessment_status"], "pending")
        self.assertIsNone(result["cvss"]["base_score"])
        self.assertIn("findings", result["details"])

    def test_v1_2_pass_is_not_applicable(self):
        result = self.run_version("1.2")
        self.assertEqual(result["cvss"]["assessment_status"], "not_applicable")

    def test_evidence_only_settings_are_recorded_not_judged(self):
        result = self.run_version("1.1", maxauthtries="10", usepam="no")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["details"]["evidence_only"], {"maxauthtries": "10", "usepam": "no"})

    def test_no_secret_like_text_and_no_test_address(self):
        result = self.run_version("1.2", passwordauthentication="yes", authenticationmethods="password")
        text = json.dumps(result, ensure_ascii=False)
        self.assertIsNone(self.SECRET_TEXT.search(text))
        self.assertNotIn("192.0.2.10", text)

    def test_unsupported_version(self):
        with self.assertRaises(ValueError):
            ssh_auth_check.run_check(result_version="2.0")


if __name__ == "__main__":
    unittest.main()
