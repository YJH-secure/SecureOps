"""
ACC-01(비밀번호 정책), ACC-02(계정 잠금 정책) Mock 테스트

실제 서버 파일을 읽거나 명령을 실행하지 않습니다.
"가짜 파일 시스템"(경로 -> 내용 사전)을 만들어 읽기 함수를 바꿔치기하고,
판정이 팀장 승인 기준대로 나오는지 확인합니다.

실행: python -m unittest test_account_checks -v
"""

import json
import os
import re
import tempfile
import unittest
from unittest import mock

import account_common
import acc_lockout_check as acc02
import acc_password_check as acc01

ERROR = object()   # "읽기 실패(권한 부족 등)"를 뜻하는 표시

# ---------- 가짜 파일 내용 ----------
UBUNTU_OS = 'PRETTY_NAME="Ubuntu 24.04.4 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n'
ROCKY_OS = 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.6"\n'

LOGIN_DEFS_DEFAULT = "PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nENCRYPT_METHOD SHA512\n"
LOGIN_DEFS_GOOD = "PASS_MAX_DAYS\t90\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t7\n"

# 현재 개인 VM(Ubuntu 24.04 기본 설치)과 같은 내용
UBUNTU_PASSWORD_DEFAULT = (
    "# comment\n"
    "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n"
    "password\trequisite\t\t\tpam_deny.so\n"
    "password\trequired\t\t\tpam_permit.so\n"
)
UBUNTU_PASSWORD_PWQUALITY = (
    "password\trequisite\t\t\tpam_pwquality.so retry=3\n"
    "password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt\n"
    "password\trequisite\t\t\tpam_deny.so\n"
    "password\trequired\t\t\tpam_permit.so\n"
)
UBUNTU_AUTH_DEFAULT = (
    "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n"
    "auth\trequisite\t\t\tpam_deny.so\n"
    "auth\trequired\t\t\tpam_permit.so\n"
    "auth\toptional\t\t\tpam_cap.so\n"
)
UBUNTU_AUTH_FAILLOCK = (
    "auth\trequired\t\t\tpam_faillock.so preauth\n"
    "auth\t[success=2 default=ignore]\tpam_unix.so\n"
    "auth\t[default=die]\t\t\tpam_faillock.so authfail\n"
    "auth\tsufficient\t\t\tpam_faillock.so authsucc\n"
    "auth\trequisite\t\t\tpam_deny.so\n"
    "auth\trequired\t\t\tpam_permit.so\n"
)
UBUNTU_ACCOUNT_DEFAULT = (
    "account\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so\n"
    "account\trequisite\t\t\tpam_deny.so\n"
    "account\trequired\t\t\tpam_permit.so\n"
)
UBUNTU_ACCOUNT_FAILLOCK = UBUNTU_ACCOUNT_DEFAULT + "account\trequired\t\t\tpam_faillock.so\n"

# Rocky 9 authselect(sssd + with-faillock) 형식 예시
ROCKY_SYSTEM_AUTH_FAILLOCK = (
    "auth        required      pam_env.so\n"
    "auth        required      pam_faillock.so preauth silent\n"
    "auth        sufficient    pam_unix.so nullok\n"
    "auth        sufficient    pam_sss.so forward_pass\n"
    "auth        required      pam_faillock.so authfail\n"
    "auth        required      pam_deny.so\n"
    "account     required      pam_faillock.so\n"
    "account     required      pam_unix.so\n"
    "password    requisite     pam_pwquality.so local_users_only\n"
    "password    sufficient    pam_unix.so yescrypt shadow nullok use_authtok\n"
    "password    [success=1 default=ignore] pam_sss.so use_authtok\n"
    "password    required      pam_deny.so\n"
)
ROCKY_SYSTEM_AUTH_DEFAULT = ROCKY_SYSTEM_AUTH_FAILLOCK.replace(
    "auth        required      pam_faillock.so preauth silent\n", "").replace(
    "auth        required      pam_faillock.so authfail\n", "").replace(
    "account     required      pam_faillock.so\n", "")

PWQUALITY_GOOD = "# comment\nminlen = 8\nminclass = 3\n"
FAILLOCK_GOOD = "deny = 5\nunlock_time = 600\nfail_interval = 900\n"
FAILLOCK_COMMENTED = "# deny = 3\n# unlock_time = 600\n"

GOOD_AGING = {"min_days": 1, "max_days": 90}


def ubuntu_fs(**changes):
    files = {
        "/etc/os-release": UBUNTU_OS,
        "/etc/login.defs": LOGIN_DEFS_GOOD,
        "/etc/pam.d/common-password": UBUNTU_PASSWORD_PWQUALITY,
        "/etc/pam.d/common-auth": UBUNTU_AUTH_FAILLOCK,
        "/etc/pam.d/common-account": UBUNTU_ACCOUNT_FAILLOCK,
        "/etc/security/pwquality.conf": PWQUALITY_GOOD,
        "/etc/security/faillock.conf": FAILLOCK_GOOD,
    }
    files.update(changes)
    return files


def ubuntu_vm_fs():
    """현재 개인 VM(Ubuntu 24.04.4 기본 설치) 상태"""
    return ubuntu_fs(**{
        "/etc/login.defs": LOGIN_DEFS_DEFAULT,
        "/etc/pam.d/common-password": UBUNTU_PASSWORD_DEFAULT,
        "/etc/pam.d/common-auth": UBUNTU_AUTH_DEFAULT,
        "/etc/pam.d/common-account": UBUNTU_ACCOUNT_DEFAULT,
        "/etc/security/pwquality.conf": None,
        "/etc/security/faillock.conf": FAILLOCK_COMMENTED,
    })


def rocky_fs(system_auth, **changes):
    files = {
        "/etc/os-release": ROCKY_OS,
        "/etc/login.defs": LOGIN_DEFS_GOOD,
        "/etc/pam.d/system-auth": system_auth,
        "/etc/pam.d/password-auth": system_auth,
        "/etc/security/pwquality.conf": PWQUALITY_GOOD,
        "/etc/security/faillock.conf": FAILLOCK_GOOD,
    }
    files.update(changes)
    return files


# 가짜 파일 시스템으로 바꿔치기: None = 파일 없음, ERROR = 읽기 실패
class FakeSystem:
    def __init__(self, files, conf_d=None, aging=None):
        self.files = dict(files)
        self.conf_d = conf_d or {}
        self.files.update(self.conf_d)
        self.aging = aging or {}
        self.read_paths = []
        self.chage_accounts = []

    def read_text(self, path):
        self.read_paths.append(path)
        value = self.files.get(path)
        if value is ERROR:
            return "error", None
        if value is None:
            return "missing", None
        return "ok", value

    def list_conf_files(self, directory):
        return sorted(p for p in self.conf_d if p.startswith(directory + "/"))

    def run_chage(self, account):
        self.chage_accounts.append(account)
        return self.aging.get(account)

    def __enter__(self):
        self.patches = [
            mock.patch.object(account_common, "read_text", side_effect=self.read_text),
            mock.patch.object(account_common, "list_conf_files", side_effect=self.list_conf_files),
            mock.patch.object(account_common, "run_chage", side_effect=self.run_chage),
            mock.patch("subprocess.run", side_effect=AssertionError("no real command")),
        ]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


def run01(files, accounts=("cju",), aging=None, conf_d=None, version="1.1"):
    aging = {"cju": GOOD_AGING} if aging is None else aging
    with FakeSystem(files, conf_d, aging) as fake:
        return acc01.run_check(accounts=list(accounts), result_version=version), fake


def run02(files, version="1.1"):
    with FakeSystem(files) as fake:
        return acc02.run_check(result_version=version), fake


def items(result, name):
    return [f for f in result["details"]["findings"] if f["item"] == name]


def status_of(result, name):
    return {f["status"] for f in items(result, name)}


# ==================================================
# 정책 파일
# ==================================================
class PolicyTest(unittest.TestCase):
    def test_policies_match_approved_criteria(self):
        c1 = acc01.load_policy()["criteria"]
        self.assertEqual((c1["min_length"], c1["min_classes"], c1["max_days"], c1["min_days"]), (8, 3, 90, 1))
        self.assertTrue(c1["forbid_nullok"])
        p2 = acc02.load_policy()
        c2 = p2["criteria"]
        self.assertEqual((c2["deny_min"], c2["deny_max"], c2["deny_recommended"]), (1, 10, 5))
        self.assertEqual((c2["unlock_time_min"], c2["fail_interval_recommended"]), (600, 900))
        self.assertEqual(acc01.load_policy()["severity"], "high")
        self.assertEqual(p2["severity"], "medium")

    def _policy_file(self, check_id, mutate):
        with open(acc01.POLICY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        mutate(next(p for p in data["policies"] if p["check_id"] == check_id))
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, tmp)
        tmp.close()
        self.addCleanup(os.remove, tmp.name)
        return tmp.name

    def test_invalid_policies_rejected(self):
        cases = [
            (acc01, "ACC-01", lambda p: p["criteria"].update(min_length="8")),
            (acc01, "ACC-01", lambda p: p["criteria"].update(min_classes=5)),
            (acc01, "ACC-01", lambda p: p["criteria"].update(interactive_accounts=["bad name"])),
            (acc01, "ACC-01", lambda p: p["criteria"]["profiles"].pop("rocky")),
            (acc01, "ACC-01", lambda p: p["cvss_assessment"].update(vulnerable_assessment_status="scored")),
            (acc02, "ACC-02", lambda p: p["criteria"].update(deny_min=0)),
            (acc02, "ACC-02", lambda p: p["criteria"]["profiles"]["ubuntu"].update(stacks=[])),
            (acc02, "ACC-02", lambda p: p["criteria"].update(type="password_policy")),
        ]
        for module, check_id, mutate in cases:
            with self.subTest(check_id=check_id):
                with self.assertRaises(ValueError):
                    module.load_policy(self._policy_file(check_id, mutate))


# ==================================================
# ACC-01 비밀번호 정책
# ==================================================
class Acc01Test(unittest.TestCase):
    def test_all_good_is_pass(self):
        result, _ = run01(ubuntu_fs())
        self.assertEqual(result["status"], "pass", result["evidence"])
        self.assertEqual(result["severity"], "high")

    def test_current_vm_state_is_vulnerable(self):
        result, _ = run01(ubuntu_vm_fs(), aging={"cju": {"min_days": 0, "max_days": 99999}})
        self.assertEqual(result["status"], "vulnerable")
        for name in ("min_length", "complexity_classes", "PASS_MAX_DAYS", "PASS_MIN_DAYS", "nullok",
                     "account_max_days(cju)", "account_min_days(cju)"):
            with self.subTest(name):
                self.assertEqual(status_of(result, name), {"vulnerable"})
        self.assertEqual(items(result, "min_length")[0]["actual"], 6)

    def test_pwquality_defaults_when_conf_missing(self):
        # 모듈은 연결됐지만 설정 파일이 없으면 기본값(minlen 8, minclass 0) -> 종류 기준 미달
        result, _ = run01(ubuntu_fs(**{"/etc/security/pwquality.conf": None}))
        self.assertEqual(status_of(result, "min_length"), {"pass"})
        self.assertEqual(status_of(result, "complexity_classes"), {"vulnerable"})

    def test_negative_credits_count_as_required_classes(self):
        conf = "minlen = 8\nminclass = 0\ndcredit = -1\nucredit = -1\nocredit = -1\n"
        result, _ = run01(ubuntu_fs(**{"/etc/security/pwquality.conf": conf}))
        self.assertEqual(items(result, "complexity_classes")[0]["actual"], 3)
        self.assertEqual(result["status"], "pass")

    def test_positive_credits_shorten_length(self):
        conf = "minlen = 8\nminclass = 3\ndcredit = 1\n"
        result, _ = run01(ubuntu_fs(**{"/etc/security/pwquality.conf": conf}))
        self.assertEqual(items(result, "min_length")[0]["actual"], 7)
        self.assertEqual(status_of(result, "min_length"), {"vulnerable"})

    def test_conf_d_and_module_args_override(self):
        conf_d = {"/etc/security/pwquality.conf.d/50-local.conf": "minlen = 12\n"}
        result, _ = run01(ubuntu_fs(), conf_d=conf_d)
        self.assertEqual(items(result, "min_length")[0]["actual"], 12)
        password = UBUNTU_PASSWORD_PWQUALITY.replace("retry=3", "retry=3 minlen=6")
        result, _ = run01(ubuntu_fs(**{"/etc/pam.d/common-password": password}), conf_d=conf_d)
        self.assertEqual(items(result, "min_length")[0]["actual"], 6)
        self.assertEqual(result["status"], "vulnerable")

    def test_enforcing_zero_is_vulnerable(self):
        result, _ = run01(ubuntu_fs(**{"/etc/security/pwquality.conf": PWQUALITY_GOOD + "enforcing = 0\n"}))
        self.assertEqual(result["status"], "vulnerable")

    def test_optional_pwquality_needs_review(self):
        password = UBUNTU_PASSWORD_PWQUALITY.replace("requisite\t\t\tpam_pwquality", "optional\tpam_pwquality")
        result, _ = run01(ubuntu_fs(**{"/etc/pam.d/common-password": password}))
        self.assertEqual(result["status"], "needs_review")

    def test_other_complexity_module_needs_review(self):
        for module in ("pam_passwdqc.so", "pam_custom_policy.so"):
            with self.subTest(module):
                password = UBUNTU_PASSWORD_DEFAULT.replace("pam_deny.so", f"{module}\npassword requisite pam_deny.so")
                result, _ = run01(ubuntu_fs(**{"/etc/pam.d/common-password": password}))
                self.assertEqual(status_of(result, "complexity_classes"), {"needs_review"})

    def test_pam_unix_minlen_without_complexity(self):
        password = UBUNTU_PASSWORD_DEFAULT.replace("obscure yescrypt", "obscure yescrypt minlen=10")
        result, _ = run01(ubuntu_fs(**{"/etc/pam.d/common-password": password}))
        self.assertEqual(status_of(result, "min_length"), {"pass"})
        self.assertEqual(status_of(result, "complexity_classes"), {"vulnerable"})

    def test_login_defs_missing_or_invalid_values(self):
        result, _ = run01(ubuntu_fs(**{"/etc/login.defs": "PASS_WARN_AGE 7\n"}))
        self.assertEqual(status_of(result, "PASS_MAX_DAYS"), {"vulnerable"})
        self.assertEqual(status_of(result, "PASS_MIN_DAYS"), {"vulnerable"})
        result, _ = run01(ubuntu_fs(**{"/etc/login.defs": "PASS_MAX_DAYS abc\nPASS_MIN_DAYS 1\n"}))
        self.assertEqual(result["status"], "needs_review")

    def test_nullok_variants(self):
        auth = UBUNTU_AUTH_FAILLOCK.replace("pam_unix.so", "pam_unix.so nullok_secure")
        result, _ = run01(ubuntu_fs(**{"/etc/pam.d/common-auth": auth}))
        self.assertEqual(status_of(result, "nullok"), {"vulnerable"})
        # password 단계의 nullok는 인증(auth) 단계가 아니므로 nullok 판정 대상 아님
        password = UBUNTU_PASSWORD_PWQUALITY.replace("yescrypt", "yescrypt nullok")
        result, _ = run01(ubuntu_fs(**{"/etc/pam.d/common-password": password}))
        self.assertEqual(status_of(result, "nullok"), {"pass"})

    def test_account_aging(self):
        result, _ = run01(ubuntu_fs(), aging={"cju": None})
        self.assertEqual(result["status"], "needs_review")       # 못 읽으면 pass로 추정하지 않음
        result, _ = run01(ubuntu_fs(), aging={"cju": {"min_days": 1, "max_days": -1}})
        self.assertEqual(status_of(result, "account_max_days(cju)"), {"vulnerable"})
        result, _ = run01(ubuntu_fs(), accounts=(), aging={})
        self.assertEqual(status_of(result, "account_aging"), {"needs_review"})

    def test_rocky_default_is_vulnerable(self):
        result, _ = run01(rocky_fs(ROCKY_SYSTEM_AUTH_DEFAULT, **{"/etc/security/pwquality.conf": "# minlen = 8\n"}))
        self.assertEqual(result["status"], "vulnerable")
        self.assertEqual(status_of(result, "complexity_classes"), {"vulnerable"})
        self.assertEqual(len(items(result, "nullok")), 2)        # system-auth, password-auth 각각
        self.assertEqual(status_of(result, "nullok"), {"vulnerable"})

    def test_required_file_failures_are_error(self):
        for path, value in (("/etc/login.defs", None), ("/etc/pam.d/common-password", ERROR),
                            ("/etc/pam.d/common-auth", None), ("/etc/os-release", ERROR)):
            with self.subTest(path):
                self.assertEqual(run01(ubuntu_fs(**{path: value}))[0]["status"], "error")
        result, _ = run01(ubuntu_fs(**{"/etc/security/pwquality.conf": ERROR}))
        self.assertEqual(result["status"], "error")

    def test_unsupported_os_and_bad_override(self):
        result, _ = run01(ubuntu_fs(**{"/etc/os-release": "ID=debian\n"}))
        self.assertEqual(result["status"], "not_applicable")
        result, _ = run01(ubuntu_fs(), accounts=("cju;id",))
        self.assertEqual(result["status"], "error")

    def test_reads_only_expected_files(self):
        result, fake = run01(ubuntu_fs())
        self.assertEqual(set(fake.read_paths), {
            "/etc/os-release", "/etc/login.defs", "/etc/pam.d/common-password", "/etc/pam.d/common-auth",
            "/etc/security/pwquality.conf"})
        self.assertNotIn("/etc/shadow", fake.read_paths)
        self.assertEqual(fake.chage_accounts, ["cju"])


# ==================================================
# ACC-02 계정 잠금 정책
# ==================================================
class Acc02Test(unittest.TestCase):
    def test_all_good_is_pass(self):
        result, _ = run02(ubuntu_fs())
        self.assertEqual(result["status"], "pass", result["evidence"])
        self.assertEqual(result["severity"], "medium")

    def test_current_vm_state_is_vulnerable(self):
        result, _ = run02(ubuntu_vm_fs())
        self.assertEqual(result["status"], "vulnerable")
        self.assertEqual(items(result, "faillock_connection")[0]["actual"], "not connected")
        self.assertEqual(items(result, "deny"), [])              # 연결이 없으면 설정값은 판정하지 않음

    def test_partial_configuration_needs_review(self):
        result, _ = run02(ubuntu_fs(**{"/etc/pam.d/common-account": UBUNTU_ACCOUNT_DEFAULT}))
        self.assertEqual(result["status"], "needs_review")
        auth = UBUNTU_AUTH_FAILLOCK.replace("auth\t[default=die]\t\t\tpam_faillock.so authfail\n", "")
        result, _ = run02(ubuntu_fs(**{"/etc/pam.d/common-auth": auth}))
        self.assertEqual(result["status"], "needs_review")

    def test_wrong_order_or_control_needs_review(self):
        auth = ("auth required pam_faillock.so authfail\n"
                "auth [success=1 default=ignore] pam_unix.so\n"
                "auth required pam_faillock.so preauth\n")
        result, _ = run02(ubuntu_fs(**{"/etc/pam.d/common-auth": auth}))
        self.assertEqual(status_of(result, "faillock_connection"), {"needs_review"})
        auth = UBUNTU_AUTH_FAILLOCK.replace("required\t\t\tpam_faillock.so preauth", "optional pam_faillock.so preauth")
        result, _ = run02(ubuntu_fs(**{"/etc/pam.d/common-auth": auth}))
        self.assertEqual(status_of(result, "faillock_connection"), {"needs_review"})

    def test_deny_range(self):
        for deny, expected in ((1, "pass"), (5, "pass"), (10, "pass"), (0, "vulnerable"), (11, "vulnerable")):
            with self.subTest(deny=deny):
                conf = FAILLOCK_GOOD.replace("deny = 5", f"deny = {deny}")
                result, _ = run02(ubuntu_fs(**{"/etc/security/faillock.conf": conf}))
                self.assertEqual(status_of(result, "deny"), {expected})

    def test_unlock_time(self):
        for value, expected in (("600", "pass"), ("1800", "pass"), ("300", "vulnerable"),
                                ("0", "needs_review"), ("never", "needs_review")):
            with self.subTest(value=value):
                conf = FAILLOCK_GOOD.replace("unlock_time = 600", f"unlock_time = {value}")
                result, _ = run02(ubuntu_fs(**{"/etc/security/faillock.conf": conf}))
                self.assertEqual(status_of(result, "unlock_time"), {expected})

    def test_short_fail_interval_needs_review(self):
        conf = FAILLOCK_GOOD.replace("fail_interval = 900", "fail_interval = 300")
        result, _ = run02(ubuntu_fs(**{"/etc/security/faillock.conf": conf}))
        self.assertEqual(result["status"], "needs_review")

    def test_module_args_override_conf(self):
        auth = UBUNTU_AUTH_FAILLOCK.replace("preauth", "preauth deny=20").replace("authfail", "authfail deny=20")
        result, _ = run02(ubuntu_fs(**{"/etc/pam.d/common-auth": auth}))
        self.assertEqual(items(result, "deny")[0]["actual"], 20)
        self.assertEqual(result["status"], "vulnerable")
        auth = UBUNTU_AUTH_FAILLOCK.replace("preauth", "preauth deny=3").replace("authfail", "authfail deny=5")
        result, _ = run02(ubuntu_fs(**{"/etc/pam.d/common-auth": auth}))
        self.assertEqual(status_of(result, "faillock_settings"), {"needs_review"})

    def test_conf_missing_uses_defaults(self):
        result, _ = run02(ubuntu_fs(**{"/etc/security/faillock.conf": None}))
        self.assertEqual(items(result, "deny")[0]["actual"], 3)
        self.assertEqual(result["status"], "pass")

    def test_legacy_tally_needs_review(self):
        auth = "auth required pam_tally2.so deny=5\n" + UBUNTU_AUTH_DEFAULT
        result, _ = run02(ubuntu_fs(**{"/etc/pam.d/common-auth": auth,
                                       "/etc/pam.d/common-account": UBUNTU_ACCOUNT_DEFAULT}))
        self.assertEqual(result["status"], "needs_review")

    def test_read_failures_are_error(self):
        for path, value in (("/etc/pam.d/common-auth", None), ("/etc/pam.d/common-account", ERROR),
                            ("/etc/security/faillock.conf", ERROR), ("/etc/os-release", None)):
            with self.subTest(path):
                self.assertEqual(run02(ubuntu_fs(**{path: value}))[0]["status"], "error")

    def test_rocky_profiles(self):
        result, fake = run02(rocky_fs(ROCKY_SYSTEM_AUTH_FAILLOCK))
        self.assertEqual(result["status"], "pass", result["evidence"])
        self.assertIn("/etc/pam.d/password-auth", fake.read_paths)
        result, _ = run02(rocky_fs(ROCKY_SYSTEM_AUTH_DEFAULT))
        self.assertEqual(result["status"], "vulnerable")
        # system-auth에만 연결되고 password-auth(sshd 사용)에는 없으면 vulnerable
        files = rocky_fs(ROCKY_SYSTEM_AUTH_FAILLOCK, **{"/etc/pam.d/password-auth": ROCKY_SYSTEM_AUTH_DEFAULT})
        result, _ = run02(files)
        self.assertEqual(result["status"], "vulnerable")


# ==================================================
# 결과 형식 (v1.1 / v1.2) 및 민감정보
# ==================================================
class ResultFormatTest(unittest.TestCase):
    SECRET_TEXT = re.compile(r"\b(?:password|token|api[_-]?key|secret|cookie)\s*[:=]\s*\S+", re.I)
    SECRET_KEY = re.compile(r"^(?:password|passwd|token|access_token|refresh_token|api_key|"
                            r"secret|private_key|cookie|authorization)$", re.I)

    def all_results(self, version):
        vm = ubuntu_vm_fs()
        return [run01(vm, aging={"cju": {"min_days": 0, "max_days": 99999}}, version=version)[0],
                run01(ubuntu_fs(), version=version)[0],
                run02(vm, version=version)[0],
                run02(ubuntu_fs(), version=version)[0]]

    def keys(self, value):
        if isinstance(value, dict):
            for key, item in value.items():
                yield key
                yield from self.keys(item)
        elif isinstance(value, list):
            for item in value:
                yield from self.keys(item)

    def test_v1_1_fields(self):
        for result in self.all_results("1.1"):
            self.assertEqual(set(result) - {"details"},
                             {"check_id", "status", "severity", "evidence", "recommendation"})

    def test_v1_2_cvss(self):
        vulnerable_01, pass_01, vulnerable_02, pass_02 = self.all_results("1.2")
        for result in (vulnerable_01, vulnerable_02):
            self.assertNotIn("severity", result)
            self.assertEqual(result["cvss"]["assessment_status"], "pending")
            self.assertIsNone(result["cvss"]["base_score"])
        for result in (pass_01, pass_02):
            self.assertEqual(result["cvss"]["assessment_status"], "not_applicable")

    def test_no_secret_like_text_or_keys(self):
        for result in self.all_results("1.2"):
            self.assertIsNone(self.SECRET_TEXT.search(json.dumps(result, ensure_ascii=False)))
            self.assertFalse([k for k in self.keys(result) if self.SECRET_KEY.match(k)])

    def test_policy_load_failure(self):
        self.assertEqual(acc01.run_check("missing.json")["severity"], "high")
        self.assertEqual(acc02.run_check("missing.json", result_version="1.2")["status"], "error")
        with self.assertRaises(ValueError):
            acc01.run_check(result_version="2.0")


# ==================================================
# 공통 도우미
# ==================================================
class CommonTest(unittest.TestCase):
    def test_parse_pam_handles_brackets_comments_and_dash(self):
        entries = account_common.parse_pam(
            "# c\n-auth [success=1 default=ignore] /usr/lib/security/pam_unix.so nullok # tail\n@include x\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["type"], "auth")
        self.assertEqual(entries[0]["control"], "[success=1 default=ignore]")
        self.assertEqual(entries[0]["module"], "pam_unix.so")
        self.assertEqual(entries[0]["args"], ["nullok"])

    def test_parse_chage(self):
        output = ("Last password change\t\t\t\t\t: Nov 04, 2026\n"
                  "Minimum number of days between password change\t\t: 0\n"
                  "Maximum number of days between password change\t\t: 99999\n")
        self.assertEqual(account_common.parse_chage(output), {"min_days": 0, "max_days": 99999})
        self.assertIsNone(account_common.parse_chage("unexpected"))

    def test_run_chage_rejects_bad_names(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("must not run")):
            self.assertIsNone(account_common.run_chage("cju;id"))
            self.assertIsNone(account_common.run_chage("../root"))


if __name__ == "__main__":
    unittest.main()
