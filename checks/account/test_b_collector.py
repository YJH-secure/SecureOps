"""
B 읽기 전용 수집기 Mock 테스트

실제 서버 파일을 읽거나 명령을 실행하지 않습니다.
"가짜 대상 서버"(파일·폴더·명령 결과 사전)를 만들어 수집기를 실행하고 확인합니다.
  1) 수집기 출력 -> 어댑터 판정 = 기존 단독 실행(run_check) / 순수 판정 결과
  2) 실패를 빈 값·정상으로 바꾸지 않고 항목 state로 기록
  3) 허용된 명령(sshd -T, sshd -T -C, chage -l)만 실행, 정책 계정만 조회
  4) 시간 예산·출력 상한, 인자 금지, root 소유 설정 파일 검사

실행: python -m unittest test_b_collector -v
"""

import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import acc_lockout_check as acc02
import acc_password_check as acc01
import b_collector as collector
import central_adapter as adapter
import ssh_auth_check
from test_account_checks import (ERROR, FakeSystem, GOOD_AGING, ROCKY_SYSTEM_AUTH_FAILLOCK,
                                 rocky_fs, ubuntu_fs, ubuntu_vm_fs)
from test_central_adapter import CHAGE_GOOD
from test_ssh_auth_check import make_output

CONTEXT = {"host": "192.0.2.10", "addr": "192.0.2.10"}      # 문서용 IP
SSHD = collector.SSHD_PATH
CHAGE = collector.CHAGE_PATH
SSH_POLICY = ssh_auth_check.load_policy()
SSH_USERS = SSH_POLICY["criteria"]["test_connection"]["users"]
GOOD_SSHD = make_output(allowusers=["secureops-scan", "secureops-fix"])
SSHD_CONFIG_TEXT = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n"
DROPIN_TEXT = "PasswordAuthentication no\n"
TIMEOUT = object()      # 명령 시간 초과 표시
CONFIG = collector.CONFIG_PATH
CONFIG_DIR = "/etc/secureops"
CONFIG_TEXT = json.dumps(CONTEXT)


# 가짜 파일 정보 (종류, 권한, 소유자)
def fake_stat(kind="file", mode=0o644, uid=0):
    type_bits = {"file": stat.S_IFREG, "dir": stat.S_IFDIR, "link": stat.S_IFLNK}[kind]
    return os.stat_result((type_bits | mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))


def spec(user, context=CONTEXT):
    return f"user={user},host={context['host']},addr={context['addr']}"


# ---------- 가짜 대상 서버 ----------
class FakeTarget:
    """files : {경로: 내용 | None(없음) | ERROR(권한 부족)}
    dirs     : {폴더: [이름...] | ERROR}  (없으면 폴더 없음)
    commands : {(명령...): 출력 | (종료코드, 출력) | TIMEOUT}  (없으면 실행 실패)"""

    def __init__(self, files, dirs=None, commands=None, clock=None, stats=None):
        self.files = dict(files)
        self.dirs = dict(dirs or {})
        self.commands = dict(commands or {})
        self.ran = []
        self.clock = clock or [0.0]
        self.stats = dict(stats or {})        # 설정 파일·폴더의 소유자·권한

    def lstat(self, path):
        if path not in self.stats:
            raise FileNotFoundError(path)
        return self.stats[path]

    def read_bytes(self, path, limit):
        value = self.files.get(path)
        if path not in self.files or value is None:
            raise FileNotFoundError(path)
        if value is ERROR:
            raise PermissionError(path)
        return value.encode("utf-8")[:limit] if isinstance(value, str) else value[:limit]

    def listdir(self, path):
        if path not in self.dirs:
            raise FileNotFoundError(path)
        if self.dirs[path] is ERROR:
            raise PermissionError(path)
        return list(self.dirs[path])

    def is_regular(self, path):
        return path in self.files and self.files[path] is not None

    def run(self, argv, timeout):
        self.ran.append(tuple(argv))
        result = self.commands.get(tuple(argv))
        if result is None:
            raise FileNotFoundError(argv[0])
        if result is TIMEOUT:
            raise subprocess.TimeoutExpired(argv, timeout)
        code, out = result if isinstance(result, tuple) else (0, result)
        return subprocess.CompletedProcess(argv, code, out.encode("utf-8") if isinstance(out, str) else out, b"")

    def __enter__(self):
        self.patches = [
            mock.patch.object(collector, "_read_bytes", side_effect=self.read_bytes),
            mock.patch.object(collector, "_listdir", side_effect=self.listdir),
            mock.patch.object(collector, "_is_regular", side_effect=self.is_regular),
            mock.patch.object(collector, "_run", side_effect=self.run),
            mock.patch.object(collector, "_now", side_effect=lambda: self.clock[0]),
            mock.patch.object(collector, "_lstat", side_effect=self.lstat),
            mock.patch("subprocess.run", side_effect=AssertionError("no real command")),
        ]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


# 정상 상태의 가짜 서버 (ACC 파일 + SSH 설정 + 명령 결과)
def target(acc_fs=None, ssh_files=None, dirs=None, commands=None, stats=None, **kw):
    files = dict(acc_fs if acc_fs is not None else ubuntu_fs())
    files.update({SSHD: "binary", "/etc/ssh/sshd_config": SSHD_CONFIG_TEXT,
                  "/etc/ssh/sshd_config.d/50-local.conf": DROPIN_TEXT, CONFIG: CONFIG_TEXT})
    all_stats = {CONFIG_DIR: fake_stat("dir", 0o755), CONFIG: fake_stat("file", 0o644)}
    all_stats.update(stats or {})
    files.update(ssh_files or {})
    all_dirs = {"/etc/ssh/sshd_config.d": ["50-local.conf"]}
    all_dirs.update(dirs or {})
    all_commands = {(SSHD, "-T"): GOOD_SSHD}
    all_commands.update({(SSHD, "-T", "-C", spec(u)): GOOD_SSHD for u in SSH_USERS})
    all_commands[(CHAGE, "-l", "user1")] = CHAGE_GOOD
    all_commands.update(commands or {})
    return FakeTarget(files, all_dirs, all_commands, stats=all_stats, **kw)


def write_policy(path_holder, mutate):
    with open(acc01.POLICY_FILE, encoding="utf-8") as f:
        data = json.load(f)
    mutate(data["policies"][0]["criteria"])
    handle, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(handle, "w", encoding="utf-8") as f:
        json.dump(data, f)
    path_holder.append(path)
    return path


def judge(check_id, document, policy_path=None, context=CONTEXT):
    return adapter.judge_payload(check_id, document["payloads"][check_id], context,
                                 policy_path=policy_path, result_version="1.1")


class CollectorBase(unittest.TestCase):
    def setUp(self):
        self.paths = []

    def tearDown(self):
        for path in self.paths:
            os.remove(path)


# ==================================================
# 1. 수집기 -> 어댑터 결과 = 기존 판정 결과
# ==================================================
class EquivalenceTest(CollectorBase):
    def test_acc_matches_run_check(self):
        policy_path = write_policy(self.paths, lambda c: c.update(interactive_accounts=["user1"]))
        cases = {
            "ubuntu_good": ubuntu_fs(),
            "ubuntu_vm_default": ubuntu_vm_fs(),
            "faillock_conf_missing": ubuntu_fs(**{"/etc/security/faillock.conf": None}),
            "pam_unreadable": ubuntu_fs(**{"/etc/pam.d/common-auth": ERROR}),
            "rocky": rocky_fs(ROCKY_SYSTEM_AUTH_FAILLOCK),
        }
        for name, fs in cases.items():
            with self.subTest(case=name):
                with FakeSystem(fs, aging={"user1": GOOD_AGING}):
                    expected01 = acc01.run_check(policy_path)
                    expected02 = acc02.run_check(policy_path)
                with target(fs):
                    document = collector.collect(CONTEXT, acc_policy_path=policy_path)
                self.assertEqual(judge("ACC-01", document, policy_path), expected01)
                self.assertEqual(judge("ACC-02", document, policy_path), expected02)

    def test_conf_d_files_are_collected(self):
        conf = "/etc/security/pwquality.conf.d/50-local.conf"
        fs = ubuntu_fs(**{conf: "minlen = 12\n"})
        with FakeSystem(fs, conf_d={conf: "minlen = 12\n"}, aging={}):
            expected = acc01.run_check()
        with target(fs, dirs={"/etc/security/pwquality.conf.d": ["50-local.conf", "README"]}):
            document = collector.collect(CONTEXT)
        payload = document["payloads"]["ACC-01"]
        self.assertEqual(payload["pwquality_conf_d"], {"state": "ok", "paths": [conf]})   # *.conf만
        self.assertEqual(judge("ACC-01", document), expected)

    def test_ssh_02_matches_direct_judge(self):
        merged = ("Include /etc/ssh/sshd_config.d/*.conf\n" + DROPIN_TEXT + "\n" + "PermitRootLogin no\n")
        for name, user_output in {"good": GOOD_SSHD,
                                  "password_on": make_output(passwordauthentication="yes")}.items():
            with self.subTest(case=name):
                commands = {(SSHD, "-T", "-C", spec(u)): user_output for u in SSH_USERS}
                with target(commands=commands):
                    document = collector.collect(CONTEXT)
                payload = document["payloads"]["SSH-02"]
                self.assertEqual(payload["sshd_config"], {"state": "ok", "text": merged})
                expected = ssh_auth_check.check_ssh_02(SSH_POLICY, GOOD_SSHD, merged,
                                                       {u: user_output for u in SSH_USERS})
                self.assertEqual(judge("SSH-02", document), expected)


# ==================================================
# 2. 실패를 항목 state로 기록
# ==================================================
class RecordTest(CollectorBase):
    def test_file_states(self):
        fs = ubuntu_fs(**{"/etc/security/pwquality.conf": None, "/etc/pam.d/common-auth": ERROR,
                          "/etc/login.defs": "x" * (collector.MAX_ITEM_BYTES + 1)})
        fs["/etc/pam.d/common-password"] = b"\xff\xfe not utf-8"
        with target(fs):
            files = collector.collect(CONTEXT)["payloads"]["ACC-01"]["files"]
        self.assertEqual(files["/etc/security/pwquality.conf"], {"state": "missing"})
        self.assertEqual(files["/etc/pam.d/common-auth"], {"state": "error"})
        self.assertEqual(files["/etc/login.defs"], {"state": "truncated"})
        self.assertEqual(files["/etc/pam.d/common-password"], {"state": "error"})

    def test_command_states(self):
        commands = {(SSHD, "-T"): (255, "bad config"), (SSHD, "-T", "-C", spec(SSH_USERS[0])): TIMEOUT}
        with target(commands=commands) as fake:
            del fake.commands[(SSHD, "-T", "-C", spec(SSH_USERS[1]))]       # 실행 자체 실패
            payload = collector.collect(CONTEXT)["payloads"]["SSH-02"]
        self.assertEqual(payload["sshd_T"], {"state": "error", "exit_code": 255})
        self.assertEqual(payload["sshd_T_C"][SSH_USERS[0]], {"state": "timeout"})
        self.assertEqual(payload["sshd_T_C"][SSH_USERS[1]], {"state": "error"})
        self.assertEqual(payload["sshd_T_C"][SSH_USERS[1]].get("text"), None)   # stderr 내용 없음

    def test_ok_command_has_exit_code_zero(self):
        with target():
            payload = collector.collect(CONTEXT)["payloads"]["SSH-02"]
        self.assertEqual(payload["sshd_T"]["exit_code"], 0)
        self.assertEqual(payload["sshd_T"]["state"], "ok")

    def test_unreadable_include_dir_is_error_not_empty(self):
        # Rocky sshd_config.d(700)를 root가 아닌 권한으로 읽는 상황 -> 빈 Include로 넘기지 않음
        for dirs in ({"/etc/ssh/sshd_config.d": ERROR},):
            with self.subTest(dirs=dirs):
                with target(dirs=dirs):
                    document = collector.collect(CONTEXT)
                self.assertEqual(document["payloads"]["SSH-02"]["sshd_config"], {"state": "error"})
                self.assertEqual(judge("SSH-02", document)["status"], "error")

    def test_include_failures(self):
        cases = {
            "main_missing": {"/etc/ssh/sshd_config": None},
            "main_unreadable": {"/etc/ssh/sshd_config": ERROR},
            "dropin_unreadable": {"/etc/ssh/sshd_config.d/50-local.conf": ERROR},
        }
        for name, files in cases.items():
            with self.subTest(case=name):
                with target(ssh_files=files):
                    payload = collector.collect(CONTEXT)["payloads"]["SSH-02"]
                self.assertEqual(payload["sshd_config"], {"state": "error"})

    def test_include_dir_missing_is_ok(self):
        with target(ssh_files={"/etc/ssh/sshd_config.d/50-local.conf": None},
                    dirs={"/etc/ssh/sshd_config.d": []}) as fake:
            del fake.dirs["/etc/ssh/sshd_config.d"]
            payload = collector.collect(CONTEXT)["payloads"]["SSH-02"]
        self.assertEqual(payload["sshd_config"]["state"], "ok")

    def test_sshd_not_installed(self):
        with target(ssh_files={SSHD: None}) as fake:
            document = collector.collect(CONTEXT)
        self.assertEqual(document["payloads"]["SSH-02"], {"sshd_installed": False})
        self.assertFalse(any(cmd[0] == SSHD for cmd in fake.ran))
        self.assertEqual(judge("SSH-02", document)["status"], "not_applicable")

    def test_conf_d_listing_failure(self):
        with target(dirs={"/etc/security/pwquality.conf.d": ERROR}):
            document = collector.collect(CONTEXT)
        self.assertEqual(document["payloads"]["ACC-01"]["pwquality_conf_d"], {"state": "error"})
        self.assertEqual(judge("ACC-01", document)["status"], "error")

    def test_unknown_or_unsupported_os_sends_os_release_only(self):
        for os_text in ('ID=debian\nVERSION_ID="12"\n', 'NAME="x"\n', ERROR):
            with self.subTest(os_text=os_text):
                with target(ubuntu_fs(**{"/etc/os-release": os_text})) as fake:
                    document = collector.collect(CONTEXT)
                self.assertEqual(document["payloads"]["ACC-01"]["files"], {})
                self.assertEqual(document["payloads"]["ACC-02"]["files"], {})
                self.assertFalse(any(cmd[0] == CHAGE for cmd in fake.ran))


# ==================================================
# 3. 허용 명령·정책 계정만
# ==================================================
class SafetyTest(CollectorBase):
    def test_only_allowed_commands(self):
        policy_path = write_policy(self.paths, lambda c: c.update(interactive_accounts=["user1"]))
        with target() as fake:
            collector.collect(CONTEXT, acc_policy_path=policy_path)
        allowed = {(SSHD, "-T"), (CHAGE, "-l", "user1")}
        allowed |= {(SSHD, "-T", "-C", spec(u)) for u in SSH_USERS}
        self.assertEqual(set(fake.ran), allowed)
        self.assertNotIn("/etc/shadow", fake.files)

    def test_accounts_only_from_policy(self):
        with target() as fake:                                   # 실제 정책 : interactive_accounts 빈 목록
            document = collector.collect(CONTEXT)
        self.assertEqual(document["payloads"]["ACC-01"]["chage"], {})
        self.assertFalse(any(cmd[0] == CHAGE for cmd in fake.ran))
        self.assertEqual(set(document["payloads"]["SSH-02"]["sshd_T_C"]), set(SSH_USERS))

    def test_any_argument_is_rejected(self):
        # sudoers 인자 금지("")와 같은 기준 : 수집기도 인자를 받지 않음
        for args in (["--user", "root"], ["--host", "h", "--addr", "a"], ["x"]):
            with self.subTest(args=args):
                out = io.StringIO()
                with target() as fake:
                    self.assertEqual(collector.main(args, out=out), 2)
                self.assertEqual(fake.ran, [])

    def test_context_is_reflected(self):
        with target():
            document = collector.collect(CONTEXT)
        self.assertEqual(document["context_used"], CONTEXT)
        self.assertEqual(document["collector"]["name"], "secureops-b-read")


# ==================================================
# 4. 시간 예산·출력·인자
# ==================================================
class LimitTest(CollectorBase):
    def test_budget_exhaustion_marks_remaining_as_timeout(self):
        clock = [0.0]
        with target(clock=clock) as fake:
            original = fake.run

            def slow_run(argv, timeout):
                clock[0] += 30                                   # 명령마다 30초 걸린다고 가정
                return original(argv, timeout)
            fake.run = slow_run
            collector._run.side_effect = slow_run
            payload = collector.collect(CONTEXT)["payloads"]["SSH-02"]
        self.assertEqual(payload["sshd_T"]["state"], "ok")                     # 0초 시작
        self.assertEqual(payload["sshd_T_C"][SSH_USERS[0]]["state"], "ok")     # 30초 시점 (남은 20초)
        self.assertEqual(payload["sshd_T_C"][SSH_USERS[1]], {"state": "timeout"})   # 60초 시점

    def test_main_outputs_single_json(self):
        out = io.StringIO()
        with target():
            code = collector.main([], out=out)
        self.assertEqual(code, 0)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        document = json.loads(lines[0])
        self.assertEqual(set(document["payloads"]), {"SSH-02", "ACC-01", "ACC-02"})
        self.assertEqual(document["context_used"], CONTEXT)              # 설정 파일 값 사용

    def test_output_limit_is_below_a_transport_limit(self):
        # B 상한(종료 코드 3)이 A 상한(1MiB, 절단 후 실행 실패)보다 먼저 걸려야 함
        self.assertLess(collector.MAX_OUTPUT_BYTES, 1024 * 1024)
        self.assertGreaterEqual(1024 * 1024 - collector.MAX_OUTPUT_BYTES, 32 * 1024)

    def test_exit_codes_stay_in_0_to_4(self):
        # 255는 A에서 SSH 자체 오류로 분류하므로 사용하지 않음
        cases = [
            ([], {}),                                                           # 정상 0
            (["x"], {}),                                                        # 인자 2
            ([], {"stats": {CONFIG: fake_stat("file", 0o666)}}),               # 설정 4
        ]
        for args, kw in cases:
            with self.subTest(args=args, kw=kw):
                out = io.StringIO()
                with target(**kw):
                    code = collector.main(args, out=out)
                self.assertIn(code, {0, 1, 2, 3, 4})
                self.assertNotEqual(code, 255)

    def test_budget_is_within_a_transport_limit(self):
        # A 전체 60초 = SSH 연결 최대 10초 + 수집 + 여유 -> 수집 예산 45초 이하
        self.assertLessEqual(collector.TOTAL_BUDGET, 45)

    def test_output_too_large(self):
        out = io.StringIO()
        with target(), mock.patch.object(collector, "MAX_OUTPUT_BYTES", 100):
            code = collector.main([], out=out)
        self.assertEqual(code, 3)
        self.assertIn("output too large", out.getvalue())

    def test_policy_failure(self):
        out = io.StringIO()
        with target(), mock.patch.object(collector.acc01, "load_policy", side_effect=ValueError("bad")):
            code = collector.main([], out=out)
        self.assertEqual(code, 4)

    def test_unexpected_error_writes_no_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        with target(), mock.patch.object(collector, "collect", side_effect=RuntimeError("boom")), \
                mock.patch("sys.stderr", err):
            code = collector.main([], out=out)
        self.assertEqual(code, 1)
        self.assertEqual(err.getvalue(), "")
        self.assertIn("unexpected error", out.getvalue())


# ==================================================
# 5. root 소유 설정 파일 (/etc/secureops/b-read.json)
# ==================================================
class ConfigTest(CollectorBase):
    def run_main(self, **target_kw):
        out = io.StringIO()
        with target(**target_kw) as fake:
            code = collector.main([], out=out)
        return code, out.getvalue(), fake

    def test_invalid_config_is_rejected_before_any_command(self):
        cases = {
            "file_unreadable": {"ssh_files": {CONFIG: ERROR}},
            "file_symlink": {"stats": {CONFIG: fake_stat("link", 0o777)}},
            "file_not_root": {"stats": {CONFIG: fake_stat("file", 0o644, uid=1000)}},
            "file_group_writable": {"stats": {CONFIG: fake_stat("file", 0o664)}},
            "file_other_writable": {"stats": {CONFIG: fake_stat("file", 0o646)}},
            "dir_symlink": {"stats": {CONFIG_DIR: fake_stat("link", 0o777)}},
            "dir_not_root": {"stats": {CONFIG_DIR: fake_stat("dir", 0o755, uid=1000)}},
            "dir_other_writable": {"stats": {CONFIG_DIR: fake_stat("dir", 0o757)}},
            "not_json": {"ssh_files": {CONFIG: "host=a"}},
            "extra_key": {"ssh_files": {CONFIG: json.dumps(dict(CONTEXT, user="root"))}},
            "missing_addr": {"ssh_files": {CONFIG: json.dumps({"host": "h"})}},
            "bad_host": {"ssh_files": {CONFIG: json.dumps({"host": "a,b", "addr": "1"})}},
            "bad_addr": {"ssh_files": {CONFIG: json.dumps({"host": "h", "addr": "1 2"})}},
            "not_object": {"ssh_files": {CONFIG: json.dumps(["h", "a"])}},
        }
        for name, kw in cases.items():
            with self.subTest(case=name):
                code, output, fake = self.run_main(**kw)
                self.assertEqual(code, 4)
                self.assertIn("config invalid", output)
                self.assertEqual(fake.ran, [])                  # 명령 실행 전 중단

    def test_missing_config_is_rejected(self):
        out = io.StringIO()
        with target() as fake:
            del fake.stats[CONFIG]                               # 설정 파일이 아예 없음
            code = collector.main([], out=out)
        self.assertEqual(code, 4)
        self.assertEqual(fake.ran, [])


if __name__ == "__main__":
    unittest.main()
