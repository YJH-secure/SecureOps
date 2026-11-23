#!/usr/bin/env python3
"""
B 읽기 전용 수집기 (설계 초안, 2026-11-23) - SSH-02, ACC-01, ACC-02

[하는 일]
대상 서버에서 정해진 파일과 명령 결과만 읽어서
B/D 매핑표 v1 모양의 payload JSON 1개를 표준 출력으로 내보냅니다.
판정은 하지 않습니다. (판정은 중앙의 central_adapter.judge_payload가 담당)

  (중앙) A 전송 계층 --고정 명령--> (대상) sudo -n secureops-b-read
                                         └ 이 파일 실행 -> payload JSON 1개 출력

[안전 원칙]
- 읽기 전용 : 파일 읽기, sshd -T, sshd -T -C, chage -l 만 실행 (쓰기·변경 명령 없음)
- 명령은 절대 경로 고정, 셸을 거치지 않음 (shell=True 사용 안 함), 환경 변수 고정
- 계정 목록은 정책 JSON에서만 읽음 (호출하는 쪽이 계정을 넘길 수 없음)
- 비밀번호 해시를 읽지 않음 (/etc/shadow 직접 읽지 않음, chage -l은 기간 정보만)
- stderr 내용은 payload에 넣지 않음 (내부 정보 노출 방지)
- 항목 하나가 실패해도 멈추지 않고 그 항목만 error / missing / timeout / truncated로 기록
- 명령별 10초, 전체 40초 예산 (A 전송 계층 60초 = SSH 연결 최대 10초 + 수집 + 여유)
- 출력 전체 1MiB 미만 (A 전송 계층 stdout 상한)
- 실행 인자를 받지 않음 (sudoers에서 인자 금지 "" 와 함께 사용)
- host/addr는 대상 서버의 root 소유 설정 파일에서만 읽음 (/etc/secureops/b-read.json)
  소유자 root, 그룹·기타 쓰기 불가, 심볼릭 링크 아님을 확인하고 아니면 거부
- 표준 오류(stderr)에 아무것도 쓰지 않음 (A·D는 stderr가 있으면 STOP)

[설정 파일 예] /etc/secureops/b-read.json  (root:root, 0644, 폴더 /etc/secureops도 root 소유·0755)
{"host": "192.0.2.10", "addr": "192.0.2.10"}

[종료 코드]
0 : payload 출력 (항목별 실패는 payload 안의 state로 전달)
1 : 예상하지 못한 오류
2 : 실행 인자가 있음 (인자는 받지 않음)
3 : 출력이 상한을 넘음
4 : 설정·정책 파일 오류 (설치 문제)

[설치 예 (승인 후, SSH-01 수집기와 같은 절차)]
install -o root -g root -m 0755 b_collector.py /usr/local/sbin/secureops-b-read  (함께 쓰는 모듈 배치는 승인 요청서에서 확정)
/etc/sudoers.d/secureops-b-read (0440) : secureops-scan ALL=(root) NOPASSWD: /usr/local/sbin/secureops-b-read ""

※ 설치 위치·대상 환경·sudoers는 승인 전 미확정입니다.
"""

import fnmatch     # Include 파일 이름 패턴(*.conf) 맞추기
import json
import os
import posixpath
import stat
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import account_common as common     # noqa: E402  os-release 해석, 계정 이름 규칙
import acc_lockout_check as acc02   # noqa: E402  ACC-02 정책 읽기
import acc_password_check as acc01  # noqa: E402  ACC-01 정책 읽기
import ssh_auth_check as ssh02      # noqa: E402  SSH-02 정책 읽기, host/addr 형식 검사
import ssh_check                    # noqa: E402  sshd_config 한 줄 나누기


COLLECTOR_NAME = "secureops-b-read"
COLLECTOR_VERSION = "0.1-draft"

SSHD_PATH = "/usr/sbin/sshd"          # Ubuntu·Rocky 공통 위치 (PATH 검색 안 함)
CHAGE_PATH = "/usr/bin/chage"
SSHD_CONFIG = "/etc/ssh/sshd_config"
OS_RELEASE = "/etc/os-release"
CONFIG_PATH = "/etc/secureops/b-read.json"   # host/addr 설정 (root 소유)
CONFIG_KEYS = {"host", "addr"}
SAFE_ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}   # 영어 출력, 고정 경로

COMMAND_TIMEOUT = 10                  # 명령 1개 최대 시간(초)
TOTAL_BUDGET = 40                     # 수집 전체 최대 시간(초), A 60초 안에서 연결 10초 + 여유
MAX_ITEM_BYTES = 256 * 1024           # 파일·명령 출력 1개 최대 크기
MAX_OUTPUT_BYTES = 1024 * 1024 - 1    # 최종 JSON 최대 크기 (1MiB 미만)


# ==================================================
# 1. 시스템과 닿는 부분 (테스트에서 가짜로 바꿀 수 있게 작게 분리)
# ==================================================

# 파일을 최대 limit 바이트까지 읽습니다. 일반 파일이 아니면 OSError
def _read_bytes(path, limit):
    info = os.stat(path)                       # 링크는 따라감 (Rocky PAM -> /etc/authselect)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("not a regular file")
    with open(path, "rb") as f:
        return f.read(limit)


def _listdir(path):
    return os.listdir(path)


def _is_regular(path):
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def _run(argv, timeout):
    return subprocess.run(argv, capture_output=True, timeout=timeout, env=SAFE_ENV, shell=False)


def _now():
    return time.monotonic()


def _lstat(path):
    return os.lstat(path)                      # 링크를 따라가지 않고 링크 자체 정보


# ==================================================
# 1-1. 설정 파일 (host/addr) 읽기
#   - 파일과 폴더 모두 : 심볼릭 링크 아님, 소유자 root, 그룹·기타 쓰기 불가
#   - 내용 : {"host": ..., "addr": ...} 정확히 두 키, 공백·쉼표 없는 글자
#   - 하나라도 어긋나면 ValueError (종료 코드 4)
# ==================================================

def _check_owner(path, want_dir):
    info = _lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"symlink not allowed: {path}")
    if want_dir != stat.S_ISDIR(info.st_mode) or (not want_dir and not stat.S_ISREG(info.st_mode)):
        raise ValueError(f"unexpected file type: {path}")
    if info.st_uid != 0:
        raise ValueError(f"owner is not root: {path}")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"writable by group or others: {path}")


def load_config(path=CONFIG_PATH):
    _check_owner(posixpath.dirname(path), want_dir=True)
    _check_owner(path, want_dir=False)
    record = read_file(path)
    if record["state"] != "ok":
        raise ValueError("config unreadable")
    data = json.loads(record["text"])
    if not isinstance(data, dict) or set(data) != CONFIG_KEYS:
        raise ValueError("config must have exactly host and addr")
    if not all(ssh02.is_safe_name(data[key]) for key in CONFIG_KEYS):
        raise ValueError("invalid host/addr")
    return {"host": data["host"], "addr": data["addr"]}


# ==================================================
# 2. 기록(record) 만들기
# ==================================================

# 전체 시간 예산: 남은 시간이 없으면 이후 항목은 timeout으로 기록
class Budget:
    def __init__(self, seconds=TOTAL_BUDGET):
        self.deadline = _now() + seconds

    def remaining(self):
        return self.deadline - _now()


# 바이트를 글자로 바꿔 ok 기록을 만듭니다. 크기 초과는 truncated, UTF-8이 아니면 error
def _text_record(data, exit_code=None):
    if len(data) > MAX_ITEM_BYTES:
        record = {"state": "truncated"}
    else:
        try:
            record = {"state": "ok", "text": data.decode("utf-8")}
        except UnicodeDecodeError:
            record = {"state": "error"}
    if exit_code is not None:
        record["exit_code"] = exit_code
    return record


# 파일 1개 -> 기록
def read_file(path):
    try:
        data = _read_bytes(path, MAX_ITEM_BYTES + 1)
    except FileNotFoundError:
        return {"state": "missing"}
    except OSError:
        return {"state": "error"}            # 권한 부족, 일반 파일 아님 등
    return _text_record(data)


# 명령 1개 -> 기록 (stderr는 버림, 실패 종류만 기록)
def run_command(argv, budget):
    remaining = budget.remaining()
    if remaining <= 0:
        return {"state": "timeout"}
    try:
        done = _run(argv, min(COMMAND_TIMEOUT, remaining))
    except subprocess.TimeoutExpired:
        return {"state": "timeout"}
    except OSError:
        return {"state": "error"}
    if done.returncode != 0:
        return {"state": "error", "exit_code": done.returncode}
    return _text_record(done.stdout, exit_code=0)


# ==================================================
# 3. SSH-02 수집
# ==================================================

# sshd_config와 Include 파일을 "Include가 있던 자리"에 끼워 넣어 원문 1개로 만듭니다.
# 하나라도 못 읽으면 전체를 error로 기록합니다. (빈 설정으로 판정되지 않게)
# Include 폴더를 열 수 없으면(권한 부족) glob이 조용히 빈 결과를 주므로 직접 확인합니다.
def read_sshd_config(path=SSHD_CONFIG, seen=None):
    seen = set() if seen is None else seen
    if path in seen:
        return {"state": "ok", "text": ""}   # 같은 파일 반복 방지
    seen.add(path)
    record = read_file(path)
    if record["state"] != "ok":
        return {"state": "error"}

    collected = []
    for line in record["text"].splitlines(keepends=True):
        collected.append(line)
        key, rest = ssh_check.split_config_line(line)
        if key != "include":
            continue
        for pattern in rest.split():
            if not posixpath.isabs(pattern):
                pattern = posixpath.join("/etc/ssh", pattern)
            matches = _expand_include(pattern)
            if matches is None:
                return {"state": "error"}
            for inc in matches:
                inner = read_sshd_config(inc, seen)
                if inner["state"] != "ok":
                    return {"state": "error"}
                collected.append(inner["text"])
                collected.append("\n")
    text = "".join(collected)
    if len(text.encode("utf-8")) > MAX_ITEM_BYTES:
        return {"state": "truncated"}
    return {"state": "ok", "text": text}


# Include 패턴의 파일 목록 (폴더 이름에는 와일드카드 없다고 보고, 파일 이름만 * ? 지원)
# 폴더를 열 수 없으면 None (= 확인 실패), 폴더가 없으면 빈 목록
def _expand_include(pattern):
    directory, name = posixpath.split(pattern)
    if not any(ch in name for ch in "*?["):
        return [pattern] if _is_regular(pattern) else []
    try:
        names = _listdir(directory)
    except FileNotFoundError:
        return []
    except OSError:
        return None
    return [posixpath.join(directory, n) for n in sorted(names)
            if fnmatch.fnmatch(n, name) and _is_regular(posixpath.join(directory, n))]


def collect_ssh_02(policy, context, budget):
    if not _is_regular(SSHD_PATH):
        return {"sshd_installed": False}
    payload = {
        "sshd_installed": True,
        "sshd_T": run_command([SSHD_PATH, "-T"], budget),
        "sshd_config": read_sshd_config(),
        "sshd_T_C": {},
    }
    for user in policy["criteria"]["test_connection"]["users"]:      # 정책 계정만
        spec = ssh02.build_connection_spec(user, context)
        payload["sshd_T_C"][user] = run_command([SSHD_PATH, "-T", "-C", spec], budget)
    return payload


# ==================================================
# 4. ACC-01 / ACC-02 수집
# ==================================================

# pwquality.conf.d 안의 *.conf 목록 (폴더 없으면 빈 목록 = 정상)
def list_conf_d(directory):
    try:
        names = _listdir(directory)
    except FileNotFoundError:
        return {"state": "ok", "paths": []}
    except OSError:
        return {"state": "error"}
    paths = [posixpath.join(directory, n) for n in sorted(names) if n.endswith(".conf")]
    return {"state": "ok", "paths": [p for p in paths if _is_regular(p)]}


def collect_acc(policy01, policy02, budget):
    os_record = read_file(OS_RELEASE)
    os_id = common.parse_os_release(os_record["text"])[0] if os_record["state"] == "ok" else ""
    acc01_payload = {"os_release": dict(os_record), "files": {}}
    acc02_payload = {"os_release": dict(os_record), "files": {}}

    # OS를 모르거나 지원 대상이 아니면 os_release만 보냄 (판정은 어댑터가 error / not_applicable)
    if os_id in policy01["applies_to"]:
        profile = policy01["criteria"]["profiles"][os_id]
        listing = list_conf_d(profile["pwquality_conf_dir"])
        paths = [profile["login_defs"], *profile["password_files"], *profile["auth_files"],
                 profile["pwquality_conf"], *listing.get("paths", [])]
        acc01_payload["files"] = {p: read_file(p) for p in dict.fromkeys(paths)}
        acc01_payload["pwquality_conf_d"] = listing
        acc01_payload["chage"] = {}
        for account in policy01["criteria"]["interactive_accounts"]:          # 정책 계정만
            if common.ACCOUNT_NAME.match(account):
                acc01_payload["chage"][account] = run_command([CHAGE_PATH, "-l", account], budget)

    if os_id in policy02["applies_to"]:
        profile = policy02["criteria"]["profiles"][os_id]
        paths = [profile["faillock_conf"]]
        paths += [p for stack in profile["stacks"] for p in (stack["auth"], stack["account"])]
        acc02_payload["files"] = {p: read_file(p) for p in dict.fromkeys(paths)}

    return acc01_payload, acc02_payload


# ==================================================
# 5. 전체 수집 -> JSON 1개
# ==================================================

def collect(context, ssh_policy_path=None, acc_policy_path=None):
    ssh_policy = ssh02.load_policy(ssh_policy_path) if ssh_policy_path else ssh02.load_policy()
    policy01 = acc01.load_policy(acc_policy_path) if acc_policy_path else acc01.load_policy()
    policy02 = acc02.load_policy(acc_policy_path) if acc_policy_path else acc02.load_policy()

    started = _now()
    budget = Budget()
    acc01_payload, acc02_payload = collect_acc(policy01, policy02, budget)
    document = {
        "collector": {"name": COLLECTOR_NAME, "version": COLLECTOR_VERSION},
        "context_used": {"host": context["host"], "addr": context["addr"]},   # 중앙 context와 대조용
        "payloads": {
            "SSH-02": collect_ssh_02(ssh_policy, context, budget),
            "ACC-01": acc01_payload,
            "ACC-02": acc02_payload,
        },
    }
    document["collector"]["elapsed_ms"] = int((_now() - started) * 1000)
    return document


# 오류일 때도 표준 출력에 짧은 JSON 1줄만 씁니다. (stderr는 쓰지 않음)
def _fail(out, code, reason):
    out.write(json.dumps({"collector": {"name": COLLECTOR_NAME, "version": COLLECTOR_VERSION},
                          "error": reason}) + "\n")
    return code


def main(argv=None, out=None, config_path=CONFIG_PATH):
    out = out or sys.stdout
    argv = sys.argv[1:] if argv is None else argv
    if argv:                                           # 인자는 받지 않음
        return _fail(out, 2, "arguments not allowed")
    try:
        context = load_config(config_path)
    except (OSError, ValueError):
        return _fail(out, 4, "config invalid")
    try:
        document = collect(context)
    except (OSError, ValueError):
        return _fail(out, 4, "policy load failed")
    except Exception:                                  # noqa: BLE001  예상 못 한 오류도 stderr 없이 종료
        return _fail(out, 1, "unexpected error")
    text = json.dumps(document, ensure_ascii=False)
    if len(text.encode("utf-8")) + 1 > MAX_OUTPUT_BYTES:
        return _fail(out, 3, "output too large")
    out.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
