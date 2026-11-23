"""
중앙 연동 어댑터 (방식 B) - SSH-02, ACC-01, ACC-02

대상 서버의 수집기가 보낸 "원시 데이터 묶음(payload)"을
B 판정 함수(check_ssh_02, check_acc_01, check_acc_02)가 받는 입력으로 바꿔 주는 번역기입니다.

  수집기(대상 서버) --payload--> [이 어댑터] --입력--> B 판정 함수 --결과--> D(저장·집계)

원칙
  - 이 파일은 명령 실행·SSH 연결·대상 서버 파일 읽기를 하지 않습니다. (읽기 전용 수집은 수집기 담당)
    단, 판정 기준인 B 정책 JSON(로컬 파일)은 읽습니다.
  - 수집 실패를 "빈 값"이나 "pass"로 추정하지 않습니다. 실패는 error(또는 기준상 needs_review)로 넘깁니다.
  - 점검 계정은 정책 JSON의 목록만 씁니다. (payload에 다른 계정이 와도 판정에 쓰지 않음)
  - SSH-02 host/addr은 정책에 고정하지 않고, 실행할 때 검증된 값을 context로 받습니다.
  - 기존 판정 함수와 SSH-01 코드는 바꾸지 않습니다.

※ payload 형식은 D와 확정 전인 "초안"입니다. 필드 이름이 확정되면 이 파일만 맞추면 됩니다.

[수집 기록(record) 초안] 파일 1개 또는 명령 1개의 수집 결과
  {"state": "ok", "text": "내용"}   정상 수집
  {"state": "missing"}              파일 없음
  {"state": "error"}                권한 부족 등 읽기 실패
  {"state": "timeout"}              명령 시간 초과
  {"state": "truncated"}            출력 절단
  (명령 실패는 "error", 종료 코드는 있으면 "exit_code"에 기록)
  ok라도 exit_code가 0이 아니거나, timeout/truncated 표시가 true이면 error로 봅니다.
  (중앙 실행 계층의 차단과 별개로, 항목 단위에서도 한 번 더 막는 안전장치)
"""

import os
import posixpath    # 대상 서버(리눅스) 경로를 PC 종류와 상관없이 "/" 기준으로 다루기
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:           # 같은 폴더의 B 모듈을 찾을 수 있게 경로 추가
    sys.path.insert(0, BASE_DIR)

import account_common as common     # noqa: E402  ACC 공통 도우미
import acc_lockout_check as acc02   # noqa: E402  ACC-02 판정
import acc_password_check as acc01  # noqa: E402  ACC-01 판정
import ssh_auth_check as ssh02      # noqa: E402  SSH-02 판정


DEFAULT_RESULT_VERSION = "1.2"           # 중앙 저장은 v1.2 형식 사용
SUPPORTED_RESULT_VERSIONS = {"1.1", "1.2"}


# ==================================================
# 1. 수집 기록 -> B 상태값 ("ok" | "missing" | "error")
# ==================================================

# ok 기록이 실제로 "끝까지 정상 실행"됐는지 확인합니다.
#   exit_code : 있으면 반드시 정수 0 (True/False는 정수로 인정하지 않음)
#   timeout, truncated : 있으면 반드시 False
def is_clean_ok(record):
    if "exit_code" in record:
        code = record["exit_code"]
        if isinstance(code, bool) or not isinstance(code, int) or code != 0:
            return False
    return record.get("timeout", False) is False and record.get("truncated", False) is False


# 수집 기록 1개를 (상태, 내용)으로 바꿉니다.
# ok인데 내용이 글자가 아니거나 실행 정보가 어긋나면 형식 오류이므로 error 처리합니다.
# timeout, truncated, 알 수 없는 상태는 모두 error (불완전한 값으로 오판하지 않기 위해)
def normalize_record(record):
    if not isinstance(record, dict):
        return "error", None
    state = record.get("state")
    if state == "ok" and isinstance(record.get("text"), str) and is_clean_ok(record):
        return "ok", record["text"]
    if state == "missing":
        return "missing", None
    return "error", None


# 명령 출력용: 성공이면 글자, 아니면 None (판정 함수가 None을 "수집 실패"로 처리)
def command_text(record):
    state, text = normalize_record(record)
    return text if state == "ok" else None


# payload 안의 사전(dict) 필드를 꺼냅니다. 없거나 형식이 다르면 빈 사전
def get_dict(payload, key):
    value = payload.get(key) if isinstance(payload, dict) else None
    return value if isinstance(value, dict) else {}


# ==================================================
# 2. SSH-02
# payload 초안:
#   {"sshd_installed": true,
#    "sshd_T": 기록,                          sudo sshd -T
#    "sshd_config": 기록,                     설정 파일 + Include를 끼워 넣은 전체 텍스트
#    "sshd_T_C": {"계정": 기록, ...}}         sudo sshd -T -C user=계정,host=..,addr=..
# context: {"host": "...", "addr": "..."}  실행 환경에서 검증된 접속 문맥 (필수)
# ==================================================

def adapt_ssh_02(policy, payload, context):
    severity = policy["severity"]
    users = list(policy["criteria"]["test_connection"]["users"])   # 정책 계정만 사용

    # host/addr은 정책 값으로 대신하지 않고 반드시 실행할 때 받아야 합니다.
    if not isinstance(context, dict):
        return ssh02.make_result("error", severity, "Missing connection context (host/addr)")
    try:
        ssh02.validate_test_connection({"users": users, "host": context.get("host"),
                                        "addr": context.get("addr")})
    except ValueError:
        return ssh02.make_result("error", severity, "Invalid connection context (host/addr)")

    if not isinstance(payload, dict):
        return ssh02.make_result("error", severity, "Invalid collection payload")
    if payload.get("sshd_installed") is False:
        return ssh02.make_result("not_applicable", severity, "OpenSSH server (sshd) is not installed")

    global_output = command_text(payload.get("sshd_T"))
    if global_output is None:
        return ssh02.make_result("error", severity, "Failed to run sshd -T (collection failed)")

    # [발견 사항 보완] check_ssh_02는 설정 파일 읽기 실패를 스스로 검사하지 않습니다.
    # 실패를 빈 설정으로 넘기면 Match 규칙이 없는 것처럼 판정되므로, 여기서 먼저 error로 막습니다.
    config_state, config_text = normalize_record(payload.get("sshd_config"))
    if config_state != "ok":
        return ssh02.make_result("error", severity, "Failed to read sshd configuration files")

    collected = get_dict(payload, "sshd_T_C")
    user_outputs = {user: command_text(collected.get(user)) for user in users}
    return ssh02.check_ssh_02(policy, global_output, config_text, user_outputs)


# ==================================================
# 3. ACC 공통: OS 확인
# ==================================================

# os-release 기록에서 OS를 꺼냅니다. 실패하면 (None, None, 오류 결과)
#   OS를 알아낼 수 없음(읽기 실패, ID 없음) -> error
#   OS는 확인됐지만 지원 대상이 아님         -> not_applicable
def read_os(policy, payload, make_result):
    severity = policy["severity"]
    state, text = normalize_record(payload.get("os_release"))
    if state != "ok":
        return None, None, make_result("error", severity, "Failed to read /etc/os-release")
    os_id, os_version = common.parse_os_release(text)
    if not os_id:
        return None, None, make_result("error", severity, "Unable to determine OS (no ID in /etc/os-release)")
    if os_id not in policy["applies_to"]:
        return None, None, make_result("not_applicable", severity,
                                       f"OS not in applies_to: {os_id or 'unknown'}")
    return os_id, os_version, None


# 정책 프로필에 있는 경로만 payload에서 꺼냅니다.
# payload에 아예 없는 경로는 "보냈는데 없음"인지 알 수 없으므로 missing이 아니라 error로 둡니다.
def pick_files(payload, paths):
    collected = get_dict(payload, "files")
    return {path: normalize_record(collected[path]) if path in collected else ("error", None)
            for path in dict.fromkeys(paths)}


# conf.d 목록의 항목 1개가 "정책 폴더 바로 안의 *.conf 파일"인지 확인합니다.
#   - 글자여야 함
#   - 정리한 경로(normpath)가 원래 경로와 같아야 함 ("..", "//", "./" 같은 우회 표현 거부)
#   - 부모 폴더가 정확히 정책 폴더여야 함 (하위 폴더나 다른 폴더 거부)
def is_conf_d_path(path, conf_dir):
    if not isinstance(path, str) or not path.endswith(".conf"):
        return False
    if posixpath.normpath(path) != path:
        return False
    return posixpath.dirname(path) == posixpath.normpath(conf_dir)


# ==================================================
# 4. ACC-01
# payload 초안:
#   {"os_release": 기록,
#    "files": {"경로": 기록, ...},               login.defs, PAM, pwquality.conf, conf.d 파일
#    "pwquality_conf_d": {"state": "ok", "paths": [...]},   conf.d 안 *.conf 목록 (폴더 없으면 빈 목록)
#    "chage": {"계정": 기록, ...}}               LC_ALL=C chage -l 계정 출력
# ==================================================

def adapt_acc_01(policy, payload):
    severity = policy["severity"]
    if not isinstance(payload, dict):
        return acc01.make_result("error", severity, "Invalid collection payload")
    os_id, os_version, failed = read_os(policy, payload, acc01.make_result)
    if failed:
        return failed
    profile = policy["criteria"]["profiles"][os_id]

    # conf.d 목록: 목록을 못 받으면 추가 설정을 놓칠 수 있으므로 error
    listing = payload.get("pwquality_conf_d")
    if not isinstance(listing, dict) or listing.get("state") != "ok" \
            or not isinstance(listing.get("paths"), list) or not is_clean_ok(listing):
        return acc01.make_result("error", severity, f"Failed to list {profile['pwquality_conf_dir']}")
    # 목록 안에 형식이 이상한 항목이 하나라도 있으면 조용히 버리지 않고 error
    # (버리면 추가 설정을 놓친 채 pass가 나올 수 있음)
    conf_d_paths = []
    for path in listing["paths"]:
        if not is_conf_d_path(path, profile["pwquality_conf_dir"]):
            return acc01.make_result("error", severity,
                                     f"Invalid entry in {profile['pwquality_conf_dir']} listing")
        conf_d_paths.append(path)
    conf_d_paths = sorted(set(conf_d_paths))

    paths = [profile["login_defs"], *profile["password_files"], *profile["auth_files"],
             profile["pwquality_conf"], *conf_d_paths]
    files = pick_files(payload, paths)

    # 계정 기간: 정책의 대화형 계정만. 조회 실패·형식 이상은 None -> 판정 함수가 needs_review
    collected = get_dict(payload, "chage")
    aging = {}
    for account in policy["criteria"]["interactive_accounts"]:
        output = command_text(collected.get(account))
        aging[account] = common.parse_chage(output) if output is not None else None
    return acc01.check_acc_01(policy, os_id, os_version, files, conf_d_paths, aging)


# ==================================================
# 5. ACC-02
# payload 초안:
#   {"os_release": 기록, "files": {"경로": 기록, ...}}   faillock.conf, PAM 파일
# ==================================================

def adapt_acc_02(policy, payload):
    severity = policy["severity"]
    if not isinstance(payload, dict):
        return acc02.make_result("error", severity, "Invalid collection payload")
    os_id, os_version, failed = read_os(policy, payload, acc02.make_result)
    if failed:
        return failed
    profile = policy["criteria"]["profiles"][os_id]
    paths = [profile["faillock_conf"]]
    paths += [path for stack in profile["stacks"] for path in (stack["auth"], stack["account"])]
    return acc02.check_acc_02(policy, os_id, os_version, pick_files(payload, paths))


# ==================================================
# 6. 중앙에서 부르는 입구 (점검 1개 -> 결과 1개, 예외 없이 항상 결과 반환)
# ==================================================

# 점검 ID별 도구: 정책 읽기 함수, 예비 위험도(정책을 못 읽었을 때만), 결과 만들기, v1.2 변환
CHECKS = {
    "SSH-02": (ssh02.load_policy, ssh02.FALLBACK_SEVERITY, ssh02.make_result, ssh02.to_result_v1_2),
    "ACC-01": (acc01.load_policy, acc01.FALLBACK_SEVERITY, acc01.make_result, common.to_result_v1_2),
    "ACC-02": (acc02.load_policy, acc02.FALLBACK_SEVERITY, acc02.make_result, common.to_result_v1_2),
}


# 점검 ID에 맞는 어댑터를 부릅니다. (context는 SSH-02만 사용)
def adapt(check_id, policy, payload, context):
    if check_id == "SSH-02":
        return adapt_ssh_02(policy, payload, context)
    if check_id == "ACC-01":
        return adapt_acc_01(policy, payload)
    return adapt_acc_02(policy, payload)


# policy_path, result_version은 이름을 붙여서만 받습니다. (* 뒤 = 키워드 전용)
# 예: judge_payload("ACC-01", payload, result_version="1.1")
# 위치로 넘기면 TypeError가 나서 "버전 값이 정책 경로로 들어가는" 실수를 막습니다.
def judge_payload(check_id, payload, context=None, *, policy_path=None,
                  result_version=DEFAULT_RESULT_VERSION):
    # 호출하는 쪽(중앙 코드)의 실수는 바로 알려야 하므로 예외(ValueError)로 알립니다.
    # 글자가 아닌 값(리스트 등)도 TypeError가 아니라 같은 ValueError로 통일합니다.
    if not isinstance(check_id, str) or check_id not in CHECKS:
        raise ValueError(f"unsupported check_id: {check_id!r}")
    if not isinstance(result_version, str) or result_version not in SUPPORTED_RESULT_VERSIONS:
        raise ValueError(f"unsupported result_version: {result_version!r}")
    # policy_path : None일 때만 기본 정책. 그 외에는 비어 있지 않은 글자 경로만 허용
    # (False, 0, [], {}, "" 같은 값이 "값 없음"으로 취급되어 기본 정책으로 바뀌는 것을 막음)
    if policy_path is not None and (not isinstance(policy_path, str) or not policy_path.strip()):
        raise ValueError(f"invalid policy_path: {policy_path!r}")
    load_policy, fallback_severity, make_result, to_v1_2 = CHECKS[check_id]

    # 1단계: 정책 읽기 (경로를 안 주면 각 모듈의 기본 정책 파일)
    try:
        policy = load_policy() if policy_path is None else load_policy(policy_path)
    except (OSError, ValueError) as e:
        policy = None
        result = make_result("error", fallback_severity, f"Policy load failed: {type(e).__name__}")
    else:
        # 2단계: payload 변환 + 판정. 예상 못 한 형식이라도 중앙 실행을 멈추지 않고 error로 기록
        try:
            result = adapt(check_id, policy, payload, context)
        except Exception as e:   # noqa: BLE001
            result = make_result("error", policy["severity"], f"Adapter failed: {type(e).__name__}")

    # 3단계: 결과 형식
    if result_version == "1.1":
        return result
    return to_v1_2(result, policy)
