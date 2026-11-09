#!/usr/bin/env python3
"""
SSH 진단 모듈 - SSH-01: SSH root 원격 로그인 제한

[이 프로그램이 하는 일]
서버가 root 계정의 SSH 직접 로그인을 막고 있는지 확인

[비유]
정책 JSON = 채점 기준표
이 코드   = 채점하는 선생님
출력 결과 = 성적표

[실행 순서]
1. 정책 JSON(채점 기준표)을 읽는다.
2. 서버의 실제 SSH 설정을 읽는다. (전체 설정 + root 접속 조건의 설정)
3. 둘을 비교한다.
4. 결과 1개를 출력한다.

[판정 기준] 기준표 v1.1, 2026-11-09 팀장 승인
- no                                  -> pass
- yes, prohibit-password,
  without-password, forced-commands-only -> vulnerable
- Match 적용 조건을 확정할 수 없음     -> needs_review
- 수집·명령 실패                       -> error
판정에 쓰는 값은 정책 JSON(policies/ssh_policy.json)에서 읽습니다.

[실행 방법]
sudo python3 ssh_check.py
sudo python3 ssh_check.py --addr <테스트할 접속 IP> --host <테스트할 접속 이름>   (실제 환경 조건 지정)

이 프로그램은 설정을 읽기만 하고, 서버 설정을 바꾸지 않습니다.
"""

# import: 파이썬이 미리 만들어 둔 도구 상자를 가져오는 명령
import argparse    # 실행할 때 --addr 같은 옵션 받기
import fnmatch     # root 같은 이름이 패턴(r* 등)에 맞는지 확인하기
import glob        # *.conf 같은 패턴에 맞는 파일 찾기
import json        # JSON 파일 읽기, JSON 형식으로 출력하기
import os          # 파일 경로 만들기, 파일이 있는지 확인하기
import re          # 글자를 규칙(정규식)으로 나누기
import shutil      # 프로그램이 어디에 설치되어 있는지 찾기
import subprocess  # 파이썬 안에서 리눅스 명령어 실행하기


# ==================================================
# 1. 프로그램 전체에서 쓰는 값
#    대문자 이름은 "실행 중에 바꾸지 않는 값"이라는 관례
# ==================================================

# 이 파일이 들어 있는 폴더와 정책 파일 경로
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = os.path.join(BASE_DIR, "policies", "ssh_policy.json")

# 서버의 SSH 설정 파일 위치
SSHD_CONFIG = "/etc/ssh/sshd_config"

# 이 코드가 담당하는 점검 번호
CHECK_ID = "SSH-01"

# 정책 파일이 깨져서 위험도를 읽을 수 없을 때만 쓰는 예비 값
FALLBACK_SEVERITY = "high"

# 정책 형식 검사에 쓰는 허용값 (판정 기준이 아니라 "형식" 규칙)
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
SUPPORTED_TYPES = {"sshd_effective_setting"}
SUPPORTED_OPERATORS = {"equals"}
TEST_CONNECTION_KEYS = ("user", "host", "addr")

# Match 조건 중 "사용자"만 보는 조건입니다.
# 이 조건들만 있으면 sshd -T -C user=root 결과로 root의 값을 정확히 알 수 있습니다.
# 그 외 조건(Address, Host, LocalPort 등)은 접속 위치에 따라 결과가 달라집니다.
USER_ONLY_MATCH_KEYS = {"user", "group", "all"}

# 판정 결과별 안내 문구입니다.
# 사람이 읽는 안내일 뿐, 이 문구로 서버 명령을 실행하지 않습니다.
RECOMMENDATIONS = {
    "pass": "현재 설정 유지",
    "vulnerable": "관리자 승인 후 root 원격 로그인 제한 정책 검토",
    "error": "오류 원인 해결 후 재실행",
    "not_applicable": "해당 없음, 근거 확인",
    "needs_review": "관리자가 Match 적용 조건과 승인 정책을 비교해 최종 판정",
}


# ==================================================
# 2. 결과 만들기
# ==================================================

# 팀 규격 v1.1의 필수 5개 필드를 만듭니다.
def make_result(status, severity, evidence):
    return {
        "check_id": CHECK_ID,                       # 점검 번호
        "status": status,                           # 판정 결과
        "severity": severity,                       # 항목의 위험도
        "evidence": evidence,                       # 판정 근거
        "recommendation": RECOMMENDATIONS[status],  # 판정별 안내 문구
    }



# ==================================================
# 3. 정책 JSON 검사하기
# ==================================================

# 값이 "비어 있지 않은 문자열"인지 확인하는 도우미 함수
def is_text(value):
    return isinstance(value, str) and bool(value.strip())


# 정책 1개의 형식이 맞는지 검사합니다. 문제가 있으면 오류를 일으킵니다.
def validate_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError("policy item must be an object")

    # 공통 필수 필드
    for field in ("check_id", "description", "severity"):
        if not is_text(policy.get(field)):
            raise ValueError(f"missing or invalid field: {field}")
    if policy["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"unknown severity: {policy['severity']}")

    criteria = policy.get("criteria")
    if not isinstance(criteria, dict) or not criteria:
        raise ValueError("missing or invalid field: criteria")
    if criteria.get("type") not in SUPPORTED_TYPES:
        raise ValueError(f"unsupported criteria.type: {criteria.get('type')}")
    if criteria.get("operator") not in SUPPORTED_OPERATORS:
        raise ValueError(f"unsupported criteria.operator: {criteria.get('operator')}")
    for field in ("setting", "expected"):
        if not is_text(criteria.get(field)):
            raise ValueError(f"missing or invalid field: criteria.{field}")

    # 취약 값 목록: { "값": "위반 사유" } 형태여야 합니다.
    vulnerable_values = criteria.get("vulnerable_values")
    if not isinstance(vulnerable_values, dict) or not vulnerable_values:
        raise ValueError("missing or invalid field: criteria.vulnerable_values")
    for value, reason in vulnerable_values.items():
        if not is_text(value) or not is_text(reason):
            raise ValueError("invalid entry in criteria.vulnerable_values")

    # 양호 기준값이 취약 목록에도 있으면 기준이 모순입니다.
    vulnerable_lower = {value.lower() for value in vulnerable_values}
    if criteria["expected"].lower() in vulnerable_lower:
        raise ValueError("criteria.expected is also listed in criteria.vulnerable_values")

    # root 접속 조건 확인용 테스트 접속 정보 (sshd -T -C에 사용)
    validate_test_connection(criteria.get("test_connection"))


# 테스트 접속 정보가 올바른지 검사합니다.
# SSH-01은 root 계정 진단이므로 user는 반드시 root여야 합니다.
def validate_test_connection(test_connection):
    if not isinstance(test_connection, dict):
        raise ValueError("missing or invalid field: criteria.test_connection")
    for key in TEST_CONNECTION_KEYS:
        value = test_connection.get(key)
        # 쉼표나 공백이 있으면 -C 옵션의 형식이 깨지므로 거부합니다.
        if not is_text(value) or re.search(r"[\s,]", value):
            raise ValueError(f"missing or invalid field: criteria.test_connection.{key}")
    if test_connection["user"] != "root":
        raise ValueError("criteria.test_connection.user must be root")


# 정책 파일을 읽고 그중 SSH-01 정책 1개를 찾아 돌려줍니다.
def load_policy(path=POLICY_FILE):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("policy file must be an object")
    if not is_text(data.get("policy_version")):
        raise ValueError("missing or invalid field: policy_version")
    if not isinstance(data.get("policies"), list) or not data["policies"]:
        raise ValueError("missing or invalid field: policies")

    for policy in data["policies"]:
        validate_policy(policy)

    check_ids = [policy["check_id"] for policy in data["policies"]]
    if len(check_ids) != len(set(check_ids)):
        raise ValueError("duplicate check_id in policy file")

    for policy in data["policies"]:
        if policy["check_id"] == CHECK_ID:
            return policy
    raise ValueError(f"policy not found: {CHECK_ID}")


# 테스트 접속 정보를 sshd -C 형식 글자로 바꿉니다.
# 예: {"user": "root", "host": "h", "addr": "192.0.2.10"} -> "user=root,host=h,addr=192.0.2.10"
def build_connection_spec(test_connection):
    return ",".join(f"{key}={test_connection[key]}" for key in TEST_CONNECTION_KEYS)



# ==================================================
# 4. 서버 설정 읽기
# ==================================================

# SSH 서버 프로그램 sshd의 위치를 찾습니다. 없으면 None
def find_sshd():
    sshd = shutil.which("sshd")
    if sshd:
        return sshd
    if os.path.exists("/usr/sbin/sshd"):
        return "/usr/sbin/sshd"
    return None


# sshd -T를 실행해 실제로 적용 중인 SSH 설정을 가져옵니다.
# connection_spec이 있으면 sshd -T -C <조건>으로 "그 접속 조건에서" 적용되는 설정을 가져옵니다.
# 예: sshd -T -C user=root,host=secureops-check,addr=192.0.2.10
def get_sshd_output(sshd, connection_spec=None):
    command = [sshd, "-T"]
    if connection_spec:
        command += ["-C", connection_spec]
    try:
        return subprocess.run(
            command,
            capture_output=True,   # 결과를 화면 대신 변수로 받기
            text=True,             # 결과를 글자로 받기
            check=True,            # 명령이 실패하면 오류로 처리
            timeout=10,            # 10초가 넘으면 중단
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


# 설정 파일 한 줄을 "키워드"와 "나머지"로 나눕니다.
# SSH 설정은 "PermitRootLogin no"와 "PermitRootLogin=no" 형식을 모두 허용합니다.
def split_config_line(line):
    text = line.strip()
    if not text or text.startswith("#"):
        return None, ""
    parts = re.split(r"\s*=\s*|\s+", text, maxsplit=1)
    key = parts[0].lower()
    rest = parts[1].strip() if len(parts) > 1 else ""
    return key, rest


# SSH 설정 파일과 Include로 연결된 파일을 Include 위치에 끼워 넣어 하나로 합칩니다.
def read_config_text(path=SSHD_CONFIG, seen=None):
    if seen is None:
        seen = set()
    if path in seen:      # 같은 파일을 반복해서 읽지 않기 (무한 반복 방지)
        return ""
    seen.add(path)

    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return None

    collected = []
    for raw in lines:
        collected.append(raw)
        key, rest = split_config_line(raw)
        if key != "include":
            continue
        for pattern in rest.split():
            if not os.path.isabs(pattern):
                pattern = os.path.join("/etc/ssh", pattern)
            for inc in sorted(glob.glob(pattern)):
                text = read_config_text(inc, seen)
                if text is None:    # 연결된 파일을 못 읽으면 전체 판단 불가
                    return None
                collected.append(text)
                collected.append("\n")
    return "".join(collected)



# Match 줄의 조건을 {키워드: 값} 형태로 나눕니다.
# 예: "User root Address 10.0.0.0/8" -> {"user": "root", "address": "10.0.0.0/8"}
#     "All"                          -> {"all": ""}
def parse_match_conditions(rest):
    tokens = rest.replace("=", " ").split()
    conditions = {}
    index = 0
    while index < len(tokens):
        keyword = tokens[index].lower()
        if keyword == "all":                     # all은 값이 없는 조건
            conditions[keyword] = ""
            index += 1
        else:                                    # 나머지는 "키워드 값" 쌍
            conditions[keyword] = tokens[index + 1] if index + 1 < len(tokens) else ""
            index += 2
    return conditions


# Match User 조건이 root에 적용될 가능성이 있는지 확인합니다.
# 예: "alice,bob" -> False (root와 무관),  "root" "r*" "!alice" -> True
def user_condition_may_match_root(patterns):
    for pattern in patterns.split(","):
        if pattern.startswith("!"):              # 부정 조건은 root에 적용될 수 있으므로 보수적으로 True
            return True
        if fnmatch.fnmatchcase("root", pattern):
            return True
    return False


# Match 블록 중 점검 설정(permitrootlogin)을 바꾸는 블록을 모두 찾습니다.
# root와 무관한 블록(Match User alice 등)은 제외합니다.
# 돌려주는 값: [{"keywords": {...}, "value": "yes"}, ...]
# root 관련 match만 모으기
def find_match_rules(config_text, setting):
    rules = []
    current = None   # 지금 읽고 있는 Match 블록의 조건 (블록 밖이면 None)

    for line in config_text.splitlines():
        key, rest = split_config_line(line)
        if key is None:
            continue
        if key == "match":
            current = parse_match_conditions(rest)
        elif current is not None and key == setting:
            if "user" in current and not user_condition_may_match_root(current["user"]):
                continue
            value = rest.split()[0].lower() if rest.split() else ""
            rules.append({"keywords": set(current), "value": value})
    return rules


# sshd -T 결과에서 원하는 설정의 값을 꺼냅니다. 없으면 None
def parse_setting_value(sshd_output, setting):
    for line in (sshd_output or "").splitlines():
        key, _, raw_value = line.partition(" ")
        if key.lower() == setting:
            value = raw_value.strip().lower()
            return value or None
    return None



# ==================================================
# 5. 판정하기
# ==================================================

# 정책과 수집한 설정을 비교해서 최종 결과를 만듭니다.
# 서버에 접속하지 않고 받은 글자만 보고 판단하므로, 가짜 입력으로 테스트할 수 있습니다.
#   policy : 정책 JSON의 SSH-01기준
#   sshd_output : sshd -T 결과 (전체 기본 설정)
#   config_text : 설정 파일 내용 (Match 블록을 찾는 데 사용)
#   root_output : sshd -T -C user=root,... 결과 (root 접속 조건에서 실제 적용 설정)
def check_ssh_01(policy, sshd_output, config_text="", root_output=None):
    severity = policy["severity"]
    criteria = policy["criteria"]
    setting = criteria["setting"].lower()       # 예: permitrootlogin
    expected = criteria["expected"].lower()     # 예: no
    vulnerable_values = {value.lower(): reason for value, reason in criteria["vulnerable_values"].items()}

    if not sshd_output or not sshd_output.strip():
        return make_result("error", severity, "sshd -T output is empty")

    global_value = parse_setting_value(sshd_output, setting)
    if global_value is None:
        return make_result("error", severity, f"{setting} not found in sshd -T output")

    match_rules = find_match_rules(config_text, setting)

    # 1) root 접속 조건의 결과가 없으면, Match가 없는 경우에만 전체 설정으로 판정할 수 있습니다.
    if root_output is None:
        if match_rules:
            return make_result(
                "needs_review", severity,
                f"Effective SSH setting: {setting} {global_value}; "
                f"Match rule sets {setting} but root-specific evaluation is unavailable",
            )
        value = global_value
        evidence = f"Effective SSH setting: {setting} {value}"
    else:
        value = parse_setting_value(root_output, setting)
        if value is None:
            return make_result("error", severity, f"{setting} not found in sshd -T -C output")
        evidence = f"Effective SSH setting for root (sshd -T -C): {setting} {value}"

    # 2) 실제 root 접속 조건에서 취약 값이 확인되면, Match가 있어도 vulnerable입니다.
    if value in vulnerable_values:
        return make_result("vulnerable", severity, f"{evidence}; violation: {vulnerable_values[value]}")

    # 3) 기준값과 다르고 취약 목록에도 없는 값은 사람이 확인합니다.
    if value != expected:
        return make_result("needs_review", severity, f"{evidence}; unknown value not defined in policy")

    # 4) 기준값과 같아도, 접속 위치(Address 등)에 따라 달라지는 Match가 있으면 다시 확인합니다.
    #    테스트 접속 조건 하나로는 모든 접속을 확인할 수 없으므로,
    #    다른 접속에서 나올 수 있는 값이 모두 기준값일 때만 pass입니다.
    conditional_rules = [rule for rule in match_rules if rule["keywords"] - USER_ONLY_MATCH_KEYS]
    if conditional_rules:
        # 다른 접속에서 나올 수 있는 값: 기본 설정값 + root 관련 Match 전체의 값
        # (사용자 조건 Match도 포함: 테스트 주소에서는 조건부 Match에 가려졌을 수 있음)
        possible_values = {global_value} | {rule["value"] for rule in match_rules}
        if possible_values != {expected}:
            conditions = sorted(set().union(*(rule["keywords"] for rule in conditional_rules)))
            return make_result(
                "needs_review", severity,
                f"{evidence}; Match conditions ({', '.join(conditions)}) may change {setting} "
                f"for other connections (possible values: {', '.join(sorted(possible_values))})",
            )

    # 5) 기준을 만족하면 양호입니다.
    return make_result("pass", severity, evidence)



# ==================================================
# 6. 전체 실행하기
# ==================================================

# host, addr: 실제 환경의 테스트 접속 조건을 실행할 때 따로 지정하는 값 (없으면 정책 값 사용)
def run_check(policy_path=POLICY_FILE, host=None, addr=None):
    # 1단계: 정책 읽기
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as e:
        return make_result("error", FALLBACK_SEVERITY, f"Policy load failed: {type(e).__name__}")

    severity = policy["severity"]

    # 테스트 접속 조건: 정책 값을 복사한 뒤, 실행할 때 지정한 값이 있으면 덮어씁니다.
    test_connection = dict(policy["criteria"]["test_connection"])
    if host is not None:
        test_connection["host"] = host
    if addr is not None:
        test_connection["addr"] = addr
    try:
        validate_test_connection(test_connection)
    except ValueError:
        return make_result("error", severity, "Invalid test connection override (host/addr)")

    # 2단계: SSH 서버 확인
    sshd = find_sshd()
    if sshd is None:
        return make_result("not_applicable", severity, "OpenSSH server (sshd) is not installed")

    # 3단계: 전체 기본 설정 읽기
    sshd_output = get_sshd_output(sshd)
    if sshd_output is None:
        return make_result("error", severity, "Failed to run sshd -T (check root privilege or sshd configuration)")

    # 4단계: Match 확인에 필요한 설정 파일 읽기
    config_text = read_config_text()
    if config_text is None:
        return make_result("error", severity, "Failed to read sshd configuration files")

    # 5단계: root 접속 조건에서 적용되는 설정 읽기
    root_output = get_sshd_output(sshd, build_connection_spec(test_connection))
    if root_output is None:
        return make_result("error", severity, "Failed to run sshd -T -C for root connection test")

    # 6단계: 판정
    return check_ssh_01(policy, sshd_output, config_text, root_output)


if __name__ == "__main__":
    # 예: sudo python3 ssh_check.py --addr 10.0.0.5 --host admin-pc
    parser = argparse.ArgumentParser(description="SSH-01 root 원격 로그인 제한 점검")
    parser.add_argument("--host", help="sshd -T -C 테스트 접속의 host 값 (기본: 정책 값)")
    parser.add_argument("--addr", help="sshd -T -C 테스트 접속의 addr 값 (기본: 정책 값)")
    args = parser.parse_args()
    print(json.dumps(run_check(host=args.host, addr=args.addr), ensure_ascii=False, indent=2))