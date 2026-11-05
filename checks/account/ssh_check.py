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
2. 서버의 실제 SSH 설정을 읽는다.
3. 둘을 비교한다.
4. 결과 1개를 출력한다.

[실행 방법]
sudo python3 ssh_check.py

이 프로그램은 설정을 읽기만 하고, 서버 설정을 바꾸지 않습니다.
"""

# import: 파이썬이 미리 만들어 둔 도구 상자를 가져오는 명령
import glob        # *.conf 같은 패턴에 맞는 파일 찾기
import json        # JSON 파일 읽기, JSON 형식으로 출력하기
import os          # 파일 경로 만들기, 파일이 있는지 확인하기
import shutil      # 프로그램이 어디에 설치되어 있는지 찾기
import subprocess  # 파이썬 안에서 리눅스 명령어 실행하기


# ==================================================
# 1. 프로그램 전체에서 쓰는 값
#    대문자 이름은 "실행 중에 바꾸지 않는 값"이라는 관례
# ==================================================

# __file__은 지금 실행 중인 이 파일의 경로
# BASE_DIR에는 이 파일이 들어 있는 폴더 경로를 저장
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 정책 파일 경로를 만듭니다.
# 결과 예시: .../checks/account/policies/ssh_policy.json
POLICY_FILE = os.path.join(BASE_DIR, "policies", "ssh_policy.json")

# 서버의 SSH 설정 파일 위치
SSHD_CONFIG = "/etc/ssh/sshd_config"

# 이 코드가 담당하는 점검 번호
CHECK_ID = "SSH-01"

# 정책 파일이 깨져서 위험도를 읽을 수 없을 때만 쓰는 예비 값
FALLBACK_SEVERITY = "high"

# { } 는 집합입니다. 값이 이 안에 있는지 검사할 때 씁니다.
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}  # 허용되는 위험도
SUPPORTED_TYPES = {"sshd_effective_setting"}                # 이 코드가 처리할 수 있는 점검 종류
SUPPORTED_OPERATORS = {"equals"}                            # 이 코드가 처리할 수 있는 비교 방식

# 팀 기준이 정해질 때까지 사람이 확인하도록 임시로 분리한 값
# 세 값 모두 키를 이용한 root 접속 가능성이 있음
REVIEW_VALUES = {"prohibit-password", "without-password", "forced-commands-only"}


# ==================================================
# 2. 결과 만들기
# ==================================================

# def: 함수를 만드는 명령. 함수는 이름을 붙여 둔 작업 묶음.
# status, severity, evidence는 이 함수에 넣어 주는 재료.
def make_result(status, severity, evidence):
    # return: 함수가 만든 값을 호출한 곳으로 돌려주고 함수 종료
    # { "이름": 값 } 형태를 딕셔너리
    # 팀 규격의 필수 4개 필드만 생성
    return {
        "check_id": CHECK_ID,   # 점검 번호
        "status": status,       # 판정 결과
        "severity": severity,   # 항목의 위험도
        "evidence": evidence,   # 판정 근거
    }




# ==================================================
# 3. 정책 JSON 검사하기
# ==================================================

# 정책 1개의 형식이 맞는지 검사합니다.
# 문제가 있으면 raise로 오류를 발생시켜 작업을 멈춥니다.
def validate_policy(policy):
    # isinstance(값, dict): 값이 딕셔너리인지 확인합니다.
    # not은 결과를 반대로 뒤집습니다. 즉, 딕셔너리가 아니면 오류입니다.
    if not isinstance(policy, dict):
        raise ValueError("policy item must be an object")

    # for: 괄호 안의 값을 하나씩 꺼내서 field에 넣고 아래 코드를 반복합니다.
    for field in ("check_id", "description", "severity"):
        # 문자열이 아니거나 비어 있으면 오류입니다.
        # policy.get(field): 값이 없어도 프로그램이 멈추지 않고 None을 돌려줍니다.
        # strip(): 앞뒤 공백을 지웁니다. 공백만 있으면 빈 값이 됩니다.
        if not isinstance(policy.get(field), str) or not policy[field].strip():
            # f"..." 안의 {field} 자리에 변수 값이 들어갑니다.
            raise ValueError(f"missing or invalid field: {field}")

    # 위험도는 허용 목록에 있는 소문자 값만 사용할 수 있습니다.
    if policy["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"unknown severity: {policy['severity']}")

    # criteria는 "무엇을 어떤 기준으로 판정할지" 적힌 부분입니다.
    criteria = policy.get("criteria")
    if not isinstance(criteria, dict) or not criteria:
        raise ValueError("missing or invalid field: criteria")

    # 이 코드가 처리할 수 없는 점검 종류나 비교 방식이면 오류입니다.
    if criteria.get("type") not in SUPPORTED_TYPES:
        raise ValueError(f"unsupported criteria.type: {criteria.get('type')}")
    if criteria.get("operator") not in SUPPORTED_OPERATORS:
        raise ValueError(f"unsupported criteria.operator: {criteria.get('operator')}")

    # 읽을 설정 이름(setting)과 양호 기준값(expected)이 있는지 확인합니다.
    for field in ("setting", "expected"):
        if not isinstance(criteria.get(field), str) or not criteria[field].strip():
            raise ValueError(f"missing or invalid field: criteria.{field}")


# 정책 파일을 읽고 그중 SSH-01 정책 1개를 찾아 돌려줍니다.
# path=POLICY_FILE: 경로를 안 넘기면 기본 정책 파일을 사용합니다.
def load_policy(path=POLICY_FILE):
    # with open(...): 파일을 열고, 작업이 끝나면 자동으로 닫습니다.
    # encoding="utf-8": 한글이 깨지지 않게 읽습니다.
    with open(path, encoding="utf-8") as f:
        data = json.load(f)  # JSON 내용을 파이썬 값으로 바꿉니다.

    # 파일 맨 바깥 구조가 규격과 맞는지 검사합니다.
    if not isinstance(data, dict):
        raise ValueError("policy file must be an object")
    if not isinstance(data.get("policy_version"), str) or not data["policy_version"].strip():
        raise ValueError("missing or invalid field: policy_version")
    if not isinstance(data.get("policies"), list) or not data["policies"]:
        raise ValueError("missing or invalid field: policies")

    # 파일 안의 모든 정책을 먼저 검사합니다.
    for policy in data["policies"]:
        validate_policy(policy)

    # 정책들에서 check_id만 뽑아 목록을 만듭니다.
    check_ids = [policy["check_id"] for policy in data["policies"]]

    # set은 중복을 없앱니다. 개수가 달라지면 중복이 있었다는 뜻입니다.
    if len(check_ids) != len(set(check_ids)):
        raise ValueError("duplicate check_id in policy file")

    # 정책 목록에서 SSH-01을 찾아 돌려줍니다.
    for policy in data["policies"]:
        if policy["check_id"] == CHECK_ID:
            return policy

    # 끝까지 찾지 못한 경우입니다.
    raise ValueError(f"policy not found: {CHECK_ID}")




# ==================================================
# 4. 서버 설정 읽기
# ==================================================

# SSH 서버 프로그램 sshd의 위치를 찾습니다.
def find_sshd():    
    sshd = shutil.which("sshd")  # 명령어 검색 경로에서 sshd를 찾습니다.
    if sshd:                     # 찾았으면 그 경로를 돌려줍니다.
        return sshd
    if os.path.exists("/usr/sbin/sshd"):  # 못 찾았으면 기본 위치를 확인합니다.
        return "/usr/sbin/sshd"
    return None  # None은 "값이 없음"입니다. 여기서는 SSH 서버 미설치를 뜻합니다.


# sshd -T를 실행해 실제로 적용 중인 SSH 설정을 가져옵니다.
# 리눅스에서 `sudo sshd -T`를 직접 치는 것과 같은 작업입니다.
def get_sshd_output(sshd):
    # try: 오류가 날 수 있는 작업을 시도합니다.
    try:
        return subprocess.run(
            [sshd, "-T"],          # 실행할 명령어
            capture_output=True,   # 결과를 화면에 띄우지 않고 변수로 받습니다.
            text=True,             # 결과를 글자로 받습니다.
            check=True,            # 명령이 실패하면 오류로 처리합니다.
            timeout=10,            # 10초가 넘으면 중단합니다.
        ).stdout                   # 명령 결과 중 정상 출력 내용만 꺼냅니다.
    # except: try 안에서 아래 오류가 나면 실행됩니다.
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None  # 실행 실패를 None으로 알립니다.


# SSH 설정 파일과 Include로 연결된 파일을 합쳐서 읽습니다.
# Include는 "다른 설정 파일도 함께 읽어라"라는 뜻입니다.
# Match 설정이 있는지 찾기 위해 이 내용이 필요합니다.
def read_config_text(path=SSHD_CONFIG, seen=None):
    # 처음 실행될 때 "이미 읽은 파일" 목록을 만듭니다.
    if seen is None:
        seen = set()

    # 이미 읽은 파일이면 다시 읽지 않습니다. 무한 반복을 막기 위해서입니다.
    if path in seen:
        return ""
    seen.add(path)

    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()  # 파일을 한 줄씩 나눠서 목록으로 저장합니다.
    except (OSError, UnicodeDecodeError):
        return None  # 파일을 못 읽으면 None을 돌려줍니다.

    collected = []  # 읽은 내용을 모아 둘 빈 목록

    for raw in lines:  # 파일을 한 줄씩 확인합니다.
        collected.append(raw)  # append: 목록 끝에 추가합니다.
        parts = raw.split()    # 공백 기준으로 단어를 나눕니다.

        # 예: "Include /etc/ssh/sshd_config.d/*.conf"
        #     -> ["Include", "/etc/ssh/sshd_config.d/*.conf"]
        # Include 줄이 아니면 continue로 다음 줄로 넘어갑니다.
        if len(parts) < 2 or parts[0].lower() != "include":
            continue

        # parts[1:]은 두 번째 단어부터 끝까지입니다.
        for pattern in parts[1:]:
            # 상대 경로이면 /etc/ssh를 앞에 붙입니다.
            if not os.path.isabs(pattern):
                pattern = os.path.join("/etc/ssh", pattern)

            # 패턴에 맞는 파일을 찾아 이름 순서대로 읽습니다.
            for inc in sorted(glob.glob(pattern)):
                # 함수가 자기 자신을 다시 호출합니다.
                # 연결된 파일 안의 Include까지 읽기 위해서입니다.
                text = read_config_text(inc, seen)

                # 연결된 파일을 못 읽으면 전체 판단이 불가능합니다.
                if text is None:
                    return None
                collected.append(text)

    # 목록의 내용을 하나의 긴 문자열로 합칩니다.
    return "".join(collected)


# Match 블록 안에 점검할 설정이 있는지 찾습니다.
# Match는 특정 사용자나 IP에만 다른 설정을 적용하는 기능입니다.
def has_match_rule(config_text, setting):
    in_match = False  # 지금 Match 블록 안에 있는가? 처음에는 아니므로 False

    for line in config_text.splitlines():  # 내용을 한 줄씩 확인합니다.
        parts = line.split()

        # 빈 줄이나 # 주석 줄은 건너뜁니다.
        if not parts or parts[0].startswith("#"):
            continue

        key = parts[0].lower()  # 대소문자 구분을 없애기 위해 소문자로 바꿉니다.

        if key == "match":
            in_match = True  # 이제부터 Match 블록 안입니다.
        elif in_match and key == setting:
            return True  # Match 안에서 점검 설정을 찾았습니다.

    return False  # 끝까지 찾지 못했습니다.





# ==================================================
# 5. 판정하기
# ==================================================

# 정책과 수집한 설정을 비교해서 최종 결과를 만듭니다.
# 이 함수는 서버에 접속하지 않고, 받은 글자만 보고 판단합니다.
# 그래서 가짜 입력으로 쉽게 테스트할 수 있습니다.
def check_ssh_01(policy, sshd_output, config_text=""):
    # 정책에서 위험도, 설정 이름, 양호 기준값을 꺼냅니다.
    severity = policy["severity"]
    setting = policy["criteria"]["setting"].lower()    # 예: permitrootlogin
    expected = policy["criteria"]["expected"].lower()  # 예: no

    # sshd -T 결과가 없으면 판정할 수 없으므로 error입니다.
    if not sshd_output or not sshd_output.strip():
        return make_result("error", severity, "sshd -T output is empty")

    value = None  # 찾은 설정값을 넣을 변수. 처음에는 값이 없습니다.

    for line in sshd_output.splitlines():  # 결과를 한 줄씩 확인합니다.
        # 첫 번째 띄어쓰기를 기준으로 나눕니다.
        # 예: "permitrootlogin no" -> key="permitrootlogin", raw_value="no"
        # _ 는 쓰지 않을 값이라는 표시입니다.
        key, _, raw_value = line.partition(" ")

        if key.lower() == setting:
            value = raw_value.strip().lower()  # 공백을 지우고 소문자로 바꿉니다.
            break  # 찾았으므로 반복을 끝냅니다.

    # 설정을 찾지 못하면 추정하지 않고 error로 처리합니다.
    if not value:
        return make_result("error", severity, f"{setting} not found in sshd -T output")

    # 결과에 남길 판정 근거를 만듭니다.
    evidence = f"Effective SSH setting: {setting} {value}"

    # 실제 값과 정책 기준값이 같으면 True, 다르면 False입니다.
    matches = value == expected

    # 아래 조건은 위에서부터 차례로 확인합니다.
    # return을 만나면 함수가 끝나므로 순서가 중요합니다.

    # 1) root 로그인이 yes로 허용되어 있으면 취약입니다.
    if value == "yes" and not matches:
        return make_result("vulnerable", severity, evidence)

    # 2) Match 예외가 있으면 사람이 확인해야 합니다.
    #    양호로 판정하기 전에 먼저 확인합니다.
    if has_match_rule(config_text, setting):
        return make_result("needs_review", severity, f"{evidence}; Match rule also sets {setting}")

    # 3) 정책 기준과 같으면 양호입니다.
    if matches:
        return make_result("pass", severity, evidence)

    # 4) 팀 기준이 아직 없는 값은 사람이 확인해야 합니다.
    if value in REVIEW_VALUES:
        return make_result("needs_review", severity, f"{evidence}; policy decision required")

    # 5) 코드가 모르는 값도 임의로 판정하지 않습니다.
    return make_result("needs_review", severity, f"{evidence}; unknown value")





# ==================================================
# 6. 전체 실행하기
# ==================================================

# 앞의 함수들을 순서대로 불러서 전체 점검을 진행합니다.
def run_check(policy_path=POLICY_FILE):
    # 1단계: 정책 읽기
    try:
        policy = load_policy(policy_path)
    # as e: 오류 내용을 e라는 이름으로 받습니다.
    except (OSError, ValueError) as e:
        # 정책에 문제가 있으면 점검하지 않고 error로 기록합니다.
        return make_result("error", FALLBACK_SEVERITY, f"Policy load failed: {e}")

    severity = policy["severity"]

    # 2단계: SSH 서버가 설치되어 있는지 확인
    sshd = find_sshd()
    if sshd is None:
        return make_result("not_applicable", severity, "OpenSSH server (sshd) is not installed")

    # 3단계: 실제 적용 중인 설정 읽기
    sshd_output = get_sshd_output(sshd)
    if sshd_output is None:
        return make_result("error", severity, "Failed to run sshd -T (check root privilege or sshd configuration)")

    # 4단계: Match 확인에 필요한 설정 파일 읽기
    config_text = read_config_text()
    if config_text is None:
        return make_result("error", severity, "Failed to read sshd configuration files")

    # 5단계: 정책과 설정을 비교해서 결과 돌려주기
    return check_ssh_01(policy, sshd_output, config_text)


# 이 파일을 직접 실행했을 때만 아래 코드가 동작합니다.
# 다른 파일에서 import로 가져올 때는 실행되지 않습니다.
if __name__ == "__main__":
    # run_check() 결과를 보기 좋은 JSON 형식으로 출력합니다.
    # ensure_ascii=False: 한글을 그대로 출력합니다.
    # indent=2: 두 칸씩 들여쓰기합니다.
    print(json.dumps(run_check(), ensure_ascii=False, indent=2))