#!/usr/bin/env python3
"""
SSH 진단 모듈 - SSH-02: SSH 인증 방식 및 정책 점검

[이 프로그램이 하는 일]
서버의 SSH가 "승인된 인증 방식(공개키)"만 열어 두었는지,
접속 허용 계정 범위(AllowUsers/AllowGroups)가 정해져 있는지 확인

[실행 순서]
1. 정책 JSON(policies/ssh_auth_policy.json)을 읽는다.
2. 서버의 실제 SSH 설정을 읽는다.
   - sshd -T                     : 전체 기본 설정
   - sshd -T -C user=<계정>,...   : 그 계정으로 접속할 때 실제 적용되는 설정 (Match 반영)
3. 계정별로 설정을 하나씩 정책과 비교한다.
4. 가장 심각한 판정 1개를 결과로 출력한다. (vulnerable > error > needs_review > pass)

[판정 기준] 2026-11-12 팀장 승인
- 7개 인증 설정이 기대값과 다르면                      -> vulnerable
- AuthenticationMethods에 실제로 쓸 수 있는 미승인 방식 -> vulnerable
- AllowUsers/AllowGroups 미설정, 승인 범위 밖 계정       -> needs_review
- 접속 위치(Address 등)에 따라 달라지는 Match           -> needs_review
- 수집·명령 실패                                        -> error
- MaxAuthTries, UsePAM                                  -> 판정 없이 details에 기록만
판정에 쓰는 값은 모두 정책 JSON에서 읽습니다.

[실행 방법]
sudo python3 ssh_auth_check.py
sudo python3 ssh_auth_check.py --user cju             (개발용: 테스트 계정 지정, 여러 번 사용 가능)
sudo python3 ssh_auth_check.py --addr <IP> --host <이름>
sudo python3 ssh_auth_check.py --result-version 1.2

이 프로그램은 설정을 읽기만 하고, 서버 설정을 바꾸지 않습니다.
"""

import argparse   # 실행 옵션(--user 등) 받기
import json       # JSON 읽기·출력
import os         # 파일 경로 만들기
import re         # 글자 규칙 검사 (공백·쉼표 찾기)
import sys        # 파이썬이 모듈을 찾는 경로(sys.path) 다루기

# 이 파일이 있는 폴더를 모듈 검색 경로에 넣어, 같은 폴더의 ssh_check.py를 불러옵니다.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# SSH-01 모듈의 "읽기 전용 도우미 함수"를 그대로 재사용합니다. (SSH-01 코드는 수정하지 않음)
# 예: ssh_check.find_sshd(), ssh_check.get_sshd_output(), ssh_check.read_config_text()
import ssh_check  # noqa: E402


# ==================================================
# 1. 프로그램 전체에서 쓰는 값
# ==================================================

POLICY_FILE = os.path.join(BASE_DIR, "policies", "ssh_auth_policy.json")
CHECK_ID = "SSH-02"
FALLBACK_SEVERITY = "medium"          # 정책을 못 읽었을 때만 쓰는 예비 위험도
SUPPORTED_TYPES = {"sshd_auth_policy"}
YES_NO = {"yes", "no"}

# OpenSSH의 인증 방식 이름 -> 그 방식을 켜고 끄는 설정 이름
# (OpenSSH가 정한 사실이지 판정 기준이 아니므로 코드에 둡니다)
METHOD_SETTINGS = {
    "publickey": "pubkeyauthentication",
    "password": "passwordauthentication",
    "keyboard-interactive": "kbdinteractiveauthentication",
    "hostbased": "hostbasedauthentication",
    "gssapi-with-mic": "gssapiauthentication",
}

# 여러 판정을 하나로 합칠 때의 우선순위 (앞일수록 심각)
STATUS_PRIORITY = ["vulnerable", "error", "needs_review", "pass"]

RECOMMENDATIONS = {
    "pass": "현재 설정 유지",
    "vulnerable": "관리자 승인 후 미승인 SSH 인증 방식 제한 및 키 인증 전용 정책 적용 검토",
    "error": "오류 원인 해결 후 재실행",
    "not_applicable": "해당 없음, 근거 확인",
    "needs_review": "관리자가 접속 허용 계정 범위와 Match 적용 조건을 승인 정책과 비교해 최종 판정",
}


# ==================================================
# 2. 결과 만들기
# ==================================================

# v1.1 결과 1개를 만듭니다. details가 있으면 함께 넣습니다.
def make_result(status, severity, evidence, details=None):
    result = {
        "check_id": CHECK_ID,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "recommendation": RECOMMENDATIONS[status],
    }
    if details is not None:
        result["details"] = details
    return result


# 설정 1개에 대한 판정 기록(finding)을 만듭니다. details에 들어갑니다.
def make_finding(user, setting, actual, expected, status, reason):
    return {
        "user": user,           # 어떤 테스트 계정 조건에서 본 값인지
        "setting": setting,     # 설정 이름
        "actual": actual,       # 실제 값
        "expected": expected,   # 기대 값
        "status": status,       # 이 설정의 판정
        "reason": reason,       # 판정 사유
    }


# 여러 판정 중 가장 심각한 것을 고릅니다.
def worst_status(statuses):
    for status in STATUS_PRIORITY:
        if status in statuses:
            return status
    return "pass"


# ==================================================
# 3. 정책 JSON 검사하기
# ==================================================

is_text = ssh_check.is_text   # "비어 있지 않은 문자열"인지 확인 (SSH-01 함수 재사용)


# 계정 이름·host·addr처럼 sshd -C에 들어갈 값인지 확인 (공백·쉼표 금지)
def is_safe_name(value):
    return is_text(value) and not re.search(r"[\s,]", value)


# 값이 "비어 있지 않은 문자열 목록"인지 확인
def is_text_list(value, allow_empty=False):
    if not isinstance(value, list) or (not value and not allow_empty):
        return False
    return all(is_text(item) for item in value)


def validate_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError("policy item must be an object")
    for field in ("check_id", "description", "severity"):
        if not is_text(policy.get(field)):
            raise ValueError(f"missing or invalid field: {field}")
    if policy["severity"] not in ssh_check.ALLOWED_SEVERITIES:
        raise ValueError(f"unknown severity: {policy['severity']}")

    criteria = policy.get("criteria")
    if not isinstance(criteria, dict) or criteria.get("type") not in SUPPORTED_TYPES:
        raise ValueError("missing or unsupported criteria.type")

    # 설정별 기대값: {"설정": {"expected": "yes|no", "reason": "..."}}
    settings = criteria.get("settings")
    if not isinstance(settings, dict) or not settings:
        raise ValueError("missing or invalid field: criteria.settings")
    for name, rule in settings.items():
        if not is_text(name) or not isinstance(rule, dict):
            raise ValueError("invalid entry in criteria.settings")
        if rule.get("expected") not in YES_NO or not is_text(rule.get("reason")):
            raise ValueError(f"invalid entry in criteria.settings.{name}")

    # AuthenticationMethods 판정 기준
    methods = criteria.get("authentication_methods")
    if not isinstance(methods, dict) or not is_text(methods.get("setting")):
        raise ValueError("missing or invalid field: criteria.authentication_methods")
    approved = methods.get("approved_methods")
    if not is_text_list(approved) or any(m not in METHOD_SETTINGS for m in approved):
        raise ValueError("invalid field: criteria.authentication_methods.approved_methods")

    # 접속 허용 계정 기준
    access = criteria.get("access_control")
    if not isinstance(access, dict):
        raise ValueError("missing or invalid field: criteria.access_control")
    if not is_text_list(access.get("settings")) or not is_text_list(access.get("approved_accounts")):
        raise ValueError("invalid field: criteria.access_control")
    if not is_text_list(access.get("pending_accounts", []), allow_empty=True):
        raise ValueError("invalid field: criteria.access_control.pending_accounts")

    # 기록만 하는 설정 목록
    if not is_text_list(criteria.get("evidence_only", []), allow_empty=True):
        raise ValueError("invalid field: criteria.evidence_only")

    validate_test_connection(criteria.get("test_connection"))

    # v1.2 CVSS 평가 상태 (선택)
    cvss_assessment = policy.get("cvss_assessment")
    if cvss_assessment is not None:
        if not isinstance(cvss_assessment, dict):
            raise ValueError("invalid field: cvss_assessment")
        if cvss_assessment.get("vulnerable_assessment_status") not in ssh_check.ALLOWED_VULNERABLE_CVSS_STATUSES:
            raise ValueError("invalid field: cvss_assessment.vulnerable_assessment_status")
        if not is_text(cvss_assessment.get("rationale")):
            raise ValueError("missing or invalid field: cvss_assessment.rationale")


# 테스트 접속 정보: users(계정 목록), host, addr
def validate_test_connection(test_connection):
    if not isinstance(test_connection, dict):
        raise ValueError("missing or invalid field: criteria.test_connection")
    users = test_connection.get("users")
    if not isinstance(users, list) or not users or not all(is_safe_name(u) for u in users):
        raise ValueError("missing or invalid field: criteria.test_connection.users")
    for key in ("host", "addr"):
        if not is_safe_name(test_connection.get(key)):
            raise ValueError(f"missing or invalid field: criteria.test_connection.{key}")


def load_policy(path=POLICY_FILE):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not is_text(data.get("policy_version")):
        raise ValueError("missing or invalid field: policy_version")
    if not isinstance(data.get("policies"), list) or not data["policies"]:
        raise ValueError("missing or invalid field: policies")
    for policy in data["policies"]:
        validate_policy(policy)
    for policy in data["policies"]:
        if policy["check_id"] == CHECK_ID:
            return policy
    raise ValueError(f"policy not found: {CHECK_ID}")


# 계정 1개의 sshd -C 조건 글자를 만듭니다. 예: "user=cju,host=h,addr=192.0.2.10"
def build_connection_spec(user, test_connection):
    return f"user={user},host={test_connection['host']},addr={test_connection['addr']}"


# ==================================================
# 4. 설정 읽기 도우미
# ==================================================

# sshd -T 결과에서 같은 설정이 여러 줄일 때 값을 모두 꺼냅니다.
# AllowUsers처럼 값 하나당 한 줄씩 출력되는 설정에 사용합니다. (계정 이름은 대소문자 유지)
def parse_setting_values(sshd_output, setting):
    values = []
    for line in (sshd_output or "").splitlines():
        key, _, raw_value = line.partition(" ")
        if key.lower() == setting:
            values.extend(raw_value.split())
    return values


# 설정 파일의 Match 블록 안에서, 점검 대상 설정을 바꾸는 줄을 모두 찾습니다.
# 돌려주는 값: [{"keywords": {"address"}, "setting": "passwordauthentication", "value": "yes"}, ...]
def find_match_rules(config_text, settings):
    rules = []
    current = None
    for line in (config_text or "").splitlines():
        key, rest = ssh_check.split_config_line(line)
        if key is None:
            continue
        if key == "match":
            current = ssh_check.parse_match_conditions(rest)
        elif current is not None and key in settings:
            rules.append({"keywords": set(current), "setting": key, "value": rest.strip().lower()})
    return rules


# 사용자 조건(User/Group/All) 외의 조건이 붙은 Match만 고릅니다.
# 이런 Match는 접속 위치에 따라 결과가 달라져 테스트 접속 하나로 확정할 수 없습니다.
def conditional_rules_for(match_rules, setting):
    return [rule for rule in match_rules
            if rule["setting"] == setting and rule["keywords"] - ssh_check.USER_ONLY_MATCH_KEYS]


# ==================================================
# 5. 판정하기 (설정 묶음별)
# ==================================================

# (1) 7개 인증 설정: 기대값과 비교
def judge_settings(user, user_output, global_output, criteria, match_rules):
    findings = []
    for setting, rule in criteria["settings"].items():
        setting = setting.lower()
        expected = rule["expected"]
        value = ssh_check.parse_setting_value(user_output, setting)

        if value is None:
            findings.append(make_finding(user, setting, None, expected, "error",
                                         "not found in sshd -T -C output"))
            continue
        if value != expected:
            findings.append(make_finding(user, setting, value, expected, "vulnerable", rule["reason"]))
            continue

        # 지금은 기대값이어도, 다른 접속 위치에서는 다른 값이 나올 수 있는지 확인
        if conditional_rules_for(match_rules, setting):
            possible = {value, ssh_check.parse_setting_value(global_output, setting)}
            possible |= {r["value"] for r in match_rules if r["setting"] == setting}
            possible.discard(None)
            if possible != {expected}:
                findings.append(make_finding(
                    user, setting, value, expected, "needs_review",
                    f"Match conditions may change this setting for other connections "
                    f"(possible values: {', '.join(sorted(possible))})"))
                continue

        findings.append(make_finding(user, setting, value, expected, "pass", "matches approved policy"))
    return findings


# (2) AuthenticationMethods: 실제로 쓸 수 있는 인증 경로에 미승인 방식이 있는지 확인
#   예: "publickey,password publickey" -> 경로 2개: [publickey+password], [publickey]
#   경로 안의 방식이 모두 켜져 있어야(yes) 그 경로로 실제 로그인할 수 있습니다.
def judge_authentication_methods(user, user_output, criteria, match_rules):
    rule = criteria["authentication_methods"]
    setting = rule["setting"].lower()
    approved = set(rule["approved_methods"])
    expected = "any or " + " ".join(sorted(approved))
    value = ssh_check.parse_setting_value(user_output, setting)

    if value is None:
        return make_finding(user, setting, None, expected, "error", "not found in sshd -T -C output")

    if value == "any":
        status, reason = "pass", "no method list; enabled methods are judged by individual settings"
    else:
        usable_paths, unknown = [], []
        for path in value.split():
            methods = [m.split(":")[0] for m in path.split(",")]   # keyboard-interactive:pam -> keyboard-interactive
            unknown += [m for m in methods if m not in METHOD_SETTINGS]
            if all(m in METHOD_SETTINGS and
                   ssh_check.parse_setting_value(user_output, METHOD_SETTINGS[m]) == "yes"
                   for m in methods):
                usable_paths.append(methods)

        unapproved = sorted({m for path in usable_paths for m in path if m not in approved})
        if unapproved:
            status, reason = "vulnerable", f"unapproved method enabled in an active path: {', '.join(unapproved)}"
        elif unknown:
            status, reason = "needs_review", f"unknown method in list: {', '.join(sorted(set(unknown)))}"
        elif not usable_paths:
            status, reason = "needs_review", "no authentication path is usable with current settings"
        else:
            status, reason = "pass", "all active paths use approved methods only"

    if status == "pass" and conditional_rules_for(match_rules, setting):
        status, reason = "needs_review", "Match conditions may change this setting for other connections"
    return make_finding(user, setting, value, expected, status, reason)


# (3) AllowUsers/AllowGroups: 접속 허용 계정 범위 확인 (미설정이어도 vulnerable이 아니라 needs_review)
def judge_access_control(user, user_output, criteria, match_rules):
    rule = criteria["access_control"]
    approved = set(rule["approved_accounts"])
    pending = set(rule.get("pending_accounts", []))
    allowusers = parse_setting_values(user_output, "allowusers")
    allowgroups = parse_setting_values(user_output, "allowgroups")
    actual = {"allowusers": allowusers, "allowgroups": allowgroups}
    expected = "allowusers within approved accounts: " + ", ".join(sorted(approved))

    if not allowusers and not allowgroups:
        status, reason = "needs_review", "AllowUsers/AllowGroups not set; approved account scope needs review"
    elif allowusers:
        names = [entry.split("@")[0] for entry in allowusers]   # user@host 형식이면 계정 부분만
        outside = sorted(set(names) - approved)
        if outside:
            waiting = sorted(set(outside) & pending)
            reason = f"accounts outside approved list: {', '.join(outside)}"
            if waiting:
                reason += f" (pending confirmation: {', '.join(waiting)})"
            status = "needs_review"
        else:
            status, reason = "pass", "AllowUsers contains approved accounts only"
    else:
        status, reason = "needs_review", "only AllowGroups is set; group membership needs review"

    if status == "pass" and any(conditional_rules_for(match_rules, s) for s in ("allowusers", "allowgroups")):
        status, reason = "needs_review", "Match conditions may change account restrictions for other connections"
    return make_finding(user, "allowusers/allowgroups", actual, expected, status, reason)


# ==================================================
# 6. 전체 판정 (수집한 글자만 보고 판단 -> 가짜 입력으로 테스트 가능)
#   global_output : sshd -T 결과
#   config_text   : 설정 파일 내용 (Include 포함)
#   user_outputs  : {"계정": sshd -T -C 결과 또는 None}
# ==================================================

def check_ssh_02(policy, global_output, config_text, user_outputs):
    severity = policy["severity"]
    criteria = policy["criteria"]

    if not global_output or not global_output.strip():
        return make_result("error", severity, "sshd -T output is empty")

    checked = [s.lower() for s in criteria["settings"]]
    checked += [criteria["authentication_methods"]["setting"].lower(), "allowusers", "allowgroups"]
    match_rules = find_match_rules(config_text, set(checked))

    findings = []
    for user, user_output in user_outputs.items():
        if not user_output or not user_output.strip():
            findings.append(make_finding(user, "sshd -T -C", None, None, "error",
                                         "failed to collect effective settings for this user"))
            continue
        findings += judge_settings(user, user_output, global_output, criteria, match_rules)
        findings.append(judge_authentication_methods(user, user_output, criteria, match_rules))
        findings.append(judge_access_control(user, user_output, criteria, match_rules))

    status = worst_status({f["status"] for f in findings})
    details = {
        "evaluation": "sshd -T -C user=<test user>",
        "users": list(user_outputs),
        "findings": findings,
        "evidence_only": {
            name: ssh_check.parse_setting_value(global_output, name.lower())
            for name in criteria.get("evidence_only", [])
        },
        "match_rules": [
            {"conditions": sorted(r["keywords"]), "setting": r["setting"], "value": r["value"]}
            for r in match_rules
        ],
    }
    return make_result(status, severity, build_evidence(findings, list(user_outputs)), details)


# 사람이 읽을 근거 문장을 만듭니다. pass가 아닌 항목만, 같은 내용은 한 번만 적습니다.
def build_evidence(findings, users):
    issues = []
    for f in findings:
        if f["status"] == "pass":
            continue
        actual = f["actual"]
        if isinstance(actual, dict):
            actual = "set" if any(actual.values()) else "not set"
        text = f"{f['status']}: {f['setting']} {actual} ({f['reason']})"
        if text not in issues:
            issues.append(text)
    head = f"SSH auth policy checked for users: {', '.join(users)}"
    if not issues:
        return f"{head}; all checked settings match approved policy"
    return f"{head}; " + "; ".join(issues)


# ==================================================
# 7. 전체 실행하기 (수집 -> 판정)
# ==================================================

def run_check(policy_path=POLICY_FILE, users=None, host=None, addr=None,
              result_version=ssh_check.DEFAULT_RESULT_VERSION):
    if result_version not in ssh_check.SUPPORTED_RESULT_VERSIONS:
        raise ValueError(f"unsupported result_version: {result_version}")
    policy_box = {}
    result = run_check_v1_1(policy_path, users, host, addr, policy_box)
    if result_version == "1.1":
        return result
    return to_result_v1_2(result, policy_box.get("policy"))


def run_check_v1_1(policy_path, users, host, addr, policy_box):
    # 1단계: 정책 읽기
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as e:
        return make_result("error", FALLBACK_SEVERITY, f"Policy load failed: {type(e).__name__}")
    policy_box["policy"] = policy
    severity = policy["severity"]

    # 테스트 접속 조건: 정책 값을 복사하고, 실행할 때 지정한 값이 있으면 덮어씁니다.
    test_connection = dict(policy["criteria"]["test_connection"])
    if users:
        test_connection["users"] = list(users)
    if host is not None:
        test_connection["host"] = host
    if addr is not None:
        test_connection["addr"] = addr
    try:
        validate_test_connection(test_connection)
    except ValueError:
        return make_result("error", severity, "Invalid test connection override (user/host/addr)")

    # 2단계: SSH 서버 확인
    sshd = ssh_check.find_sshd()
    if sshd is None:
        return make_result("not_applicable", severity, "OpenSSH server (sshd) is not installed")

    # 3단계: 전체 기본 설정
    global_output = ssh_check.get_sshd_output(sshd)
    if global_output is None:
        return make_result("error", severity, "Failed to run sshd -T (check root privilege or sshd configuration)")

    # 4단계: 설정 파일 (Match 확인용)
    config_text = ssh_check.read_config_text()
    if config_text is None:
        return make_result("error", severity, "Failed to read sshd configuration files")

    # 5단계: 계정별 실제 적용 설정
    user_outputs = {}
    for user in test_connection["users"]:
        spec = build_connection_spec(user, test_connection)
        user_outputs[user] = ssh_check.get_sshd_output(sshd, spec)

    # 6단계: 판정
    return check_ssh_02(policy, global_output, config_text, user_outputs)


# v1.1 결과를 v1.2 형식으로 바꿉니다. (severity 제거, cvss 추가, details 유지)
def to_result_v1_2(result, policy):
    result_v1_2 = {
        "check_id": result["check_id"],
        "status": result["status"],
        "evidence": result["evidence"],
        "recommendation": result["recommendation"],
        "cvss": ssh_check.build_cvss(result["status"], policy),
    }
    if "details" in result:
        result_v1_2["details"] = result["details"]
    return result_v1_2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH-02 SSH 인증 방식 및 정책 점검")
    parser.add_argument("--user", action="append",
                        help="sshd -T -C 테스트 계정 (여러 번 지정 가능, 기본: 정책 값)")
    parser.add_argument("--host", help="sshd -T -C 테스트 접속의 host 값 (기본: 정책 값)")
    parser.add_argument("--addr", help="sshd -T -C 테스트 접속의 addr 값 (기본: 정책 값)")
    parser.add_argument("--result-version", choices=sorted(ssh_check.SUPPORTED_RESULT_VERSIONS),
                        default=ssh_check.DEFAULT_RESULT_VERSION, help="결과 형식 버전 (기본: 1.1)")
    args = parser.parse_args()
    result = run_check(users=args.user, host=args.host, addr=args.addr, result_version=args.result_version)
    print(json.dumps(result, ensure_ascii=False, indent=2))
