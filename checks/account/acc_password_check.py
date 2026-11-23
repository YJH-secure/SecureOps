#!/usr/bin/env python3
"""
계정 진단 모듈 - ACC-01: 비밀번호 정책 적용 여부

[이 프로그램이 하는 일]
서버가 비밀번호 규칙(길이, 복잡도, 사용 기간)을 실제로 강제하고 있는지,
빈 비밀번호 로그인(nullok)을 허용하지 않는지 확인

[판정 기준] 2026-11-12 팀장 승인 (값은 policies/account_policy.json에서 읽음)
- 최소 길이 8자 이상, 문자 종류(대문자·소문자·숫자·특수문자) 3종류 이상
  -> PAM에 실제로 연결된 pam_pwquality의 minlen, minclass, credit 값으로 계산
- /etc/login.defs: PASS_MAX_DAYS 90일 이하, PASS_MIN_DAYS 1일 이상 (신규 계정 기본값)
- PAM 인증 설정의 pam_unix에 nullok 없음
- 승인된 대화형 계정별 실제 사용 기간 (chage -l, 해시는 읽지 않음)
  -> 확인하지 못하면 pass로 추정하지 않고 needs_review

[상태]
- 강제 수단이 전혀 없음이 확인됨 / 기준 미달 -> vulnerable
- 설정을 확정할 수 없음                      -> needs_review
- 필수 파일 조회 실패                        -> error

[실행 방법]
sudo python3 acc_password_check.py
sudo python3 acc_password_check.py --account user1   (개발용: 사용 기간을 확인할 계정 지정)
sudo python3 acc_password_check.py --result-version 1.2

이 프로그램은 설정을 읽기만 하고, 서버 설정을 바꾸지 않습니다.
"""

import argparse
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import account_common as common  # noqa: E402  (공통 도우미, 이름이 길어서 common으로 줄여 부름)


# ==================================================
# 1. 이 항목에서 쓰는 값
# ==================================================

POLICY_FILE = os.path.join(BASE_DIR, "policies", "account_policy.json")
CHECK_ID = "ACC-01"
FALLBACK_SEVERITY = "high"
PROFILE_KEYS = ("login_defs", "password_files", "auth_files", "pwquality_conf", "pwquality_conf_dir")

# pam_pwquality가 설정 파일에 값이 없을 때 쓰는 기본값 (libpwquality 기본값, 판정 기준 아님)
PWQUALITY_DEFAULTS = {"minlen": "8", "minclass": "0", "dcredit": "0", "ucredit": "0",
                      "lcredit": "0", "ocredit": "0", "enforcing": "1"}
PWQUALITY_ABSOLUTE_MIN_LEN = 6      # pwquality는 minlen을 6보다 작게 설정할 수 없음
PAM_UNIX_DEFAULT_MIN_LEN = 6        # pam_unix minlen 기본값
CREDIT_KEYS = ("dcredit", "ucredit", "lcredit", "ocredit")   # 숫자, 대문자, 소문자, 특수문자

# 비밀번호 단계에 있어도 복잡도와 관계없는 것으로 알려진 모듈
NON_COMPLEXITY_MODULES = {"pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_pwhistory.so",
                          "pam_gnome_keyring.so", "pam_systemd.so", "pam_ecryptfs.so", "pam_env.so"}
ENFORCING_CONTROLS = {"requisite", "required"}

RECOMMENDATIONS = {
    "pass": "현재 설정 유지",
    "vulnerable": "관리자 승인 후 비밀번호 길이·복잡도·사용 기간 정책 및 nullok 제거 검토",
    "error": "오류 원인 해결 후 재실행",
    "not_applicable": "해당 없음, 근거 확인",
    "needs_review": "관리자가 비밀번호 정책 적용 방식과 대상 계정을 확인해 최종 판정",
}


def make_result(status, severity, evidence, details=None):
    return common.make_result(CHECK_ID, RECOMMENDATIONS, status, severity, evidence, details)


# ==================================================
# 2. 정책 검사
# ==================================================

def validate_criteria(criteria, applies_to):
    if criteria.get("type") != "password_policy":
        raise ValueError("unsupported criteria.type")
    for key in ("min_length", "min_classes", "max_days", "min_days"):
        value = criteria.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"missing or invalid field: criteria.{key}")
    if criteria["min_classes"] > 4:
        raise ValueError("criteria.min_classes must be 4 or less")
    if not isinstance(criteria.get("forbid_nullok"), bool):
        raise ValueError("missing or invalid field: criteria.forbid_nullok")
    if not common.is_text_list(criteria.get("complexity_modules")):
        raise ValueError("missing or invalid field: criteria.complexity_modules")
    if not common.is_text_list(criteria.get("manual_review_modules", []), allow_empty=True):
        raise ValueError("invalid field: criteria.manual_review_modules")
    accounts = criteria.get("interactive_accounts")
    if not isinstance(accounts, list) or not all(common.ACCOUNT_NAME.match(str(a)) for a in accounts):
        raise ValueError("missing or invalid field: criteria.interactive_accounts")
    common.validate_profiles(criteria, applies_to, PROFILE_KEYS)


def load_policy(path=POLICY_FILE):
    return common.load_policy(path, CHECK_ID, validate_criteria)


# ==================================================
# 3. 판정: 길이·복잡도 (PAM password 단계)
# ==================================================

# pwquality 최종 설정 = 기본값 <- pwquality.conf <- pwquality.conf.d/*.conf <- PAM 인자 순서로 덮어쓰기
# 돌려주는 값: (설정 dict, 오류 사유 또는 None)
def pwquality_settings(profile, files, conf_d_paths, module_args):
    settings = dict(PWQUALITY_DEFAULTS)
    args = common.parse_args(module_args)
    if "conf" in args:
        return settings, "custom pwquality conf= path is used"
    for path in [profile["pwquality_conf"], *conf_d_paths]:
        state, text = files.get(path, ("missing", None))
        if state == "error":
            return settings, f"failed to read {path}"
        if state == "ok":
            settings.update({k: v for k, v in common.parse_kv_conf(text).items() if k in settings})
    settings.update({k: v for k, v in args.items() if k in settings})
    return settings, None


# pwquality 설정으로 "실제 최소 길이"와 "요구 문자 종류 수"를 계산합니다.
#   credit이 양수: 그 종류 문자를 쓰면 길이를 깎아 줌 -> 실제 최소 길이가 짧아짐
#   credit이 음수: 그 종류 문자가 최소 몇 개 필요 -> 요구 종류 수에 포함
def pwquality_strength(settings):
    numbers = {k: common.to_int(v) for k, v in settings.items()}
    if any(value is None for value in numbers.values()):
        return None
    minlen = max(numbers["minlen"], PWQUALITY_ABSOLUTE_MIN_LEN)
    effective_length = minlen - sum(max(numbers[k], 0) for k in CREDIT_KEYS)
    required_classes = max(numbers["minclass"], sum(1 for k in CREDIT_KEYS if numbers[k] < 0))
    return {"effective_min_length": effective_length, "required_classes": required_classes,
            "enforcing": numbers["enforcing"]}


def judge_complexity(criteria, profile, files, conf_d_paths, pwquality_records):
    findings = []
    min_length, min_classes = criteria["min_length"], criteria["min_classes"]
    length_expected, classes_expected = f">= {min_length}", f">= {min_classes}"

    for path in profile["password_files"]:
        entries = [e for e in common.parse_pam(files[path][1], path) if e["type"] == "password"]
        complexity = [e for e in entries if e["module"] in criteria["complexity_modules"]]
        manual = [e["module"] for e in entries if e["module"] in criteria.get("manual_review_modules", [])]
        unknown = [e["module"] for e in entries
                   if e["module"] not in NON_COMPLEXITY_MODULES
                   and e["module"] not in criteria["complexity_modules"] and e["module"] not in manual]

        def both(status, length, classes, reason):
            findings.append(common.make_finding("min_length", length, length_expected, status, reason, path))
            findings.append(common.make_finding("complexity_classes", classes, classes_expected, status, reason, path))

        # (1) pam_pwquality가 연결되어 있으면 그 설정값으로 계산
        if complexity:
            entry = complexity[0]
            if entry["control"] not in ENFORCING_CONTROLS:
                both("needs_review", None, None, f"{entry['module']} control is {entry['control']}; enforcement unclear")
                continue
            settings, problem = pwquality_settings(profile, files, conf_d_paths, entry["args"])
            if problem and problem.startswith("failed to read"):
                both("error", None, None, problem)
                continue
            if problem:
                both("needs_review", None, None, problem)
                continue
            strength = pwquality_strength(settings)
            pwquality_records[path] = settings
            if strength is None:
                both("needs_review", None, None, "non-numeric pwquality setting")
                continue
            if strength["enforcing"] == 0:
                both("vulnerable", strength["effective_min_length"], strength["required_classes"],
                     "pwquality enforcing=0 only warns and does not reject weak values")
                continue
            length, classes = strength["effective_min_length"], strength["required_classes"]
            findings.append(common.make_finding(
                "min_length", length, length_expected,
                "pass" if length >= min_length else "vulnerable",
                "pwquality minlen minus positive credits", path))
            findings.append(common.make_finding(
                "complexity_classes", classes, classes_expected,
                "pass" if classes >= min_classes else "vulnerable",
                "max of pwquality minclass and number of negative credits", path))
            continue

        # (2) pwquality는 없지만 다른 방식으로 강제할 수도 있는 모듈 -> 사람이 확인
        if manual or unknown:
            both("needs_review", None, None,
                 f"complexity may be enforced by other module: {', '.join(sorted(set(manual + unknown)))}")
            continue

        # (3) 복잡도 강제 수단이 전혀 없음이 확인됨 -> vulnerable
        unix = [e for e in entries if e["module"] == "pam_unix.so"]
        length = PAM_UNIX_DEFAULT_MIN_LEN
        if unix:
            length = common.to_int(common.parse_args(unix[0]["args"]).get("minlen", PAM_UNIX_DEFAULT_MIN_LEN))
        if length is None:
            findings.append(common.make_finding("min_length", None, length_expected, "needs_review",
                                                "non-numeric pam_unix minlen", path))
        else:
            findings.append(common.make_finding(
                "min_length", length, length_expected,
                "pass" if length >= min_length else "vulnerable",
                "no complexity module; pam_unix minlen (default 6)", path))
        findings.append(common.make_finding(
            "complexity_classes", 0, classes_expected, "vulnerable",
            "no complexity enforcement module in PAM password stack", path))
    return findings


# ==================================================
# 4. 판정: 사용 기간 (/etc/login.defs = 신규 계정 기본값)
# ==================================================

def judge_login_defs(criteria, profile, files):
    path = profile["login_defs"]
    values = common.parse_login_defs(files[path][1])
    findings = []

    checks = [
        ("PASS_MAX_DAYS", f"<= {criteria['max_days']}",
         lambda v: 0 <= v <= criteria["max_days"], "not set (default: no limit)"),
        ("PASS_MIN_DAYS", f">= {criteria['min_days']}",
         lambda v: v >= criteria["min_days"], "not set (default: 0)"),
    ]
    for key, expected, ok, missing_reason in checks:
        raw = values.get(key)
        if raw is None:
            findings.append(common.make_finding(key, None, expected, "vulnerable", missing_reason, path))
            continue
        number = common.to_int(raw)
        if number is None:
            findings.append(common.make_finding(key, raw, expected, "needs_review", "non-numeric value", path))
        elif ok(number):
            findings.append(common.make_finding(key, number, expected, "pass", "new account default meets policy", path))
        else:
            findings.append(common.make_finding(key, number, expected, "vulnerable",
                                                "new account default does not meet policy", path))
    return findings, {k: values.get(k) for k in ("PASS_WARN_AGE", "PASS_MIN_LEN", "ENCRYPT_METHOD")}


# ==================================================
# 5. 판정: nullok (PAM 인증 단계의 pam_unix)
# ==================================================

def judge_nullok(criteria, profile, files):
    if not criteria["forbid_nullok"]:
        return []
    findings = []
    for path in profile["auth_files"]:
        hits = [e for e in common.parse_pam(files[path][1], path)
                if e["type"] == "auth" and e["module"] == "pam_unix.so"
                and any(a in ("nullok", "nullok_secure") for a in e["args"])]
        if hits:
            lines = ", ".join(str(e["line"]) for e in hits)
            findings.append(common.make_finding("nullok", "present", "absent", "vulnerable",
                                                f"pam_unix auth allows empty credentials (line {lines})", path))
        else:
            findings.append(common.make_finding("nullok", "absent", "absent", "pass",
                                                "pam_unix auth has no nullok", path))
    return findings


# ==================================================
# 6. 판정: 승인된 대화형 계정의 실제 사용 기간 (chage -l 결과)
#    aging: {"계정": {"min_days": 0, "max_days": 99999} 또는 None(조회 실패)}
# ==================================================

def judge_account_aging(criteria, aging):
    if not aging:
        return [common.make_finding("account_aging", None, "approved interactive accounts", "needs_review",
                                    "approved interactive account list is not defined yet")]
    findings = []
    for account, values in aging.items():
        if values is None:
            findings.append(common.make_finding(
                f"account_aging({account})", None, "readable", "needs_review",
                "could not read account aging (chage -l); not assumed to pass"))
            continue
        max_days, min_days = values["max_days"], values["min_days"]
        findings.append(common.make_finding(
            f"account_max_days({account})", max_days, f"<= {criteria['max_days']}",
            "pass" if 0 <= max_days <= criteria["max_days"] else "vulnerable",
            "existing account maximum age"))
        findings.append(common.make_finding(
            f"account_min_days({account})", min_days, f">= {criteria['min_days']}",
            "pass" if min_days >= criteria["min_days"] else "vulnerable",
            "existing account minimum age"))
    return findings


# ==================================================
# 7. 전체 판정 (수집한 내용만 보고 판단 -> 가짜 입력으로 테스트 가능)
#   files        : {경로: ("ok"|"missing"|"error", 내용)}
#   conf_d_paths : pwquality.conf.d 안의 파일 경로 목록
#   aging        : 계정별 chage 결과
# ==================================================

def check_acc_01(policy, os_id, os_version, files, conf_d_paths, aging):
    severity = policy["severity"]
    criteria = policy["criteria"]
    profile = criteria["profiles"][os_id]

    # 필수 파일(login.defs, PAM 파일)을 못 읽으면 판정할 수 없으므로 error
    required = [profile["login_defs"], *profile["password_files"], *profile["auth_files"]]
    for path in dict.fromkeys(required):
        state = files.get(path, ("missing", None))[0]
        if state != "ok":
            reason = "required file is missing" if state == "missing" else "failed to read required file"
            return make_result("error", severity, f"{reason}: {path}")

    pwquality_records = {}
    findings = judge_complexity(criteria, profile, files, conf_d_paths, pwquality_records)
    login_findings, login_evidence = judge_login_defs(criteria, profile, files)
    findings += login_findings
    findings += judge_nullok(criteria, profile, files)
    findings += judge_account_aging(criteria, aging)

    status = common.worst_status({f["status"] for f in findings})
    details = {
        "os": f"{os_id} {os_version}".strip(),
        "findings": findings,
        "pwquality_effective": pwquality_records,
        "evidence_only": login_evidence,
        "accounts": list(aging),
    }
    evidence = common.build_evidence(f"ACC-01 password policy checked ({details['os']})", findings)
    return make_result(status, severity, evidence, details)


# ==================================================
# 8. 수집 -> 판정
# ==================================================

def run_check(policy_path=POLICY_FILE, accounts=None, result_version=common.DEFAULT_RESULT_VERSION):
    common.check_result_version(result_version)
    policy = None
    result = None
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as e:
        result = make_result("error", FALLBACK_SEVERITY, f"Policy load failed: {type(e).__name__}")
    if result is None:
        result = collect_and_check(policy, accounts)
    if result_version == "1.1":
        return result
    return common.to_result_v1_2(result, policy)


def collect_and_check(policy, accounts):
    severity = policy["severity"]
    criteria = policy["criteria"]

    # 1단계: OS 확인
    state, text = common.read_text(common.OS_RELEASE)
    if state != "ok":
        return make_result("error", severity, "Failed to read /etc/os-release")
    os_id, os_version = common.parse_os_release(text)
    # OS를 알 수 없음(ID 없음) -> error / OS는 확인됐지만 지원 대상이 아님 -> not_applicable
    if not os_id:
        return make_result("error", severity, "Unable to determine OS (no ID in /etc/os-release)")
    if os_id not in policy["applies_to"]:
        return make_result("not_applicable", severity, f"OS not in applies_to: {os_id or 'unknown'}")
    profile = criteria["profiles"][os_id]

    # 2단계: 확인할 계정 (실행할 때 지정하면 그 값 사용)
    accounts = list(accounts) if accounts else list(criteria["interactive_accounts"])
    if not all(common.ACCOUNT_NAME.match(a) for a in accounts):
        return make_result("error", severity, "Invalid account override")

    # 3단계: 설정 파일 읽기 (읽기 전용)
    conf_d_paths = common.list_conf_files(profile["pwquality_conf_dir"])
    paths = [profile["login_defs"], *profile["password_files"], *profile["auth_files"],
             profile["pwquality_conf"], *conf_d_paths]
    files = {path: common.read_text(path) for path in dict.fromkeys(paths)}

    # 4단계: 계정별 사용 기간 (chage -l, 해시 미수집)
    aging = {account: common.run_chage(account) for account in accounts}

    # 5단계: 판정
    return check_acc_01(policy, os_id, os_version, files, conf_d_paths, aging)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACC-01 비밀번호 정책 적용 여부 점검")
    parser.add_argument("--account", action="append",
                        help="사용 기간을 확인할 대화형 계정 (여러 번 지정 가능, 기본: 정책 값)")
    parser.add_argument("--result-version", choices=sorted(common.SUPPORTED_RESULT_VERSIONS),
                        default=common.DEFAULT_RESULT_VERSION, help="결과 형식 버전 (기본: 1.1)")
    args = parser.parse_args()
    print(json.dumps(run_check(accounts=args.account, result_version=args.result_version),
                     ensure_ascii=False, indent=2))
