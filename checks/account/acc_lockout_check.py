#!/usr/bin/env python3
"""
계정 진단 모듈 - ACC-02: 계정 잠금 정책 적용 여부

[이 프로그램이 하는 일]
비밀번호를 여러 번 틀리면 계정을 잠그는 기능(pam_faillock)이
실제 로그인 인증 흐름에 연결되어 있고, 설정값이 기준에 맞는지 확인

[판정 기준] 2026-11-12 팀장 승인 (값은 policies/account_policy.json에서 읽음)
- pam_faillock 연결: auth의 preauth, auth의 authfail, account 줄이 모두 있어야 함
  (파일이 있는지만 보지 않고, PAM에 실제로 연결된 줄과 순서·인자를 확인)
- deny 1~10회 (권장 5회)
- unlock_time 600초 이상, 0/never(관리자 수동 해제)는 승인 절차 확인이 필요해 needs_review
- fail_interval 프로젝트 권장 900초 이상 (짧으면 needs_review)

[상태]
- 명백히 미적용·기준 위반     -> vulnerable
- 일부 구성을 확인할 수 없음  -> needs_review
- 조회 실패                   -> error

[실행 방법]
sudo python3 acc_lockout_check.py
sudo python3 acc_lockout_check.py --result-version 1.2

이 프로그램은 설정을 읽기만 하고, 계정 잠금 시험이나 설정 변경을 하지 않습니다.
"""

import argparse
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import account_common as common  # noqa: E402


# ==================================================
# 1. 이 항목에서 쓰는 값
# ==================================================

POLICY_FILE = os.path.join(BASE_DIR, "policies", "account_policy.json")
CHECK_ID = "ACC-02"
FALLBACK_SEVERITY = "medium"
PROFILE_KEYS = ("faillock_conf", "stacks")

# pam_faillock이 설정 파일에 값이 없을 때 쓰는 기본값 (pam_faillock 기본값, 판정 기준 아님)
FAILLOCK_DEFAULTS = {"deny": "3", "unlock_time": "600", "fail_interval": "900"}
LEGACY_MODULES = {"pam_tally2.so", "pam_tally.so"}

RECOMMENDATIONS = {
    "pass": "현재 설정 유지",
    "vulnerable": "관리자 승인 후 pam_faillock 계정 잠금 정책 적용 검토",
    "error": "오류 원인 해결 후 재실행",
    "not_applicable": "해당 없음, 근거 확인",
    "needs_review": "관리자가 PAM 연결 상태와 잠금 해제 절차를 확인해 최종 판정",
}


def make_result(status, severity, evidence, details=None):
    return common.make_result(CHECK_ID, RECOMMENDATIONS, status, severity, evidence, details)


# ==================================================
# 2. 정책 검사
# ==================================================

def validate_criteria(criteria, applies_to):
    if criteria.get("type") != "account_lockout":
        raise ValueError("unsupported criteria.type")
    for key in ("deny_min", "deny_max", "deny_recommended", "unlock_time_min", "fail_interval_recommended"):
        value = criteria.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"missing or invalid field: criteria.{key}")
    if not 1 <= criteria["deny_min"] <= criteria["deny_recommended"] <= criteria["deny_max"]:
        raise ValueError("criteria deny range is inconsistent")
    common.validate_profiles(criteria, applies_to, PROFILE_KEYS)
    for os_id in applies_to:
        stacks = criteria["profiles"][os_id]["stacks"]
        if not isinstance(stacks, list) or not stacks:
            raise ValueError(f"invalid field: criteria.profiles.{os_id}.stacks")
        for stack in stacks:
            if not isinstance(stack, dict) or not common.is_text(stack.get("auth")) \
                    or not common.is_text(stack.get("account")):
                raise ValueError(f"invalid entry in criteria.profiles.{os_id}.stacks")


def load_policy(path=POLICY_FILE):
    return common.load_policy(path, CHECK_ID, validate_criteria)


# ==================================================
# 3. 판정: pam_faillock 연결 상태 (스택 1개)
#    스택 = 인증(auth) 파일 + 계정(account) 파일 한 쌍
# ==================================================

def judge_connection(stack, files):
    auth_path = stack["auth"]
    auth = [e for e in common.parse_pam(files[auth_path][1], auth_path) if e["type"] == "auth"]
    account = [e for e in common.parse_pam(files[stack["account"]][1], stack["account"])
               if e["type"] == "account"]

    faillock_auth = [e for e in auth if e["module"] == "pam_faillock.so"]
    preauth = [e for e in faillock_auth if "preauth" in e["args"]]
    authfail = [e for e in faillock_auth if "authfail" in e["args"]]
    faillock_account = [e for e in account if e["module"] == "pam_faillock.so"]
    lines = preauth[:1] + authfail[:1]          # 설정 인자를 읽을 줄

    def finding(status, actual, reason):
        return common.make_finding("faillock_connection", actual, "preauth + authfail + account",
                                   status, reason, auth_path), lines

    # (1) 아무 줄도 없음 -> 미적용
    if not faillock_auth and not faillock_account:
        if any(e["module"] in LEGACY_MODULES for e in auth):
            return finding("needs_review", "legacy", "legacy pam_tally module is used instead of pam_faillock")
        return finding("vulnerable", "not connected", "pam_faillock is not connected to the PAM auth stack")

    # (2) 일부만 있음 -> 확인 필요
    missing = [name for name, found in (("preauth", preauth), ("authfail", authfail),
                                        ("account", faillock_account)) if not found]
    if missing:
        return finding("needs_review", "partial", f"partial pam_faillock configuration; missing {', '.join(missing)}")

    # (3) 순서: preauth -> pam_unix -> authfail 이어야 실패 횟수가 기록됨
    unix_index = next((i for i, e in enumerate(auth) if e["module"] == "pam_unix.so"), None)
    pre_index, fail_index = auth.index(preauth[0]), auth.index(authfail[0])
    if unix_index is None or not pre_index < unix_index < fail_index:
        return finding("needs_review", "connected", "pam_faillock order around pam_unix is not standard")

    # (4) 제어값: optional, sufficient 등은 잠금이 강제되지 않을 수 있음
    if preauth[0]["control"] not in ("required", "requisite"):
        return finding("needs_review", "connected", f"preauth control is {preauth[0]['control']}")
    fail_control = authfail[0]["control"]
    if fail_control not in ("required", "requisite") and "default=die" not in fail_control:
        return finding("needs_review", "connected", f"authfail control is {fail_control}")

    return finding("pass", "connected", "preauth, authfail and account lines are connected in order")


# ==================================================
# 4. 판정: deny, unlock_time, fail_interval
#    최종 값 = 기본값 <- faillock.conf <- PAM 줄의 인자
# ==================================================

def faillock_settings(conf_state, conf_text, lines):
    settings = dict(FAILLOCK_DEFAULTS)
    if conf_state == "ok":
        settings.update({k: v for k, v in common.parse_kv_conf(conf_text).items() if k in settings})
    seen = {}
    for entry in lines:
        args = common.parse_args(entry["args"])
        if "conf" in args:
            return settings, "custom faillock conf= path is used"
        for key in FAILLOCK_DEFAULTS:
            if key in args:
                if key in seen and seen[key] != args[key]:
                    return settings, f"different {key} values on preauth and authfail lines"
                seen[key] = args[key]
    settings.update(seen)
    return settings, None


def judge_settings(criteria, settings, source):
    findings = []
    deny = common.to_int(settings["deny"])
    expected = f"{criteria['deny_min']}-{criteria['deny_max']} (recommended {criteria['deny_recommended']})"
    if deny is None:
        findings.append(common.make_finding("deny", settings["deny"], expected, "needs_review", "non-numeric value", source))
    else:
        ok = criteria["deny_min"] <= deny <= criteria["deny_max"]
        findings.append(common.make_finding("deny", deny, expected, "pass" if ok else "vulnerable",
                                            "failed attempts before lock", source))

    raw = str(settings["unlock_time"]).lower()
    unlock = common.to_int(raw)
    expected = f">= {criteria['unlock_time_min']} or approved manual unlock"
    if raw == "never" or unlock == 0:
        findings.append(common.make_finding("unlock_time", raw, expected, "needs_review",
                                            "manual unlock by administrator; approved procedure must be confirmed", source))
    elif unlock is None:
        findings.append(common.make_finding("unlock_time", raw, expected, "needs_review", "non-numeric value", source))
    else:
        ok = unlock >= criteria["unlock_time_min"]
        findings.append(common.make_finding("unlock_time", unlock, expected, "pass" if ok else "vulnerable",
                                            "seconds until automatic unlock", source))

    interval = common.to_int(settings["fail_interval"])
    expected = f">= {criteria['fail_interval_recommended']} (project recommendation)"
    if interval is None:
        findings.append(common.make_finding("fail_interval", settings["fail_interval"], expected,
                                            "needs_review", "non-numeric value", source))
    else:
        ok = interval >= criteria["fail_interval_recommended"]
        findings.append(common.make_finding(
            "fail_interval", interval, expected, "pass" if ok else "needs_review",
            "window for counting failures" if ok else "shorter than project recommended window", source))
    return findings


# ==================================================
# 5. 전체 판정 (수집한 내용만 보고 판단 -> 가짜 입력으로 테스트 가능)
#   files: {경로: ("ok"|"missing"|"error", 내용)}
# ==================================================

def check_acc_02(policy, os_id, os_version, files):
    severity = policy["severity"]
    criteria = policy["criteria"]
    profile = criteria["profiles"][os_id]

    required = [path for stack in profile["stacks"] for path in (stack["auth"], stack["account"])]
    for path in dict.fromkeys(required):
        state = files.get(path, ("missing", None))[0]
        if state != "ok":
            reason = "required file is missing" if state == "missing" else "failed to read required file"
            return make_result("error", severity, f"{reason}: {path}")

    conf_path = profile["faillock_conf"]
    conf_state, conf_text = files.get(conf_path, ("missing", None))
    if conf_state == "error":
        return make_result("error", severity, f"failed to read {conf_path}")

    findings, effective = [], {}
    for stack in profile["stacks"]:
        connection, lines = judge_connection(stack, files)
        findings.append(connection)
        settings, problem = faillock_settings(conf_state, conf_text, lines)
        effective[stack["auth"]] = settings
        if connection["actual"] != "connected":
            continue                     # 연결되지 않았으면 설정값은 기록만 하고 판정하지 않음
        if problem:
            findings.append(common.make_finding("faillock_settings", None, "consistent settings",
                                                "needs_review", problem, stack["auth"]))
            continue
        findings += judge_settings(criteria, settings, stack["auth"])

    status = common.worst_status({f["status"] for f in findings})
    details = {
        "os": f"{os_id} {os_version}".strip(),
        "findings": findings,
        "faillock_effective": effective,
        "faillock_conf": "present" if conf_state == "ok" else "missing (defaults applied)",
    }
    evidence = common.build_evidence(f"ACC-02 account lockout checked ({details['os']})", findings)
    return make_result(status, severity, evidence, details)


# ==================================================
# 6. 수집 -> 판정
# ==================================================

def run_check(policy_path=POLICY_FILE, result_version=common.DEFAULT_RESULT_VERSION):
    common.check_result_version(result_version)
    policy = None
    result = None
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as e:
        result = make_result("error", FALLBACK_SEVERITY, f"Policy load failed: {type(e).__name__}")
    if result is None:
        result = collect_and_check(policy)
    if result_version == "1.1":
        return result
    return common.to_result_v1_2(result, policy)


def collect_and_check(policy):
    severity = policy["severity"]

    state, text = common.read_text(common.OS_RELEASE)
    if state != "ok":
        return make_result("error", severity, "Failed to read /etc/os-release")
    os_id, os_version = common.parse_os_release(text)
    if os_id not in policy["applies_to"]:
        return make_result("not_applicable", severity, f"OS not in applies_to: {os_id or 'unknown'}")
    profile = policy["criteria"]["profiles"][os_id]

    paths = [profile["faillock_conf"]]
    paths += [path for stack in profile["stacks"] for path in (stack["auth"], stack["account"])]
    files = {path: common.read_text(path) for path in dict.fromkeys(paths)}
    return check_acc_02(policy, os_id, os_version, files)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACC-02 계정 잠금 정책 적용 여부 점검")
    parser.add_argument("--result-version", choices=sorted(common.SUPPORTED_RESULT_VERSIONS),
                        default=common.DEFAULT_RESULT_VERSION, help="결과 형식 버전 (기본: 1.1)")
    args = parser.parse_args()
    print(json.dumps(run_check(result_version=args.result_version), ensure_ascii=False, indent=2))
