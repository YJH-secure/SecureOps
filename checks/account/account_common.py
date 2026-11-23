#!/usr/bin/env python3
"""
계정 진단(ACC-01, ACC-02) 공통 도우미 모듈

[이 파일이 하는 일]
ACC-01(비밀번호 정책)과 ACC-02(계정 잠금 정책)가 함께 쓰는 기능을 모아 둔 곳입니다.
- 파일 읽기 (읽기만 하고 절대 쓰지 않음)
- PAM 설정 줄 나누기, key = value 설정 파일 읽기
- 운영체제(OS) 확인, 정책 JSON 공통 형식 검사
- 결과 만들기 (JSON v1.1 / v1.2)

이 파일만 실행하는 일은 없습니다. 다른 진단 파일이 import해서 사용합니다.
"""

import glob        # *.conf 같은 패턴으로 파일 찾기
import json        # 정책 JSON 읽기
import os          # 경로 다루기
import re          # 글자 규칙 검사
import subprocess  # chage 명령 실행 (읽기 전용)


# ==================================================
# 1. 공통 값
# ==================================================

OS_RELEASE = "/etc/os-release"
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
DEFAULT_RESULT_VERSION = "1.1"
SUPPORTED_RESULT_VERSIONS = {"1.1", "1.2"}
ALLOWED_VULNERABLE_CVSS_STATUSES = {"pending", "not_applicable"}

# 여러 판정을 하나로 합칠 때 우선순위 (앞일수록 심각)
STATUS_PRIORITY = ["vulnerable", "error", "needs_review", "pass"]

# 리눅스 계정 이름 규칙 (명령에 넘기기 전에 이상한 글자를 막기 위함)
ACCOUNT_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


# ==================================================
# 2. 파일 읽기 (읽기 전용)
# ==================================================

# 파일을 읽어서 (상태, 내용)을 돌려줍니다.
#   ("ok", "내용")    : 읽기 성공
#   ("missing", None) : 파일이 없음 (없는 것 자체가 판정 근거가 될 수 있음)
#   ("error", None)   : 권한 부족 등으로 읽기 실패
def read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return "ok", f.read()
    except FileNotFoundError:
        return "missing", None
    except (OSError, UnicodeDecodeError):
        return "error", None


# 폴더 안의 *.conf 파일 목록을 이름 순서로 돌려줍니다. (pwquality.conf.d 등)
def list_conf_files(directory):
    return sorted(glob.glob(os.path.join(directory, "*.conf")))


# ==================================================
# 3. 설정 내용 나누기
# ==================================================

# /etc/os-release 내용에서 ID(ubuntu, rocky)와 VERSION_ID(24.04, 9.6)를 꺼냅니다.
def parse_os_release(text):
    values = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"')
    return values.get("ID", "").lower(), values.get("VERSION_ID", "")


# PAM 설정 파일을 한 줄씩 나눕니다.
# 예: "password  requisite  pam_pwquality.so retry=3"
#   -> {"type": "password", "control": "requisite", "module": "pam_pwquality.so", "args": ["retry=3"]}
# 대괄호 제어값([success=1 default=ignore])은 공백이 있어도 하나로 묶습니다.
PAM_LINE = re.compile(r"^(-?[A-Za-z]+)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$")


def parse_pam(text, path=""):
    entries = []
    for number, raw in enumerate((text or "").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()        # 주석 제거
        if not line or line.startswith("@"):         # 빈 줄, @include 줄은 건너뜀
            continue
        match = PAM_LINE.match(line)
        if not match:
            continue
        pam_type, control, module, args = match.groups()
        entries.append({
            "file": path,
            "line": number,
            "type": pam_type.lstrip("-").lower(),     # "-auth" -> "auth"
            "control": control,
            "module": os.path.basename(module),       # /lib/.../pam_unix.so -> pam_unix.so
            "args": args.split(),
        })
    return entries


# PAM 인자 목록을 {이름: 값}으로 바꿉니다. 값이 없는 인자는 True
# 예: ["retry=3", "silent"] -> {"retry": "3", "silent": True}
def parse_args(args):
    result = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        result[key.lower()] = value if sep else True
    return result


# "key = value" 형식 설정 파일(pwquality.conf, faillock.conf)을 읽습니다.
# 값이 없는 줄(예: silent)은 True로 저장합니다.
def parse_kv_conf(text):
    result = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        result[key.strip().lower()] = value.strip() if sep else True
    return result


# /etc/login.defs 처럼 "KEY 값" 형식인 파일을 읽습니다.
def parse_login_defs(text):
    result = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0]] = parts[1].strip()
    return result


# 글자를 정수로 바꿉니다. 바꿀 수 없으면 None
def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ==================================================
# 4. 계정별 비밀번호 기간 읽기 (chage -l, 읽기 전용)
#    /etc/shadow를 직접 읽지 않고, 해시도 수집하지 않습니다.
# ==================================================

def run_chage(account):
    if not ACCOUNT_NAME.match(account or ""):
        return None
    try:
        output = subprocess.run(
            ["chage", "-l", account],
            capture_output=True, text=True, check=True, timeout=10,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},   # 영어 출력으로 고정
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return parse_chage(output)


# chage -l 결과에서 최소·최대 사용 기간만 꺼냅니다. 형식이 다르면 None
def parse_chage(output):
    values = {}
    for line in (output or "").splitlines():
        label, sep, value = line.partition(":")
        label = label.strip().lower()
        if label == "minimum number of days between password change":
            values["min_days"] = to_int(value)
        elif label == "maximum number of days between password change":
            values["max_days"] = to_int(value)
    if values.get("min_days") is None or values.get("max_days") is None:
        return None
    return values


# ==================================================
# 5. 정책 JSON 공통 검사
# ==================================================

def is_text(value):
    return isinstance(value, str) and bool(value.strip())


def is_text_list(value, allow_empty=False):
    if not isinstance(value, list) or (not value and not allow_empty):
        return False
    return all(is_text(item) for item in value)


# 정책 파일을 읽고 check_id에 맞는 정책을 찾아 돌려줍니다.
# validate_criteria: 항목별(ACC-01, ACC-02) criteria 검사 함수
def load_policy(path, check_id, validate_criteria):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not is_text(data.get("policy_version")):
        raise ValueError("missing or invalid field: policy_version")
    if not isinstance(data.get("policies"), list) or not data["policies"]:
        raise ValueError("missing or invalid field: policies")

    for policy in data["policies"]:
        if not isinstance(policy, dict):
            raise ValueError("policy item must be an object")
        if policy.get("check_id") != check_id:
            continue
        for field in ("check_id", "description", "severity"):
            if not is_text(policy.get(field)):
                raise ValueError(f"missing or invalid field: {field}")
        if policy["severity"] not in ALLOWED_SEVERITIES:
            raise ValueError(f"unknown severity: {policy['severity']}")
        if not is_text_list(policy.get("applies_to")):
            raise ValueError("missing or invalid field: applies_to")
        if not isinstance(policy.get("criteria"), dict):
            raise ValueError("missing or invalid field: criteria")
        validate_cvss_assessment(policy.get("cvss_assessment"))
        validate_criteria(policy["criteria"], policy["applies_to"])
        return policy
    raise ValueError(f"policy not found: {check_id}")


def validate_cvss_assessment(cvss_assessment):
    if cvss_assessment is None:
        return
    if not isinstance(cvss_assessment, dict):
        raise ValueError("invalid field: cvss_assessment")
    if cvss_assessment.get("vulnerable_assessment_status") not in ALLOWED_VULNERABLE_CVSS_STATUSES:
        raise ValueError("invalid field: cvss_assessment.vulnerable_assessment_status")
    if not is_text(cvss_assessment.get("rationale")):
        raise ValueError("missing or invalid field: cvss_assessment.rationale")


# OS별 프로파일 검사: applies_to의 OS마다 프로파일이 있고, 필요한 키가 있는지
def validate_profiles(criteria, applies_to, required_keys):
    profiles = criteria.get("profiles")
    if not isinstance(profiles, dict):
        raise ValueError("missing or invalid field: criteria.profiles")
    for os_id in applies_to:
        profile = profiles.get(os_id)
        if not isinstance(profile, dict):
            raise ValueError(f"missing profile for: {os_id}")
        for key in required_keys:
            if key not in profile:
                raise ValueError(f"missing field: criteria.profiles.{os_id}.{key}")


# ==================================================
# 6. 결과 만들기
# ==================================================

def make_result(check_id, recommendations, status, severity, evidence, details=None):
    result = {
        "check_id": check_id,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendations[status],
    }
    if details is not None:
        result["details"] = details
    return result


# 세부 항목 1개의 판정 기록 (details.findings에 들어감)
def make_finding(item, actual, expected, status, reason, source=None):
    finding = {"item": item, "actual": actual, "expected": expected, "status": status, "reason": reason}
    if source:
        finding["source"] = source      # 값을 읽은 파일 (예: /etc/login.defs)
    return finding


def worst_status(statuses):
    for status in STATUS_PRIORITY:
        if status in statuses:
            return status
    return "pass"


# 사람이 읽을 근거 문장: pass가 아닌 항목만, 같은 내용은 한 번만
def build_evidence(head, findings):
    issues = []
    for f in findings:
        if f["status"] == "pass":
            continue
        text = f"{f['status']}: {f['item']} {f['actual']} ({f['reason']})"
        if text not in issues:
            issues.append(text)
    if not issues:
        return f"{head}; all checked items match approved policy"
    return f"{head}; " + "; ".join(issues)


# v1.2 cvss 객체 (B는 점수를 매기지 않으므로 점수·등급은 항상 null)
def build_cvss(status, policy):
    if status == "vulnerable":
        cvss_assessment = (policy or {}).get("cvss_assessment")
        if cvss_assessment:
            assessment_status = cvss_assessment["vulnerable_assessment_status"]
            rationale = cvss_assessment["rationale"]
        else:
            assessment_status = "pending"
            rationale = "CVSS 평가 검토 전 (정책에 cvss_assessment 설정 없음, JSON 계약 v1.2 6장 전환 규칙)"
    else:
        assessment_status = "not_applicable"
        rationale = f"진단 상태가 {status}이므로 CVSS 평가 대상 아님"
    return {
        "assessment_status": assessment_status,
        "version": None, "vector": None, "base_score": None,
        "rating": None, "source": None,
        "rationale": rationale,
    }


# v1.1 결과를 v1.2로 바꿉니다. (severity 제거, cvss 추가, details 유지)
def to_result_v1_2(result, policy):
    converted = {
        "check_id": result["check_id"],
        "status": result["status"],
        "evidence": result["evidence"],
        "recommendation": result["recommendation"],
        "cvss": build_cvss(result["status"], policy),
    }
    if "details" in result:
        converted["details"] = result["details"]
    return converted


def check_result_version(result_version):
    if result_version not in SUPPORTED_RESULT_VERSIONS:
        raise ValueError(f"unsupported result_version: {result_version}")
