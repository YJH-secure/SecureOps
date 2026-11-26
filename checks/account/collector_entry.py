"""
B 수집기 출력 입구 (judge_collector_output) - 11/26 팀장 조건부 승인, 신규 파일 최소 구현

[하는 일]
수집기(b_collector.py)가 낸 원본 stdout 1건을 받아
  1) UTF-8·JSON 1줄인지 (decode)
  2) collector·context_used·payloads 구조와 점검 3개가 정확한지 (structure)
  3) context_used가 승인된 host·addr와 같은지 (context)
  4) 대상 OS·버전이 승인된 값과 같은지 (os)
를 먼저 확인하고, 통과하면 기존 judge_payload로 점검별 JSON v1.2 결과 3개를 만듭니다.

[실패 구분]
- 신뢰성 오류 (위 1~4) -> CollectorTrustError(stage, reason) : 진단 결과를 만들지 않음 (D 저장 전 STOP)
- 호출 실수 (잘못된 인자)  -> ValueError
- 신뢰된 상태에서 개별 항목 수집 실패 -> STOP 아님, 기존 판정대로 status=error·needs_review 결과

[책임 범위]
- A 전송 계층의 exit_code·stderr·timeout·truncated는 이 함수 호출 전에 A/D가 확인합니다. (raw_stdout만으로 알 수 없음)
- 기존 central_adapter.judge_payload와 판정 함수·정책은 바꾸지 않습니다.

[사용 예]
    from collector_entry import judge_collector_output, CollectorTrustError
    trusted = {"host": "10.40.0.10", "addr": "10.40.0.10", "os_id": "ubuntu", "os_version": "24.04"}
    try:
        results = judge_collector_output(raw_stdout_bytes, trusted)   # {"SSH-02": {...}, "ACC-01": {...}, "ACC-02": {...}}
    except CollectorTrustError as stop:
        ...  # stop.stage, stop.reason 를 실행 실패 기록으로 (진단 결과 없음)
"""

import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import account_common as common     # noqa: E402  os-release 해석
import central_adapter as adapter   # noqa: E402  기존 judge_payload, 기록 정규화
import ssh_auth_check as ssh02      # noqa: E402  host/addr 형식 검사


CHECK_IDS = ("SSH-02", "ACC-01", "ACC-02")                 # 결과 3개, 이 순서
TOP_KEYS = {"collector", "context_used", "payloads"}       # 최상위 필드 (정확히 이 3개)
TRUSTED_KEYS = {"host", "addr", "os_id", "os_version"}     # 승인 context 필수 키 (정확히 이 4개)
COLLECTOR_NAME = "secureops-b-read"
OS_PAYLOADS = ("ACC-01", "ACC-02")                         # os_release 기록이 들어 있는 점검


# 신뢰성 오류 : 이 예외가 나면 진단 결과가 없습니다. (D는 실행 실패 기록으로 관리)
#   stage  : decode / structure / context / os
#   reason : 짧은 원인 코드 (예 : host_mismatch)
class CollectorTrustError(Exception):
    STAGES = ("decode", "structure", "context", "os")

    def __init__(self, stage, reason):
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason


# ==================================================
# 1. 호출 실수 검사 (ValueError)
# ==================================================

def _check_arguments(raw_stdout, trusted_context, policy_paths, result_version):
    if not isinstance(raw_stdout, bytes):
        raise ValueError("raw_stdout must be bytes")
    if not isinstance(trusted_context, dict) or set(trusted_context) != TRUSTED_KEYS:
        raise ValueError("trusted_context must have exactly host, addr, os_id, os_version")
    if not all(ssh02.is_safe_name(trusted_context[key]) for key in TRUSTED_KEYS):
        raise ValueError("trusted_context values must be non-empty text without spaces or commas")
    if not isinstance(result_version, str) or result_version not in adapter.SUPPORTED_RESULT_VERSIONS:
        raise ValueError(f"unsupported result_version: {result_version!r}")
    if policy_paths is not None:
        if not isinstance(policy_paths, dict) or not set(policy_paths) <= set(CHECK_IDS):
            raise ValueError("policy_paths must map check_id to a policy file path")
        if not all(isinstance(path, str) and path.strip() for path in policy_paths.values()):
            raise ValueError("policy_paths values must be non-empty text")


# ==================================================
# 2. decode : UTF-8 + JSON 1줄 (같은 키가 두 번 나오면 structure 오류)
# ==================================================

# JSON 안에서 같은 키가 두 번 나오면 기본 동작은 뒤의 값으로 조용히 덮어씀 -> 바꿔치기 방지로 STOP
def _reject_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise CollectorTrustError("structure", "duplicate_key")
    return dict(pairs)


def _decode(raw_stdout):
    try:
        text = raw_stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise CollectorTrustError("decode", "stdout_not_utf8") from None
    if text.endswith("\n"):
        text = text[:-1]                                       # 끝의 줄바꿈 1개만 허용
    if not text.strip() or "\n" in text or "\r" in text:
        raise CollectorTrustError("decode", "not_single_line_json")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates)
    except json.JSONDecodeError:
        raise CollectorTrustError("decode", "invalid_json") from None


# ==================================================
# 3. structure : 최상위 3개, 점검 3개
# ==================================================

def _check_structure(document):
    if not isinstance(document, dict) or set(document) != TOP_KEYS:
        raise CollectorTrustError("structure", "top_level_fields")
    collector = document["collector"]
    if not isinstance(collector, dict) or collector.get("name") != COLLECTOR_NAME:
        raise CollectorTrustError("structure", "collector_name")
    context_used = document["context_used"]
    if not isinstance(context_used, dict) or set(context_used) != {"host", "addr"}:
        raise CollectorTrustError("structure", "context_used_fields")
    payloads = document["payloads"]
    if not isinstance(payloads, dict) or set(payloads) != set(CHECK_IDS):
        raise CollectorTrustError("structure", "payload_checks")       # 누락·추가 점검
    if not all(isinstance(payloads[check_id], dict) for check_id in CHECK_IDS):
        raise CollectorTrustError("structure", "payload_type")


# ==================================================
# 4. context : 수집기가 실제로 쓴 host/addr = 승인된 값
# ==================================================

def _check_context(document, trusted_context):
    used = document["context_used"]
    for key in ("host", "addr"):
        if used[key] != trusted_context[key]:
            raise CollectorTrustError("context", f"{key}_mismatch")


# ==================================================
# 5. os : ACC-01·ACC-02의 os_release가 둘 다 읽혔고, ID·VERSION_ID가 승인된 값과 같음
# ==================================================

def _check_os(document, trusted_context):
    for check_id in OS_PAYLOADS:
        state, text = adapter.normalize_record(document["payloads"][check_id].get("os_release"))
        if state != "ok":
            raise CollectorTrustError("os", "os_release_unreadable")    # 대상 OS를 확인할 수 없음
        os_id, os_version = common.parse_os_release(text)
        if os_id != trusted_context["os_id"]:
            raise CollectorTrustError("os", "os_id_mismatch")
        if os_version != trusted_context["os_version"]:
            raise CollectorTrustError("os", "os_version_mismatch")


# ==================================================
# 6. 입구 함수
# ==================================================

def judge_collector_output(raw_stdout, trusted_context, *, policy_paths=None, result_version="1.2"):
    _check_arguments(raw_stdout, trusted_context, policy_paths, result_version)
    document = _decode(raw_stdout)
    _check_structure(document)
    _check_context(document, trusted_context)
    _check_os(document, trusted_context)

    # 신뢰성 확인 통과 -> 기존 judge_payload로 점검별 판정 (SSH-02 context는 승인된 값만 사용)
    ssh_context = {"host": trusted_context["host"], "addr": trusted_context["addr"]}
    policy_paths = policy_paths or {}
    return {
        check_id: adapter.judge_payload(check_id, document["payloads"][check_id], ssh_context,
                                        policy_path=policy_paths.get(check_id),
                                        result_version=result_version)
        for check_id in CHECK_IDS
    }
