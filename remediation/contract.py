"""외부 패키지 없이 팀 공통 JSON v1.1의 구조와 값 범위를 검증한다."""

import json
import re
from datetime import datetime

STATUSES = {"pass", "vulnerable", "error", "not_applicable", "needs_review"}
SEVERITIES = {"critical", "high", "medium", "low"}


def timestamp(value):
    """ISO 8601 시각 문자열 value를 받아 타임존이 포함된 datetime을 반환한다.

    날짜·시각·타임존이 잘못되면 ValueError로 거부한다.
    """
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value
    ):
        raise ValueError("timezone-aware ISO8601 timestamp required")
    parsed = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("timezone required")
    return parsed


def _fields(obj, required, optional):
    """객체 obj와 {필드명: 자료형}인 required/optional을 받아 필드를 검증한다.

    반환: 정상일 때 None. 누락·알 수 없는 필드·잘못된 자료형은 ValueError.
    """
    if not isinstance(obj, dict) or set(required) - obj.keys() or obj.keys() - (required.keys() | optional.keys()):
        raise ValueError("missing or unknown contract fields")
    for key, kind in (required | optional).items():
        if key in obj and (not isinstance(obj[key], kind) or (kind is str and not obj[key].strip())):
            raise ValueError(f"invalid field: {key}")


def validate_report(report):
    """입력 report가 공통 JSON v1.1 보고서인지 검증한다.

    반환: 정상일 때 None. 필드·상태·중복 ID·시각 등의 규격 위반은 예외로 거부한다.
    입력 수정이나 레거시 자동 변환은 하지 않는다. 민감정보 제거는 호출자 책임이다.
    """
    _fields(report, {"schema_version": str, "scan_id": str, "target_id": str,
                     "os": str, "scanned_at": str, "results": list}, {"ip_address": str})
    if report["schema_version"] != "1.1" or not report["results"]:
        raise ValueError("nonempty v1.1 report required")
    timestamp(report["scanned_at"])
    seen = set()
    for item in report["results"]:
        _fields(item, {"check_id": str, "status": str, "severity": str,
                       "evidence": str, "recommendation": str},
                {"category": str, "title": str, "checked_at": str, "details": dict})
        if item["status"] not in STATUSES or item["severity"] not in SEVERITIES:
            raise ValueError("unknown status/severity")
        if item["check_id"] in seen:
            raise ValueError("duplicate check_id")
        seen.add(item["check_id"])
        if "checked_at" in item:
            timestamp(item["checked_at"])
    json.dumps(report, allow_nan=False)
