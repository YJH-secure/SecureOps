"""명시적으로 호출하는 레거시 보고서 이전. 파일 읽기·저장·진단은 하지 않는다."""

from copy import deepcopy
import json
import re

from core.main import DiagnosisAggregator


def _rename_string(data, old, new, location):
    if old not in data:
        return
    for field in (old, new):
        if field in data and not isinstance(data[field], str):
            raise TypeError(f"{location}.{field}: 문자열이어야 합니다.")
    if new in data and data[old] != data[new]:
        raise ValueError(f"{location}: {old}와 {new} 값이 충돌합니다.")
    data[new] = data.pop(old)


def normalize_legacy_report(data: dict) -> dict:
    """완전한 레거시 보고서를 복사하여 검증된 v1.1 딕셔너리로 반환한다.

    schema_version 1.0/1.1만 지원한다. scan_id 및 버전 포함 os는 입력에
    있어야 하며 생성·추정하지 않는다. evidence 객체 변환이나 status 보정은
    하지 않는다. 일반 v1.1 로더에서는 이 함수를 자동 호출하지 않는다.
    """
    if not isinstance(data, dict):
        raise TypeError("report: 객체여야 합니다.")
    if "schema_version" not in data:
        raise KeyError("schema_version이 필요합니다.")
    if not isinstance(data["schema_version"], str):
        raise TypeError("schema_version: 문자열이어야 합니다.")
    if data["schema_version"] not in {"1.0", "1.1"}:
        raise ValueError("정규화 지원 버전은 1.0과 1.1입니다.")

    report = deepcopy(data)
    for old, new in (("server_id", "target_id"), ("os_type", "os"),
                     ("checked_at", "scanned_at")):
        _rename_string(report, old, new, "report")
    if "scan_id" not in report:
        raise KeyError("scan_id가 필요합니다. 과거 실행 ID를 자동 생성하지 않습니다.")
    if "os" not in report:
        raise KeyError("버전이 포함된 os가 필요합니다. OS 정보를 추정하지 않습니다.")
    if not isinstance(report["os"], str):
        raise TypeError("os: 문자열이어야 합니다.")
    # 특정 배포판이나 버전을 선택하지 않고, 배포판-숫자버전 표현만 확인한다.
    if not re.fullmatch(r".+-[0-9][0-9A-Za-z._+-]*", report["os"]):
        raise ValueError("os에 명시적인 버전이 필요합니다. 예: ubuntu-24.04")
    if "results" not in report:
        raise KeyError("results가 필요합니다.")
    if not isinstance(report["results"], list):
        raise TypeError("results: 목록이어야 합니다.")
    for index, item in enumerate(report["results"]):
        location = f"results[{index}]"
        if not isinstance(item, dict):
            raise TypeError(f"{location}: 객체여야 합니다.")
        _rename_string(item, "guide", "recommendation", location)
        if "recommendation" not in item:
            raise KeyError(f"{location}.recommendation 또는 guide가 필요합니다.")
        if "severity" in item:
            if not isinstance(item["severity"], str):
                raise TypeError(f"{location}.severity: 문자열이어야 합니다.")
            item["severity"] = item["severity"].lower()
    report["schema_version"] = "1.1"
    DiagnosisAggregator._validate_report(report)
    json.dumps(report, ensure_ascii=False, allow_nan=False)
    return report
