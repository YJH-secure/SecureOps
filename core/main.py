import json
import os
import sys
import re
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

class DiagnosisAggregator:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = self._load_json()

    @classmethod
    def from_results(cls, account_results, system_results, *, target_id, os,
                     scan_id=None, scanned_at=None):
        """같은 서버·같은 실행의 B/C 결과 목록으로 새 보고서를 만든다.

        실제 진단 함수를 호출하지 않는다. 개별 반환 객체는 [result]로 전달한다.
        target_id와 os는 실행 계층에서 제공하며, None인 실행 ID/완료 시각만
        새로 생성한다. 기존 보고서의 누락 정보를 보정하는 용도가 아니다.
        """
        for name, results in (("account_results", account_results),
                              ("system_results", system_results)):
            if not isinstance(results, list):
                raise TypeError(f"{name}는 개별 결과 객체의 list여야 합니다.")
        report = {
            "schema_version": "1.1",
            "scan_id": str(uuid4()) if scan_id is None else scan_id,
            "target_id": target_id,
            "os": os,
            "scanned_at": (datetime.now(timezone.utc).isoformat()
                           if scanned_at is None else scanned_at),
            "results": deepcopy(account_results + system_results),
        }
        cls._validate_report(report)
        # details까지 실제 JSON으로 전달 가능한 값인지 확인한다.
        json.dumps(report, ensure_ascii=False, allow_nan=False)
        aggregator = cls.__new__(cls)
        aggregator.filepath = None
        aggregator.data = report
        return aggregator

    def to_json(self) -> str:
        """통계 요약을 섞지 않은 공통 v1.1 보고서를 JSON 문자열로 반환한다."""
        return json.dumps(self.get_report(), ensure_ascii=False, indent=2, allow_nan=False)

    def _load_json(self) -> dict:
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"진단 결과 JSON 파일을 찾을 수 없습니다: {self.filepath}")

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON 파일 형식이 올바르지 않습니다 (디코딩 오류): {e}")

        if not isinstance(data, dict):
            raise ValueError("JSON 데이터 최상위 포맷은 객체(Object) 형태여야 합니다.")

        self._validate_fields(data, {"schema_version": str}, {}, "report")
        if data["schema_version"] != "1.1":
            raise ValueError(
                "지원 버전은 1.1입니다. v1.0은 자동 변환하지 않습니다. "
                "별도 이전 시 scan_id, 버전이 포함된 os, 항목별 recommendation이 필요합니다."
            )
        self._validate_report(data)

        return data

    @staticmethod
    def _validate_fields(obj, required, optional, location, reject_extra=False):
        if not isinstance(obj, dict):
            raise TypeError(f"{location}은 객체여야 합니다.")
        for field in required:
            if field not in obj:
                raise KeyError(f"{location}.{field} 필수 필드가 누락되었습니다.")
        allowed = {**required, **optional}
        if reject_extra and obj.keys() - allowed.keys():
            raise ValueError(f"{location}: 허용되지 않은 필드 {sorted(obj.keys() - allowed.keys())}")
        for field, expected_type in allowed.items():
            if field not in obj:
                continue
            if not isinstance(obj[field], expected_type):
                raise TypeError(f"{location}.{field}: {expected_type.__name__} 타입이어야 합니다.")
            if expected_type is str and not obj[field]:
                raise ValueError(f"{location}.{field}: 빈 문자열은 허용하지 않습니다.")

    @staticmethod
    def _validate_timestamp(value, location):
        # Schema의 date-time에 맞춰 날짜, 시각, UTC 또는 오프셋을 요구한다.
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", value
        ):
            raise ValueError(f"{location}: 타임존이 포함된 ISO 8601 날짜·시각이 필요합니다.")
        try:
            parsed = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"{location}: 올바르지 않은 날짜·시각입니다.") from e
        if parsed.utcoffset() is None:
            raise ValueError(f"{location}: 타임존이 필요합니다.")

    @classmethod
    def _validate_report(cls, data):
        cls._validate_fields(data, {
            "schema_version": str, "scan_id": str, "target_id": str,
            "os": str, "scanned_at": str, "results": list,
        }, {"ip_address": str}, "report", reject_extra=True)
        if data["schema_version"] != "1.1":
            raise ValueError("지원 버전은 1.1입니다.")
        cls._validate_timestamp(data["scanned_at"], "scanned_at")
        if not data["results"]:
            raise ValueError("results는 1개 이상의 결과를 포함해야 합니다.")
        seen = set()
        for idx, item in enumerate(data["results"]):
            location = f"results[{idx}]"
            cls._validate_fields(item, {
                "check_id": str, "status": str, "severity": str,
                "evidence": str, "recommendation": str,
            }, {"category": str, "title": str, "checked_at": str, "details": dict},
                location, reject_extra=True)
            if item["status"] not in {"pass", "vulnerable", "error", "not_applicable", "needs_review"}:
                raise ValueError(f"{location}: 허용되지 않은 status입니다.")
            if item["severity"] not in {"critical", "high", "medium", "low"}:
                raise ValueError(f"{location}: 허용되지 않은 severity입니다.")
            if item["check_id"] in seen:
                raise ValueError(f"{location}: 중복 check_id '{item['check_id']}'")
            seen.add(item["check_id"])
            if "checked_at" in item:
                cls._validate_timestamp(item["checked_at"], f"{location}.checked_at")

    def get_report(self) -> dict:
        """검증된 공통 v1.1 보고서를 통계 요약과 별도로 반환한다."""
        self._validate_report(self.data)
        return deepcopy(self.data)

    def aggregate_results(self) -> dict:
        self._validate_report(self.data)
        results = self.data.get("results", [])

        total_items = len(results)
        pass_count = 0
        vulnerable_count = 0
        error_count = 0
        na_count = 0
        needs_review_count = 0

        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_breakdown = {}

        for item in results:
            status = item["status"]
            severity = item["severity"]
            category = str(item.get("category", "기타")).strip()

            if category not in category_breakdown:
                category_breakdown[category] = {"PASS": 0, "VULNERABLE": 0, "ERROR": 0, "N/A": 0, "REVIEW": 0}

            if status == "pass":
                pass_count += 1
                category_breakdown[category]["PASS"] += 1
            elif status == "vulnerable":
                vulnerable_count += 1
                category_breakdown[category]["VULNERABLE"] += 1
                severity_breakdown[severity] += 1
            elif status == "error":
                error_count += 1
                category_breakdown[category]["ERROR"] += 1
            elif status == "not_applicable":
                na_count += 1
                category_breakdown[category]["N/A"] += 1
            elif status == "needs_review":
                needs_review_count += 1
                category_breakdown[category]["REVIEW"] += 1

        evaluable_items = pass_count + vulnerable_count

        if evaluable_items > 0:
            pass_rate_value = round((pass_count / evaluable_items) * 100, 1)
            pass_rate_str = f"{pass_rate_value}%"
        else:
            pass_rate_str = "N/A (계산 불가)"

        summary = {
            "schema_version": self.data["schema_version"],
            "target_info": {
                "target_id": self.data["target_id"],
                "ip_address": self.data.get("ip_address", "Unknown"),
                "os": self.data["os"],
                "scan_id": self.data["scan_id"],
                "scanned_at": self.data["scanned_at"]
            },
            "metrics": {
                "total_items": total_items,
                "evaluable_items": evaluable_items,
                "pass_count": pass_count,
                "vulnerable_count": vulnerable_count,
                "error_count": error_count,
                "na_count": na_count,
                "needs_review_count": needs_review_count,
                "pass_rate": pass_rate_str
            },
            "severity_breakdown": severity_breakdown,
            "category_breakdown": category_breakdown
        }

        return summary

    def print_summary(self, summary: dict):
        target = summary["target_info"]
        metrics = summary["metrics"]
        severity = summary["severity_breakdown"]
        category = summary["category_breakdown"]

        print("=" * 70)
        print("          Linux 서버 보안 진단 결과 통합 집계 보고서          ")
        print("=" * 70)
        print(f"■ 규격 버전 : v{summary['schema_version']}")
        print(f"■ 대상 서버 : {target['target_id']} ({target['ip_address']})")
        print(f"■ 운영 체제 : {target['os'].upper()}")
        print(f"■ 스캔 ID : {target['scan_id']}")
        print(f"■ 진단 일시 : {target['scanned_at']}")
        print("-" * 70)
        print("■ 전체 집계 현황")
        print(f"  - 전체 항목 수      : {metrics['total_items']} 건")
        print(f"  - 판정 완료 항목 수 : {metrics['evaluable_items']} 건 (양호 + 취약)")
        print(f"  - 양호 (PASS) 건수  : {metrics['pass_count']} 건")
        print(f"  - 취약 (VULN) 건수  : {metrics['vulnerable_count']} 건")
        print(f"  - 진단 오류 (ERROR) : {metrics['error_count']} 건")
        print(f"  - 해당 없음 (N/A)   : {metrics['na_count']} 건")
        print(f"  - 검토 필요 (REVIEW): {metrics['needs_review_count']} 건")
        print(f"  - SecureOps 이행률  : {metrics['pass_rate']}")
        print("-" * 70)
        print("■ 취약(VULNERABLE) 항목 심각도별 세부 집계")
        print(f"  - CRITICAL (위험) : {severity['critical']} 건")
        print(f"  - HIGH     (상)   : {severity['high']} 건")
        print(f"  - MEDIUM   (중)   : {severity['medium']} 건")
        print(f"  - LOW      (하)   : {severity['low']} 건")
        print("-" * 70)
        print("■ 카테고리별 진단 현황")
        for cat_name, counts in category.items():
            print(f"  - {cat_name:<10} : 양호 {counts['PASS']} / 취약 {counts['VULNERABLE']} / 오류 {counts['ERROR']} / N/A {counts['N/A']} / 검토 {counts['REVIEW']}")
        print("=" * 70)

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_json_path = os.path.join(base_dir, "tests", "fixtures", "sample-result-v1.1-MOCK.json")

    json_path = sys.argv[1] if len(sys.argv) > 1 else default_json_path

    try:
        aggregator = DiagnosisAggregator(json_path)
        summary_report = aggregator.aggregate_results()
        aggregator.print_summary(summary_report)
    except Exception as e:
        print(f"[오류 발생] {e}", file=sys.stderr)
        sys.exit(1)
