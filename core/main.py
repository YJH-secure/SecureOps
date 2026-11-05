import json
import os
import sys
from datetime import datetime

class DiagnosisAggregator:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = self._load_json()

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

        if "results" not in data or not isinstance(data["results"], list):
            raise KeyError("JSON 데이터 내 필수 항목인 'results' 리스트가 누락되었거나 형식 오류입니다.")
            
        return data

    def aggregate_results(self) -> dict:
        results = self.data.get("results", [])
        
        total_items = len(results)
        pass_count = 0
        vulnerable_count = 0
        error_count = 0
        na_count = 0
        needs_review_count = 0
        
        severity_breakdown = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_breakdown = {}

        valid_statuses = {"pass", "vulnerable", "error", "not_applicable", "needs_review"}

        for idx, item in enumerate(results):
            if not isinstance(item, dict):
                raise ValueError(f"results[{idx}] 항목이 올바른 JSON 객체 형태가 아닙니다.")
            
            if "check_id" not in item:
                raise KeyError(f"results[{idx}] 항목에 필수 필드 'check_id'가 누락되었습니다.")

            status = str(item.get("status", "")).lower()
            severity = str(item.get("severity", "LOW")).upper()
            category = item.get("category", "기타")

            if status not in valid_statuses:
                raise ValueError(f"results[{idx}] ('{item.get('check_id')}')에 유효하지 않은 상태값('{status}')이 입력되었습니다.")

            if category not in category_breakdown:
                category_breakdown[category] = {"PASS": 0, "VULNERABLE": 0, "ERROR": 0, "N/A": 0, "REVIEW": 0}

            if status == "pass":
                pass_count += 1
                category_breakdown[category]["PASS"] += 1
            elif status == "vulnerable":
                vulnerable_count += 1
                category_breakdown[category]["VULNERABLE"] += 1
                if severity in severity_breakdown:
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
            pass_rate_str = "N/A(계산 불가)"

        summary = {
            "target_info": {
                "target_id": self.data.get("target_id", "Unknown"),
                "ip_address": self.data.get("ip_address", "Unknown"),
                "os_type": self.data.get("os_type", "Unknown"),
                "scanned_at": self.data.get("scanned_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
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
        print(f"■ 대상 서버 : {target['target_id']} ({target['ip_address']})")
        print(f"■ 운영 체제 : {target['os_type'].upper()}")
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
        print(f"  - HIGH   (상) : {severity['HIGH']} 건")
        print(f"  - MEDIUM (중) : {severity['MEDIUM']} 건")
        print(f"  - LOW    (하) : {severity['LOW']} 건")
        print("-" * 70)
        print("■ 카테고리별 진단 현황")
        for cat_name, counts in category.items():
            print(f"  - {cat_name:<10} : 양호 {counts['PASS']} / 취약 {counts['VULNERABLE']} / 오류 {counts['ERROR']} / N/A {counts['N/A']} / 검토 {counts['REVIEW']}")
        print("=" * 70)

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_json_path = os.path.join(base_dir, "tests", "fixtures", "sample_diagnosis.json")
    
    json_path = sys.argv[1] if len(sys.argv) > 1 else default_json_path
    
    try:
        aggregator = DiagnosisAggregator(json_path)
        summary_report = aggregator.aggregate_results()
        aggregator.print_summary(summary_report)
    except Exception as e:
        print(f"[오류 발생] {e}")