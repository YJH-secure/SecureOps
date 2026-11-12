# SecureOps 공통 JSON v1.1 — 팀원 AI 코드 점검 가이드

**상태: 2026-11-06 팀장 확정 개발 기준선**  
담당자: B 최종욱 / C 김서후 / D 조효민 / E 박태준 / A 김민우 (메타데이터)  
이 파일은 AI 코딩 도구와 개발자가 같은 기준으로 점검하도록 작성한 안내문이다.

## 반드시 함께 읽을 파일

1. [공통 결과 계약 v1.1](./json-result-contract-v1.1.md) — 팀장 확정 규격
2. [JSON Schema v1.1](./json-result-schema-v1.1.schema.json) — 형식 자동 검증
3. [MOCK 샘플](../../tests/fixtures/sample-result-v1.1-MOCK.json) — 예시 데이터
4. [기존 v1.0 계약](./json-result-contract-v1.md) — 해당 파일은 구 버전 브랜치에만 있을 수 있음. v1.1 우선

규격에 따라 **서버 한 대의 스캔 한 번 = JSON 보고서 1개**이다. B/C는 `results[]` 내부 항목을 반환하고, D가 최상위 메타데이터·배열을 생성한다. E는 승인된 조치 후 새로운 `scan_id`로 재검증한다.

## 각자 사용하는 AI에게 그대로 전달할 프롬프트

> SecureOps 프로젝트의 공통 JSON 결과 규격 v1.1 준수 여부를 검토해 줘.
>
> 기준 문서: `docs/architecture/json-result-contract-v1.1.md`
>
> 검증 스키마: `docs/architecture/json-result-schema-v1.1.schema.json`
>
> MOCK 샘플: `tests/fixtures/sample-result-v1.1-MOCK.json`
>
> 내 담당 코드(또는 내가 제공한 코드)를 이 규격과 비교해 다음 항목을 점검해 줘.
>
> 1. B/C의 개별 결과 필수 5필드(`check_id/status/severity/evidence/recommendation`)가 정확한가?
> 2. D의 최상위 6필드(`schema_version/scan_id/target_id/os/scanned_at/results`)가 정확한가?
> 3. `status` 다섯 종류, `severity` 소문자 네 종류, 자료형, 시간대 표기가 맞는가?
> 4. 이전 필드명(`server_id/os_type/guide`)이나 대문자 severity가 출력에 남아 있지 않은가?
> 5. `error`와 `needs_review`를 양호로 처리하지 않는가? 중복 `check_id`, 빈 결과, 민감정보 문제는 없는가?
> 6. 기존 기능을 보존하면서 최소한의 수정으로 호환 가능한가?
>
> **반환 형식**: (A) 규격 준수 여부, (B) 불일치 파일명·함수명·라인·근거, (C) 최소 수정안, (D) 실제 실행 가능한 테스트 방법, (E) 확인하지 못한 항목. 코드는 사용자 승인 없이 자동 수정·push·merge하지 말 것. 실제 테스트를 실행하지 않았다면 실행한 것처럼 말하지 말 것.
>
> GitHub 저장소가 비공개여서 접근할 수 없다면 코드를 보았다고 가정하지 말고 접근 불가라고 말해 줘. 이 경우 내가 직접 파일을 제공할게.

## 담당자별 추가 확인

| 담당 | 확인할 부분 |
|---|---|
| B 최종욱 | 개별 진단 딕셔너리, 5개 필수 결과 필드, 소문자 위험도 |
| C 김서후 | FILE-01 등 결과 객체, `evidence` 문자열 + 선택 `details` 객체 |
| D 조효민 | 상위 스캔 보고서 생성, 필수 필드 검증, 구 필드 정규화, 5상태 집계 |
| E 박태준 | `target_id + check_id` 매칭, 재검증 `scan_id` 분리, 승인 게이트 |
| A 김민우 | 대상 `target_id` 안정성, OS 버전 전달, 원격 계정 정보 결과에 노출 금지 |

## 자동 검증 방법

Python `jsonschema` 패키지를 사용할 경우:

```bash
python -m pip install jsonschema
python - <<'PY'
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

schema = json.loads(Path("docs/architecture/json-result-schema-v1.1.schema.json").read_text(encoding="utf-8"))
data = json.loads(Path("tests/fixtures/sample-result-v1.1-MOCK.json").read_text(encoding="utf-8"))
Draft202012Validator(schema, format_checker=FormatChecker()).validate(data)
ids = [r["check_id"] for r in data["results"]]
assert len(ids) == len(set(ids)), "중복 check_id"
print("Schema + 중복 ID 검증 통과")
PY
```

**중요:** JSON Schema만으로 중복 `check_id`, `scan_id` 전체 저장 이력상의 유일성, 민감정보 노출, 취약점 판정의 타당성까지 모두 확인할 수는 없다. 별도 검증 코드와 실제 VM 테스트가 필요하다. MOCK 결과를 실환경 검증 완료로 보고하지 않는다.

## 검토 결과 공유 양식

- 담당 모듈 / 브랜치 / 커밋:
- 검토한 코드 파일:
- 규격 준수 항목:
- 불일치·수정 예정 항목:
- 실행한 테스트 및 결과:
- 기존 모듈과 연동 시 장애 가능성:
- 팀장 검토·승인 요청:

## 변경 관리

v1.1은 신규 개발의 기준선이며 코드 반영 완료를 의미하지 않는다. 필수 필드명·자료형·상태값 변경은 팀장에게 영향 분석을 공유한 후 버전 개정·PR로 처리한다. 비밀값·키·실제 비밀번호는 공개 AI 입력이나 GitHub에 올리지 않는다.
