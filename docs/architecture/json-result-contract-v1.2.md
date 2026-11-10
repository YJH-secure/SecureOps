# SecureOps 공통 JSON 결과 계약 v1.2 — CVSS v3.1 초안

- 작성: 2026-11-10 / 책임: 팀장 (보안 아키텍처·통합 기준)
- 상태: **DRAFT / 미승인 / 미배포**
- 범위: B/C 진단 결과 → D CVSS 점수 검증·집계 → E 조치 후보·재검증
- 기준 문서: [CVSS 평가 정책 v1.2](../security-policy/cvss-scoring-policy-v1.2.md)
- 검증 스키마: [json-result-schema-v1.2.schema.json](json-result-schema-v1.2.schema.json)
- 참고 규격: [기존 JSON v1.1](json-result-contract-v1.1.md) — **기존 동작과 계약을 수정하지 않는다**

## 1. 변경 의도와 명시적 비호환 사항

- 진단 판정 상태 `status`의 5종(`pass/vulnerable/error/not_applicable/needs_review`)은 **그대로 유지**한다.
- v1.1의 `severity`는 정해진 검사 ID에 대한 초기 정성적 우선순위였고, CVSS 점수가 아니다. v1.2에는 `severity`를 **넣지 않고**, 별도 `cvss` 객체로 표준 평가 여부·점수·등급을 표현한다.
- 따라서 v1.2는 **v1.1과 비호환적인 신규 계약**이며, v1.1 JSON에 신규 `cvss`만 추가하거나 `schema_version`만 바꾸면 유효한 전환이 아니다.
- v1.1 진단 및 집계 코드, 기존 PR, MOCK 데이터는 현재 상태로 유지한다. 새 계약이 팀장 승인되고 수용 테스트 통과 후 전환한다.
- CVSS 공식 표준 중 프로젝트의 **1차 제안 버전은 v3.1 Base**. v4.0 또는 Temporal/Environmental 메트릭을 v3.1 Base에 혼합하지 않는다.

## 2. 스캔 최상위 객체 — v1.1 유지 필드

| 필드 | 유형 | 필수 | 의미 |
| --- | --- | --- | --- |
| `schema_version` | string | Y | `"1.2"` 고정 |
| `scan_id` | string | Y | 스캔 실행별 고유 ID. 조치 후 재진단은 신규 ID |
| `target_id` | string | Y | 서버 고유 ID. 이전의 `server_id`를 직접 사용하지 않음 |
| `os` | string | Y | 예: `ubuntu-24.04`, `rocky-9.8` |
| `scanned_at` | RFC3339 시간 문자열 | Y | 타임존 포함 |
| `results` | 배열 | Y | 1개 이상 `checkResult` 객체 |
| `ip_address` | string | N | 민감정보 제거한 공개 자료에 실제 주소 게시 금지 |

## 3. 개별 진단 결과 객체 — v1.2

| 필드 | 유형 | 필수 | 의미 |
| --- | --- | --- | --- |
| `check_id` | string | Y | 예: `SSH-01`. 동일 스캔 내 중복 금지 |
| `status` | enum | Y | 기존 5개 진단 상태값 |
| `evidence` | string | Y | 사람이 읽는 진단 근거, 비밀정보 제외 |
| `recommendation` | string | Y | 후속 확인/조치 권고. 실행할 명령으로 해석하지 않음 |
| `cvss` | object | Y | 아래 평가 상태·점수 |
| `category`, `title` | string | N | 화면 분류와 표기 |
| `checked_at` | RFC3339 시간 문자열 | N | 개별 점검 시각 |
| `details` | object | N | 파일별 ACL 등의 기존 상세 증거 보존 |

**삭제된 기존 필드**: `severity`. v1.2 결과에서 사용 금지. 기존 등급은 데이터 변환 시 `cvss.rating`으로 복사하지 않는다.

### cvss 객체 (v1.2 제안 규격)

| 필드 | 유형/허용값 | 필수 | 의미 |
| --- | --- | --- | --- |
| `assessment_status` | `scored/pending/not_applicable` | Y | CVSS 계산 여부와 가능성 |
| `version` | `"3.1"` 또는 null | Y | scored일 때만 `"3.1"` |
| `vector` | string 또는 null | Y | scored일 때 8개 Base 메트릭의 공식 Vector |
| `base_score` | 0~10 숫자 또는 null | Y | scored일 때만 공식 Base Score |
| `rating` | `none/low/medium/high/critical` 또는 null | Y | scored일 때만 Base 점수에서 파생 |
| `source` | string 또는 null | Y | 공식 출처/자체 분석 근거. scored면 비어 있지 않아야 함 |
| `rationale` | string | Y | 점수 메트릭 판단 근거 또는 미평가 사유 |

### 진단 상태와 CVSS 평가 상태의 조합

| 진단 `status` | 허용 CVSS 상태 | 처리 |
| --- | --- | --- |
| `vulnerable` | `scored` | 실제 구체적 취약 사례에 대해 8개 메트릭과 점수를 검증 완료 |
| `vulnerable` | `pending` | 평가 가능성 또는 근거 미확정. **점수 null** |
| `vulnerable` | `not_applicable` | 정책/준수 위반이나 CVSS 범위 밖. **점수 null** |
| `pass/error/not_applicable/needs_review` | `not_applicable` | 취약점 평가 결과로서 점수를 산정하지 않음 |

`status=needs_review`는 정책 판정 불가, `cvss.assessment_status=pending`은 **취약이라고 확인된 결과에 대한 CVSS 채점 대기**이므로 다른 의미다. 별도로 집계한다.

### 채점 상태의 구조적 무결성

- `scored`: `version="3.1"`, `vector`, `base_score`, `rating`, `source`, `rationale`가 필수이며 null/빈 값 금지.
- `pending` 또는 `not_applicable`: `version/vector/base_score/rating`을 **모두 null**로 보관하고 `rationale`에 이유 기록. `source`는 근거가 있으면 기록 가능.
- 공식 v3.1 Base Vector를 표준 순서 `AV/AC/PR/UI/S/C/I/A`로 **정규화하여 직렬화**한다. FIRST 공식 규격은 메트릭 순서 변경을 허용하지만, SecureOps v1.2는 **Base 메트릭 전용의 정규 순서**만 수신하도록 제한한다.
- 공식 점수·등급 구간: 0.0=none / 0.1~3.9=low / 4.0~6.9=medium / 7.0~8.9=high / 9.0~10.0=critical.
- JSON Schema는 필드·범위·일부 등급 조건을 확인한다. **Vector↔공식 산식 점수 일치, 소수점 한 자리 표현, 중복 check_id, 날짜 의미 검사 등은 D 런타임에서 추가 검증**한다.
- `source`는 공식 CVSS/CVE 제공기관 자료 또는 자체 평가 로그를 나타내며, 검증되지 않은 구성을 CVE에 임의 매핑하지 않는다.

## 4. 예시 데이터 (절대 실진단 아님)

```json
{
  "schema_version": "1.2",
  "scan_id": "mock-cvss-20261110-01",
  "target_id": "ubuntu-a-mock",
  "os": "ubuntu-24.04",
  "scanned_at": "2026-11-10T12:00:00+09:00",
  "results": [
    {
      "check_id": "SSH-01",
      "status": "vulnerable",
      "evidence": "MOCK: root SSH 정책 위반",
      "recommendation": "관리자 검토 후 정책 조치",
      "cvss": {
        "assessment_status": "pending",
        "version": null,
        "vector": null,
        "base_score": null,
        "rating": null,
        "source": null,
        "rationale": "특정 취약 시나리오와 메트릭 근거 미확정"
      }
    }
  ]
}
```

별도 [MOCK fixture](../../tests/fixtures/sample-result-v1.2-MOCK.json)에는 형식 검증용 `scored` 사례도 포함한다. 해당 사례는 **FIRST 공식 문서의 수학 예제를 재현할 뿐**, SecureOps 실서버에서 해당 취약점이나 CVE가 탐지되었다는 의미가 아니다.

## 5. D 집계 규칙

- 기존 **양호 이행률**은 `pass / (pass + vulnerable) * 100`. 분모 0이면 `N/A`. `error/not_applicable/needs_review`는 별도 기록하며 계산 제외.
- **CVSS 심각도별 취약 건수**는 `status=vulnerable` **AND** `cvss.assessment_status=scored`인 항목만 `cvss.rating`별 집계.
- `pending` 및 CVSS `not_applicable` 건수도 별도로 표시. **점수 미산정 항목을 0.0점으로 표시하지 않음**.
- 취약점 수·양호 이행률·CVSS 평균·점수 총합은 서로 다른 지표다. 점수 평균 또는 합계를 임의의 전체 서버 위험도라고 표시하지 않는다.
- E 모듈은 순위 참고자료로만 CVSS를 사용하고, `status=vulnerable`이어도 관리자 승인·백업·허용 목록·재검증 없이는 조치하지 않는다.

## 6. 버전 이전 및 호환

1. B/C와 D는 전환 기간 동안 v1.1 경로를 유지한다.
2. v1.1 `severity`는 사전 정의한 내부 우선순위이며 CVSS 점수·등급으로 변환 불가.
3. 명시적 v1.1→v1.2 어댑터가 필요하다면, `status=vulnerable` 결과는 `cvss.assessment_status="pending"`으로, 그 외는 `not_applicable`으로 옮기되 모든 점수·Vector를 null로 보관하고 이전 출처/상태를 `rationale`에 명시한다.
4. v1.1 원본은 덮어쓰지 않는다. 과거 저장 보고서는 기존 버전 그대로 조회 가능해야 한다.
5. D의 현재 `core/main.py` 등은 v1.1 전용이며 이 문서로 구현 완료를 주장할 수 없다.

## 7. 수용 테스트 (검토 기준)

- [ ] 유효한 `scored`·`pending`·`not_applicable` 3종 형태를 스키마로 검사
- [ ] `scored`의 필수 메트릭 8종, 유형, 버전, null/필수 속성 검증
- [ ] FIRST v3.1 공식 계산기와 비교하여 Vector→점수 일치
- [ ] 점수 0.0과 평가 불가 null 구분; 점수↔등급 검증
- [ ] 비정상/중복 Vector 메트릭, 잘못된 점수, 버전 충돌 거부
- [ ] 동일 스캔 중복 check_id 거부, time zone 검증
- [ ] `pass` 또는 `error` 등에 임의 점수를 부여한 경우 거부
- [ ] B/C의 기존 5종 status 및 FILE-01 details 보존
- [ ] v1.1 기존 MOCK·테스트 및 PR #8/#10/#16의 기존 기능 회귀
- [ ] v1.2 → D 집계 → E 전후 비교의 MOCK 테스트
- [ ] 실제 VM 네트워크 연동은 별도 증거 확보 후 완료 판정

## 8. 현재 승인 게이트

**현재: 스키마·MOCK·계약서 Draft만 작성.** 기존 v1.1 실행 환경에 자동 적용하거나 main에 병합하지 않는다.

미결정: (1) CVSS v3.1 Base 최종 승인 (2) 대표 사례·검증 근거 (3) E 조치 우선순위 규칙 (4) CVSS 승인자 및 기록 방식 (5) B/C/D 단계별 전환 일정.

공식 출처: https://www.first.org/cvss/v3-1/specification-document
