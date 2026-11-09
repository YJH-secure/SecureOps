# SecureOps 공통 JSON 결과 계약 v1.1 — 개발 기준선

- 작성일: 2026-11-06
- 작성 책임: 양지혁 (보안 아키텍처·통합 계약)
- 상태: 팀장 개발 기준선 확정(2026-11-06) / B·C·D·E 구현·연동 검증 진행 예정
- 적용 범위: B/C 개별 진단 결과 → D 집계·저장 → E 조치·재진단 비교

## 1. 결정 사항

1. 서버 1대의 스캔 1회 결과를 최상위 JSON 객체 하나로 표현한다.
2. B/C 진단 모듈은 `results[]`의 항목 객체를 반환한다. D는 항목을 취합하여 최상위 메타데이터를 붙인다.
3. `schema_version`은 `"1.1"`로 고정하며 취약점 기준표 v1.1 및 정책 파일 `policy_version`과 별도로 관리한다.
4. 서버 ID는 `target_id`로 통일(`server_id` 사용 금지). OS 식별자는 `os`로 통일(`os_type` 사용 금지).
5. 스캔 전체 완료 시각은 `scanned_at`, 개별 항목의 시각은 선택적 `checked_at`이다. 서로 대체하지 않는다.
6. 위험도는 소문자 `critical/high/medium/low`로 통일한다. `critical`은 확장 가능한 값이나 현재 8개 기준표 항목에 임의 배정하지 않는다.
7. `evidence`는 사람이 읽을 수 있는 필수 문자열. 구조화된 세부 근거는 선택적 `details` 객체에 보관한다.
8. `recommendation`은 필수 문자열이다. 기존 `guide`는 이 필드로 이전한다. 조치 명령 실행 입력으로 직접 사용해서는 안 된다.

## 2. 최상위 필드 (스캔 보고서)

| 필드 | 타입 | 필수 | 의미 |
|---|---|---|---|
| schema_version | string | Y | 항상 `1.1` |
| scan_id | string | Y | 스캔 실행별 고유 ID. 재검증 시 반드시 새 ID |
| target_id | string | Y | 서버 인벤토리의 고유 식별자 |
| os | string | Y | 예: `ubuntu-24.04`, `rocky-9.8` |
| scanned_at | RFC3339/ISO8601 string | Y | 타임존이 있는 스캔 결과 완료 시각 |
| results | array | Y | 1개 이상 점검 결과 객체 |
| ip_address | string | N | 내부 운영용 IP, 공개 샘플에는 실제 IP를 넣지 않음 |

## 3. results[]의 필드 (개별 검사)

| 필드 | 타입 | 필수 | 의미 |
|---|---|---|---|
| check_id | string | Y | 고유 점검 ID: SSH-01 등 |
| status | string(enum) | Y | 5개 상태 중 하나 |
| severity | string(enum) | Y | 기본 중요도; status와 독립 |
| evidence | string | Y | 수집·판정 근거 요약 (비밀값 제외) |
| recommendation | string | Y | 권고사항 또는 후속 확인 안내 |
| category | string | N | D의 분류 집계용 |
| title | string | N | 화면 표시용 점검명 |
| checked_at | datetime string | N | 개별 항목 점검 시각, 타임존 포함 |
| details | object | N | 파일별·ACL별 세부 evidence, 식별정보 제거 |

`details`가 있더라도 `evidence` 문자열을 반드시 남긴다. FILE-01처럼 하나의 check_id 아래 passwd와 shadow를 검사한 경우 세부 기록은 `details` 안에 보관하고 최상위 `check_id` 중복을 만들지 않는다.

## 4. 상태값과 집계 규칙

- `pass`: 승인 기준 충족
- `vulnerable`: 기준 위반의 실제 증거 확인
- `error`: 명령·권한·연결·파싱 실패. 취약으로 단정하지 않음
- `not_applicable`: 해당 검사 대상이 아님. evidence에 이유 필요
- `needs_review`: 실제 값은 얻었으나 정책 미확정·업무 예외 등으로 사람의 검토 필요

D의 양호 이행률 = pass / (pass + vulnerable) × 100; 분모 0이면 N/A. error, not_applicable, needs_review는 별도 건수로 기록하고 이행률 계산에서 제외한다. 심각도별 취약 건수는 `status=vulnerable`에 한해 집계한다.

## 5. 샘플 JSON (MOCK)

```json
{
  "schema_version": "1.1",
  "scan_id": "scan-20261106-001",
  "target_id": "ubuntu-a-mock",
  "os": "ubuntu-24.04",
  "scanned_at": "2026-11-06T10:00:00+09:00",
  "results": [
    {
      "check_id": "SSH-01",
      "status": "vulnerable",
      "severity": "high",
      "evidence": "예시: 유효 SSH 설정에서 root 직접 로그인이 허용됨 (MOCK)",
      "recommendation": "관리자 승인 후 root 원격 로그인 제한 정책 검토",
      "category": "계정·인증",
      "title": "SSH root 원격 로그인 제한",
      "checked_at": "2026-11-06T09:59:55+09:00"
    },
    {
      "check_id": "FILE-01",
      "status": "needs_review",
      "severity": "high",
      "evidence": "예시: /etc/shadow 허용 권한 기준의 최종 승인이 필요함 (MOCK)",
      "recommendation": "OS별 승인 기준 확정 후 재판정",
      "category": "시스템·파일",
      "title": "중요 파일 소유자·권한 점검",
      "details": {
        "files": [
          {
            "path": "/etc/shadow",
            "judgement": "needs_review"
          }
        ]
      }
    }
  ]
}
```

이 샘플은 실제 스캔 결과가 아니다. 점검 ID와 기본 중요도는 팀이 승인한 점검 정책표를 따른다.

## 6. 기존 필드 이전 규칙

| 기존/문서 상충 필드 | v1.1 기준 | 처리 |
|---|---|---|
| server_id | target_id | 입력 정규화 후 출력에서 사용 금지 |
| os_type | os | 배포판+버전 형태로 정규화 |
| checked_at (최상위) | scanned_at | 최상위에서만 이전. 결과 내부 checked_at은 보존 |
| guide | recommendation | 기존 안내 문구 이전 |
| severity: HIGH/CRITICAL/... | lowercase | 입력에서 소문자 정규화 후 결과 출력 |
| 기존 evidence 객체 | evidence + details | 요약 문자열 생성, 전체 세부 정보는 details |

전환 기간에는 D가 레거시 입력을 변환하는 어댑터를 둘 수 있지만, 정규화된 최종 출력은 반드시 v1.1 필드명만 사용한다. 상충되는 양쪽 필드가 동시에 있는데 값이 다르면 임의 선택하지 않고 검증 실패로 기록한다.

## 7. 필수 검증 항목

- 최상위 및 개별 필수 키 누락, 값 타입 오류, 빈 문자열, 빈 results 거부
- 허용되지 않은 status 또는 severity, 대소문자 표기 혼용 거부 (정규화 이전 입력은 명시적 어댑터 처리)
- 동일 scan_id·target_id 보고서 내 중복 check_id 거부
- scanned_at/checked_at은 타임존이 있는 ISO 8601 형식 검증
- 동일 진단을 재실행하면 scan_id 변경 및 이전 결과와 별도 저장
- 비밀번호·개인키·토큰·쿠키 및 불필요한 개인정보가 evidence/details에 포함되지 않도록 검사·마스킹
- 오류/보류를 양호로 자동 치환하지 않음
- 실제 데이터는 접근 제한된 저장소에 보관, 공유 샘플은 MOCK만 사용

## 8. 모듈별 적용 지시

- B 최종욱: 각 검사에서 공통 필드 `check_id/status/severity/evidence/recommendation` 반환. severity 소문자.
- C 김서후: 동일 구조 반환. 상세 파일 권한·ACL 자료는 details에 기록하고 evidence는 짧은 문자열 유지.
- D 조효민: results 배열 집계 유지; 상위 scan_id/target_id/os/scanned_at 생성·검증 및 레거시 guide, os_type 등 이전. 결과 JSON은 v1.1로만 출력.
- E 박태준: target_id+check_id로 전후 검사 항목을 매칭, scan_id로 실행 회차 구분. vulnerable라도 승인·백업·허용목록 검증 전 자동 조치 금지. error/needs_review에는 조치 금지.
- A 김민우: 서버 식별자와 OS 정보를 진단 실행 계층에 제공. IP는 선택 메타데이터.
- 팀장 양지혁: 필드·타입·판정 및 테스트 승인. 기준표 v1.1의 5장 예시를 이 결과 계약과 일치하도록 정정.

## 9. 수용 테스트 / 확정 게이트

1. SSH-01 단일 결과를 B → D로 전달하고 결과 JSON이 스키마 검증을 통과한다.
2. FILE-01 결과(세부 evidence 포함)를 C → D로 전달하고 원래 상세 근거가 유실되지 않는다.
3. pass/vulnerable/error/not_applicable/needs_review 5개 상태를 정확히 구분 집계한다.
4. 기존 D 샘플의 `guide`, `os_type`, 대문자 severity가 정규화되어 v1.1로 출력된다.
5. 누락 필드·중복 check_id·알 수 없는 상태값·잘못된 시각 형식 입력을 거부한다.
6. 재진단은 새 scan_id로 저장하며 전후 차이를 재현한다.
7. B/C/D/E 담당자는 확정된 v1.1 개발 기준에 맞춰 구현하고, 실제 연동 검증 결과로 적용 적합성을 확인한다.

## 10. 변경 관리

- 취약점 점검 기준표 v1.1은 정책 기준이고 이 문서의 결과 스키마 v1.1과 별도 버전으로 운영한다.
- 기준선 확정 후 필수 키 이름/타입/상태값의 비호환 변경은 영향 분석·버전 개정·전 담당자 공지를 필수로 한다.
- 스키마 파일 및 MOCK 샘플을 GitHub `docs/architecture/`와 `tests/fixtures/`에 반영하는 작업은 별도 PR로 진행한다.
- 참조 기준: 기존 GitHub `docs/architecture/json-result-contract-v1.md`, 효민 `core/main.py`, `tests/fixtures/sample_diagnosis.json`, 기준표 v1.1의 JSON 예시 및 FILE-01 변경 기록.