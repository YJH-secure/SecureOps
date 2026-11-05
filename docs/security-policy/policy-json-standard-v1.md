# SecureOps 보안 진단 정책 JSON 공통 규격 v1.0 (팀 검토안)

- 작성 담당: 양지혁 (아키텍처·보안 정책)
- 작성일: 2026-11-05
- 관련 Issue: #2 (ARCH-01)
- 작업 브랜치: `feature/architecture-yjh`
- 상태: **공통 저장 구조는 팀장 제안, 세부 점검 기준·코드 연동은 담당자 검토 후 확정**
- 관련 문서: [공통 진단 결과 JSON 규격](../architecture/json-result-contract-v1.md) · [시스템 아키텍처](../architecture/system-architecture.md)

## 1. 목적과 개념

계정·SSH 진단(최종욱)과 시스템 진단(김서후)이 서로 다른 보안 정책을 읽더라도 **저장 폴더 구조, 필드 이름, 위험도 표현, 변경 절차는 동일하게** 유지한다.

- **정책 JSON**: 무엇을 확인하고 어떤 기준이면 양호인지 정한 **채점 기준표**.
- **Python 진단 코드**: 실제 Linux 설정을 읽고 정책과 비교하는 **채점 프로그램**.
- **결과 JSON**: 진단 후 `pass`, `vulnerable`, `error`, `not_applicable`, `needs_review` 중 하나를 기록하는 **성적표**.

정책 JSON은 결과 JSON이 **아니다**. 정책 파일에 `status`, `evidence`, 실제 서버의 계정·비밀번호·IP를 미리 기록하지 않는다.

## 2. B안 적용: 담당별 폴더, 공통 작성 규칙

```text
SecureOps/
├── checks/
│   ├── account/                         # 최종욱
│   │   ├── ssh_check.py                 # 제안 경로 (구현 방식 조정 가능)
│   │   ├── account_check.py             # 제안 경로
│   │   └── policies/
│   │       ├── ssh_policy.json
│   │       └── account_policy.json
│   └── system/                          # 김서후
│       ├── file_check.py                # 제안 경로
│       ├── service_check.py             # 제안 경로
│       ├── firewall_check.py            # 제안 경로
│       ├── log_check.py                 # 제안 경로
│       ├── common.py                    # 시스템 점검 내부 재사용 기능
│       └── policies/
│           ├── file_policy.json
│           ├── service_policy.json
│           ├── firewall_policy.json
│           └── log_policy.json
├── core/                                 # 조효민: 결과 JSON 읽기·검증·집계
└── docs/security-policy/                 # 양지혁: 공통 작성·검토 기준
```

- 종욱·서후는 **자신의 담당 폴더 안** 정책만 수정한다. 중앙의 정책 폴더 하나를 여러 명이 동시에 편집하는 구조(C안)는 지금 단계에서 도입하지 않는다.
- 이 문서의 경로는 **작성 목표 구조**이며, 해당 파일들이 이미 구현됐다는 뜻은 아니다.
- 계정·시스템 모듈의 `common.py`는 정책 읽기·형식 검증 같은 내부 편의 기능에 사용할 수 있다. **원격 SSH 연결 로직을 각자 중복 작성하도록 이 문서에서 확정하지 않는다**. 전체 공통 SSH 수집 계층은 별도 아키텍처 결정이 필요하다.

## 3. 정책 JSON 공통 필드

하나의 정책 파일에는 `policies` 배열을 두고, 그 안에 동일한 형태의 점검 정책을 기록하는 방식을 **제안**한다.

| 위치 | 필드 | 형식 | 필수 | 설명 |
| --- | --- | --- | --- | --- |
| 최상위 | `policy_version` | string | 예 | 정책 파일 형식 버전, 현재 `"1.0"` |
| 최상위 | `policies` | array | 예 | 점검 정책 목록 |
| 각 정책 | `check_id` | string | 예 | 팀 전체에서 고유한 점검 ID (예: `SSH-01`, `FILE-01`) |
| 각 정책 | `description` | string | 예 | 무엇을 점검하는지 설명 |
| 각 정책 | `severity` | string | 예 | `critical`, `high`, `medium`, `low` (소문자) |
| 각 정책 | `criteria` | object | 예 | 시스템에서 실제 읽을 값과 양호 판정 조건 |
| 각 정책 | `applies_to` | array | 권장 | 적용할 OS 종류 (예: `["ubuntu", "rocky"]`) |
| 각 정책 | `reference` | string | 선택 | 적용한 취약점 기준표 항목 및 출처 |

**필수 공통 필드는 `check_id`, `description`, `severity`, `criteria`이다.** `criteria` 내부 상세 필드는 서로 다른 점검 유형에 맞춰 다르게 둬도 된다. 다만 `criteria.type`은 점검 프로그램이 지원하는 유형만 허용한다.

**정책 버전(`policy_version`)과 결과 버전(`schema_version`)은 서로 다른 개념**이다. 이 문서는 두 버전 모두 1.0 예시를 사용하지만, 각자 독립적으로 관리한다.

## 4. 예시 1 — 최종욱: SSH 정책 파일

저장 위치 제안: `checks/account/policies/ssh_policy.json`

```json
{
  "policy_version": "1.0",
  "policies": [
    {
      "check_id": "SSH-01",
      "description": "SSH root 계정 직접 로그인 허용 여부",
      "severity": "high",
      "applies_to": ["ubuntu", "rocky"],
      "criteria": {
        "type": "sshd_effective_setting",
        "setting": "permitrootlogin",
        "operator": "equals",
        "expected": "no"
      }
    }
  ]
}
```

- 실제 판정 시 단순히 파일 한 줄을 찾는 대신 `Include`, `Match`, 기본값 등을 고려해 **유효한 SSH 설정**을 확인해야 한다.
- `expected: "no"`는 이번 예시 정책의 제안값이다. 팀 취약점 기준표, 접근 운영정책에 맞춰 실제 기준을 확정한다.
- **예시 데이터**이며 지금 이 파일이나 SSH 검사 코드가 구현되어 있다는 의미는 아니다.

## 5. 예시 2 — 김서후: 파일 권한 정책 파일

저장 위치 제안: `checks/system/policies/file_policy.json`

```json
{
  "policy_version": "1.0",
  "policies": [
    {
      "check_id": "FILE-01",
      "description": "/etc/passwd 파일 소유자와 쓰기 권한 점검",
      "severity": "medium",
      "applies_to": ["ubuntu", "rocky"],
      "criteria": {
        "type": "file_metadata",
        "path": "/etc/passwd",
        "expected_owner": "root",
        "forbidden_permission_bits": "0022"
      }
    }
  ]
}
```

- `forbidden_permission_bits: "0022"`는 **그룹 또는 기타 사용자에게 쓰기 권한이 있으면 부적합**하다는 예시 조건이다. 실제 Python은 숫자 권한 비트 검사로 판정하고, 문자열 `"0022"`를 그대로 숫자 비교하지 않는다.
- 대상 파일 미존재, 심볼릭 링크, 소유자·권한 조회 실패 시 처리 방식은 실제 기준표·환경에 따라 정한다. 조회 실패를 `pass`로 처리하지 않는다.
- `FILE-01`과 심각도는 **예시**이며 최종 표준 점검 ID·등급은 팀 기준표와 대조해야 한다.

## 6. 공통 검증 및 판정 규칙

1. **파일 형식:** JSON 파싱 가능, 최상위 객체, `policy_version` 문자열, `policies` 배열 확인.
2. **필수 필드:** 각 정책의 `check_id`, `description`, `severity`, `criteria` 존재 및 자료형 확인; 빈 문자열/빈 조건도 거부.
3. **허용값:** `severity`는 `critical/high/medium/low` 중 하나. `criteria.type`과 `operator`는 점검 모듈이 지원하는 목록에 한정.
4. **점검 ID:** 전체 프로젝트에서 중복 금지. `SSH-01`, `ACC-01`, `FILE-01`, `SVC-01`, `FW-01`, `LOG-01` 등 담당 영역별 접두어는 예시이며 실제 번호표는 따로 확정.
5. **OS 적용:** `applies_to`의 대상 OS가 아니라면 근거를 기록한 `not_applicable` 처리 검토. 조회·실행 실패는 `error`, 업무적 판단이 필요한 상황은 `needs_review`로 구분.
6. **결과 계약:** 진단 모듈은 정책과 실제 설정을 비교해 결과 객체 `{"check_id","status","severity","evidence"}` 필수 4필드를 반환. 상위 `schema_version/target_id/scanned_at/results`는 [결과 계약](../architecture/json-result-contract-v1.md)을 따른다.
7. **오류 시 안전 처리:** 손상되거나 지원하지 않는 정책은 검사 결과를 임의로 양호 처리하지 않는다. 정책 로딩·검증 오류를 기록하고 해당 점검이 실행되지 않았음을 드러낸다.
8. **민감정보:** 정책과 `evidence`에 비밀번호, 토큰, 개인키, 불필요한 개인정보를 저장하지 않는다.
9. **실행 안전:** 정책 JSON에 임의 셸 명령문이나 원격 조치 명령을 직접 담아 실행하지 않는다. 진단은 기본 읽기 전용이며, 조치는 관리자 승인 및 허용목록 검증을 통과한 별도 모듈에서 수행한다.

## 7. 개발과 코드 리뷰의 최소 검증

- **종욱 / SSH-01:** 정책 JSON 파싱 → 검사 대상 유효 SSH 값 수집(초기에는 mock 가능) → 조건 비교 → 규격에 맞는 결과 객체 1개 반환.
- **서후 / FILE-01:** 정책 JSON 파싱 → 파일 소유자·권한 수집(초기에는 mock 가능) → 조건 비교 → 결과 객체 1개 반환.
- **상호 검토:** 상대의 정책 파일에 공통 필드 누락, 중복 `check_id`, 위험도 대소문자 혼용이 없는지 확인.
- **음성 테스트:** 잘못된 JSON, 누락 필드, 미지원 `criteria.type`, 알 수 없는 `severity`, 점검 자료 수집 실패를 넣어 **조용한 양호 처리나 중단 없는 무시**가 없는지 확인.
- **통합 테스트:** 두 모듈이 만든 결과가 효민의 `core/`에서 같은 형식으로 읽히는지 검증. 통합 테스트는 실제 서버 연동 검증과 구분하여 기록.

## 8. 정책 변경 및 권한 관리

1. 담당자가 본인 `feature/` 브랜치의 `checks/{account|system}/policies/`를 수정한다.
2. 변경한 보안 기준과 이유를 PR 본문에 기록하고, 양지혁이 공통 형식 및 보안 기준표와 일치 여부를 검토한다.
3. 필요하면 종욱·서후가 서로 검토한다. 승인된 코드·정책만 `main`으로 병합한다.
4. 운영 실행 환경에서는 승인된 버전의 정책을 읽고, 파일 수정 권한은 최소화한다. **PR 절차 자체만으로 런타임 정책 무결성을 보장하지는 않는다.**
5. 정책 기준 변경 시 샘플 테스트와 결과 판정 변경 여부를 함께 검증한다.

## 9. 결정되었거나 아직 남은 내용

### 합의·지시한 방향
- [x] 정책 JSON을 Python 코드와 분리하는 **B안 채택**
- [x] 계정·시스템 진단 각각 자신의 `policies/` 폴더 사용
- [x] 공통 필드 표준화 및 팀 공통 결과 JSON 사용 방향 정리

### 담당자 검토 후 확정
- [ ] 종욱·서후가 `policy_version + policies[]` 파일 구조에 동의하는지 확인
- [ ] 실제 기준표에 따라 점검 ID·심각도·SSH/파일 권한 판정값 확정
- [ ] `criteria.type`별 허용 연산자·필수 필드 확정
- [ ] 공통 정책 로더 범위 및 **중앙 SSH 원격 수집** 담당·호출 인터페이스 확정
- [ ] Ubuntu·Rocky의 OS별 차이와 서비스 부재에 대한 처리 검증
- [ ] 첫 SSH-01/FILE-01 mock 테스트 및 실제 서버 테스트 기록

---

이 문서는 **정책 데이터 형식의 팀 검토용 제안**이다. 예시 JSON이나 폴더 구조가 이미 코드로 구현되었거나 테스트되었다는 뜻은 아니다.
