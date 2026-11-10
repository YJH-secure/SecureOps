# SecureOps — CVSS 기반 위험도 평가 정책 v1.2 (채택 확정)

- 작성일: 2026-11-10
- 책임: 팀장 / 보안 정책 설계 및 통합 검증
- 상태: **팀장 정책 채택 확정(2026-11-10) / 코드 구현 및 실서버 검증 미완료**
- 대상: SecureOps 8개 Linux 설정 진단 항목 및 향후 웹 취약점 분석 결과
- 변경 방식: 기존 [취약점 점검 기준표 v1.1](vulnerability-checklist-v1.1.md) 및 [JSON 계약 v1.1](../architecture/json-result-contract-v1.1.md)은 보존하고, 별도의 개정 계약 v1.2를 만든 후 전환한다.

## 1. 도입 목적 및 범위

기존의 check_id별 고정 High/Medium 초기 우선순위만으로 심각도를 설명하는 한계를 보완하고, **실제로 CVSS 평가가 가능한 취약 사례**에 대해 근거가 추적되는 수치·Vector·등급을 제공한다.

- 채택 표준: **CVSS v3.1 Base Score** (2026-11-10 팀장 확정). CVSS v4.0도 존재하므로 모든 결과에 버전 표시가 필요하다.
- CVSS는 FIRST가 관리하는 취약점의 **기술적 심각도** 평가 체계다. 자체 운영 위험도, KISA 점검 적합성, 양호 이행률과 동일하지 않다.
- 서버 자산 중요도, 내부망/DMZ/외부망 위치, 노출·보완통제, 업무 영향은 별도의 **SecureOps 운영 조치 우선순위** 정책으로 관리한다. 이를 CVSS Base Score 자체에 임의로 가산/차감하지 않는다.
- 공식 근거: https://www.first.org/cvss/v3-1/specification-document 및 https://www.first.org/cvss/v3.1/user-guide
- CVSS는 FIRST의 표준이며 이 프로젝트가 개발한 점수 규격이 아님을 문서와 화면에 명시한다.

## 2. 용어·판정 분리 (반드시 유지)

| 데이터 | 의미 | 범위·제약 |
| --- | --- | --- |
| `status` | 호스트 보안 설정 진단 상태 | `pass/vulnerable/error/not_applicable/needs_review` 5종 유지 |
| `cvss.assessment_status` | CVSS 평가 가능·완료 여부 | `scored/pending/not_applicable`; **진단 status와 별개** |
| `cvss.version` | 채택 CVSS 버전 | 점수가 있을 때 `3.1` |
| `cvss.vector` | 점수 재현을 위한 공식 Vector | 필수 Base 메트릭 8종 모두 포함 |
| `cvss.base_score` | 공식 산식으로 계산한 Base 점수 | 0.0~10.0, 소수점 1자리 |
| `cvss.rating` | Base Score에서 유도한 정성 등급 | None/Low/Medium/High/Critical |
| `cvss.source` | 점수·근거 출처 | 공식 공지/CVE 문서/분석자 평가 및 검증 근거 |
| `remediation_priority` | SecureOps 별도 운영 조치 순서 | CVSS Base와 구별; 별도 정책 승인 전 미산정 |

**오판 방지**: `vulnerable`이라고 해서 CVSS 점수가 자동 생성되는 것은 아니다. `error`, `needs_review`를 임의의 점수나 `pass`로 바꾸지 않는다. `status=not_applicable`와 `cvss.assessment_status=not_applicable`도 서로 다른 의미다.

## 3. CVSS v3.1 공식 Base 평가 규칙

기본 메트릭 8종을 **구체적 취약 상황의 공격 조건과 예상 영향**에 근거해 평가한다.

| 분류 | 메트릭 | 값 |
| --- | --- | --- |
| 악용 가능성 | Attack Vector (AV) | N / A / L / P |
| 악용 가능성 | Attack Complexity (AC) | L / H |
| 악용 가능성 | Privileges Required (PR) | N / L / H |
| 악용 가능성 | User Interaction (UI) | N / R |
| 영향 범위 | Scope (S) | U / C |
| 영향 | Confidentiality (C) | N / L / H |
| 영향 | Integrity (I) | N / L / H |
| 영향 | Availability (A) | N / L / H |

- Vector 형식: `CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...`
- 수치 계산·올림(roundup)은 FIRST CVSS v3.1 공식 명세의 공식을 따른다. **임의 가중치 평균이나 High→8점 등의 매핑을 금지한다.**
- 계산된 점수와 Vector는 함께 저장·표시하고, Vector를 재계산했을 때 점수가 일치하는지 검증한다.
- 알려진 CVE의 기존 CVSS를 참조할 경우 출처·버전·적용 제품/버전·호스트 해당 여부를 확인한다. CVE가 없는 설정 위반은 자동으로 CVE와 연결하지 않는다.
- 자체 평가 시 공격 시나리오, 접근 조건, 영향 및 메트릭별 판단 사유를 기록하고 팀장·담당자의 검토를 받는다.

### 점수별 심각도

| 공식 v3.1 점수 | 등급 |
| --- | --- |
| 0.0 | None |
| 0.1~3.9 | Low |
| 4.0~6.9 | Medium |
| 7.0~8.9 | High |
| 9.0~10.0 | Critical |

## 4. 현재 SecureOps 8개 점검 항목 전환 원칙

| 항목 | 기존 v1.1 임시 우선순위 | CVSS 전환 초안 |
| --- | --- | --- |
| SSH-01 root 직접 원격 로그인 | High | 특정 취약 시나리오와 접근·영향 근거가 입증되면 평가; 설정 위반만으로 점수 지정 금지 |
| SSH-02 SSH 인증 정책 | Medium | 실제 구성과 영향 경로 확인 후 평가 가능 여부 결정 |
| ACC-01 비밀번호 정책 | High | 단순 기준 미충족은 정책 위반으로 별도 관리; 실제 취약 시나리오 입증 시 검토 |
| ACC-02 계정 잠금 정책 | Medium | 동일 |
| FILE-01 중요 파일 권한·ACL | High | 파일별 접근 조건·영향이 증거로 입증될 때 사례별 검토 |
| SVC-01 불필요한 서비스 | Medium | 활성 서비스 존재 자체가 CVE 아님; 취약한 제품/버전 또는 구체적 시나리오 근거 확인 |
| FW-01 호스트 방화벽 | High | 규칙 미준수는 정책 판정으로 관리; 실제 취약 시나리오·영향 근거 분리 |
| LOG-01 보안 로그 | Medium | 기록/보관 위반 자체에 임의 CVSS 점수를 부여하지 않음 |

**중요**: 위 표는 CVSS 점수를 8개 항목에 확정 부여한 표가 아니다. 기존 High/Medium은 **v1.1 레거시 정책 우선순위**이며 `cvss.rating`으로 복사하지 않는다. 대표 사례 1건을 선정하여 평가 가능성·근거·공식 계산 과정을 먼저 검증한다.

### 평가 상태 전환

- `scored`: 적용 가능성 및 모든 필수 메트릭이 검토되고, 유효 Vector와 공식 Base Score 계산값이 일치하며, 근거·승인자가 기록됨.
- `pending`: 구체적 취약 사례이나 CVSS 적합성·메트릭·영향 판단이 완료되지 않음. 점수·등급은 `null`.
- `not_applicable`: 취약점의 기술적 심각도 평가로 보기 어렵거나 평가 대상이 아닌 정책/준수 항목. 점수·등급은 `null`; 사유 필수.
- 이 분류는 **CVSS 평가 상태**이고, 진단 status의 `needs_review`를 대체하지 않는다.

## 5. JSON v1.2 적용 규칙 (코드 적용 전)

현재 JSON v1.1은 엄격한 `additionalProperties=false` 검증을 사용하므로, 다음 객체를 기존 결과에 무단 삽입하지 않는다. 별도 v1.2 계약·Schema·MOCK·D 검증기를 함께 개정하고 **동일 버전끼리만 통합 검증**한다.

```json
{
  "schema_version": "1.2",
  "scan_id": "mock-scan-001",
  "target_id": "ubuntu-a-mock",
  "os": "ubuntu-24.04",
  "scanned_at": "2026-11-10T12:00:00+09:00",
  "results": [
    {
      "check_id": "SSH-01",
      "status": "vulnerable",
      "evidence": "MOCK: 설정 정책 위반 확인. 실제 CVSS 평가 전.",
      "recommendation": "승인된 보안 정책에 따라 검토",
      "cvss": {
        "assessment_status": "pending",
        "version": null,
        "vector": null,
        "base_score": null,
        "rating": null,
        "source": null,
        "rationale": "구체적인 공격 전제와 영향 검증 대기"
      }
    }
  ]
}
```

위 예시는 **확정된 v1.2 계약 형식의 MOCK**이며 현재 D/B/C/E 코드가 아직 이 규격을 수용한다는 뜻은 아니다. v1.2에서 기존 `severity`는 제거하고 CVSS 객체로 대체한다. 이전 v1.1 등급을 CVSS 점수나 등급으로 자동 매핑하지 않는다. 계약 확정 전에는 B/C 모듈의 v1.1 출력을 깨뜨리지 않는다.

필수 검증 후보:
1. Vector 접두어·필수 8종·허용 값·중복 키 검사.
2. 공식 계산 결과 ↔ `base_score` 일치, 점수 ↔ `rating` 구간 일치.
3. `scored`일 때 Vector·점수·근거 필수; 그 외 점수/등급 `null` 및 사유 필수.
4. 잘못된 CVSS 값을 조용히 고치거나 자동으로 고위험 등급을 만드는 동작 거부.
5. 기존 5종 `status`, `scan_id`, `evidence`, `recommendation`, `details`, 전후 비교·백업·승인 흐름 유지.
6. v1.1 자료는 **원본 버전 유지**; v1.2 변환이 필요한 경우 명시적 어댑터에서만 처리하고 과거 결과에 가짜 CVSS 값을 채우지 않음.
7. `CVSS 0.0`과 `평가 불가(null)`를 구분.

## 6. 담당별 작업 순서 및 병합 게이트

1. **팀장(정책)**: 이 문서 및 JSON v1.2 채택 확정(2026-11-10), 대표 CVSS 사례의 실제 적용 가능성·근거 검증.
2. **A 인프라**: 정확한 자산 정보·네트워크 위치·노출 증거 제공 (CVSS Base Score 임의 변경 금지).
3. **B/C 진단**: 기존 읽기 전용 진단·5상태·evidence 유지; 대표 사례의 메트릭 판단 근거를 별도로 제공.
4. **D 집계**: v1.2 스키마·Vector 검증·공식 점수 산정·등급 파생·이력/보고서 집계 테스트. 기존 v1.1 경로 회귀 보장.
5. **E 조치**: CVSS 점수를 **조치 후보 정렬의 참고 정보**로 사용; 관리자 승인/허용목록/백업/재검증/실패 복구는 그대로 유지.
6. **팀장(검증)**: 공식 계산기와 대조, 가상·오류·미평가 사례 테스트, B→D→E 실제 연동 증거 확인 후 main 병합 판단.

**변경 관리**: PR #8(D), #10(B), #16(E) 및 다른 개발 브랜치는 현재 내용 보존. CVSS v3.1 Base + JSON v1.2 설계는 팀장 기준선으로 채택되었으므로 담당자는 병렬로 **별도 feature 브랜치에서 개발을 착수**할 수 있다. 현재 v1.1 main에는 미적용이며 기능 단위 테스트, v1.1 회귀, 통합 검증 후에만 병합한다.

## 7. 채택 확정 사항과 구현 후속 과제

- **확정:** CVSS v3.1 Base 채택(2026-11-10)
- 8개 중 어떤 구체적 취약 사례를 대표 CVSS 시연에 사용할지 (임의 등급/점수 사용 금지)
- 자체 평가 승인 담당과 CVE 공급처/증거 보관 방식
- **확정:** v1.2 `severity` 제거, `cvss` 객체 도입, 미평가 시 점수와 등급 `null`; v1.1 원본 유지 및 명시적 변환
- CVSS와 별도인 SecureOps 운영 조치 우선순위 산정 규칙

## 8. 참고 출처

1. FIRST, *CVSS v3.1 Specification Document*: https://www.first.org/cvss/v3-1/specification-document
2. FIRST, *CVSS v3.1 User Guide*: https://www.first.org/cvss/v3.1/user-guide
3. SecureOps, [기존 진단 정책 v1.1](vulnerability-checklist-v1.1.md)
4. SecureOps, [기존 결과 계약 v1.1](../architecture/json-result-contract-v1.1.md)

---
문서 상태: **정책 및 계약 채택 확정(2026-11-10) / 개별 취약점 점수는 근거 검증 전 미배정 / 프로그램·실서버 적용 미완료**.
