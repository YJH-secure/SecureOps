# SecureOps 점검 정책 v1.1 — 팀원 AI 검토 안내

## 문서 위치

- 진단 정책: `docs/security-policy/vulnerability-checklist-v1.1.md`
- JSON 계약: `docs/architecture/json-result-contract-v1.1.md`
- JSON Schema: `docs/architecture/json-result-schema-v1.1.schema.json`
- 기존 AI 규격 가이드: `docs/architecture/AI_JSON_REVIEW_GUIDE_v1.1.md`
- 인프라 README: `infrastructure/README.md` (PR #9 검토 중)

점검 기준표와 본 안내문은 PR #12가 main에 병합되기 전까지 `docs/security-policy-v1-1-alignment` 브랜치에 있다. 병합 이후에는 `main`을 참고한다.

## AI 공통 요청문

> SecureOps 프로젝트에서 내가 담당하는 모듈을 점검해 줘. 내 담당자는 [이름], 역할은 [A/B/C/D/E], 코드는 [경로]야.
> GitHub의 취약점 기준표 v1.1과 공통 JSON 결과 계약 v1.1을 실제로 읽은 뒤 비교해 줘. 접근할 수 없으면 확인하지 못했다고 설명해 줘.
> 1. 점검 ID, 양호·취약·오류·미적용·검토 필요 판정이 기준표에 맞는지 확인해 줘.
> 2. 각 결과의 필수 필드와 상태값이 JSON v1.1 계약에 맞는지 확인해 줘.
> 3. 미승인 정책 후보를 확정된 기준으로 사용하지 않았는지 확인해 줘.
> 4. 실제 테스트 증거와 미검증 항목을 구분해 줘.
> 5. 민감한 계정정보가 보고서나 커밋에 노출되지 않았는지 확인해 줘.
> 결과는 일치 항목, 불일치 위치, 수정 제안, 테스트 결과, 팀장 결정이 필요한 사항 순으로 정리해 줘.
> 내 승인 없이 파일을 수정하거나 push 또는 merge하지 마.

## 담당자별 추가 확인

| 담당자 | 추가 확인 사항 |
| --- | --- |
| A 김민우 — 인프라 | 논리 서버 식별자, 실제 Ubuntu Server/Desktop·Rocky Desktop 구성, 접근 관리 문서의 정합성 및 검증 증거 |
| B 최종욱 — 계정·인증 진단 | SSH-01·SSH-02·ACC-01·ACC-02 판정, 설정별 조건, 미확정 정책의 보류 처리 |
| C 김서후 — 시스템·서비스 진단 | FILE-01·SVC-01·FW-01·LOG-01 판정, 파일 소유권·권한·ACL 근거, OS별 후보값과 확정값 구분 |
| D 조효민 — 결과 집계 | `target_id`, `os`, `scanned_at`, `results` 등 JSON v1.1 필수값, 5종 상태 집계 및 재검증 회차 구분 |
| E 박태준 — 승인·조치·재검증 | 미승인 변경 방지, 변경 전후 증거·복구 검증, 새 `scan_id`로 재진단, 정책 후보 자동 적용 금지 |

## 문서 우선순위와 상태

결과 JSON 필드 및 자료형은 계약 v1.1을 따른다. 점검 판정은 기준표 v1.1을 따르되 미확정으로 표시된 항목은 검토 대상으로 남긴다. 인프라 문서는 운영 환경 설명이며, 진단 기준 자체를 변경하지 않는다. 문서 사이에 충돌이 발생하면 임의로 변경하지 말고 팀장에게 보고한다.
