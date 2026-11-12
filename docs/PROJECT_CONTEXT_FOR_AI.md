# SecureOps AI 인수인계 요약 (2026-11-09)

> 새 ChatGPT/다른 AI 대화에 전달할 **길잡이 문서**. 이 글은 모든 채팅의 원문 백업이 아니다. 최신 브랜치·PR·테스트를 반드시 다시 읽을 것.

## 1. 자료를 읽는 순서

1. [진행 현황](project-status.md): 날짜가 있는 업무 상태와 미해결 항목.
2. [JSON 결과 계약 v1.1](architecture/json-result-contract-v1.1.md) 및 [Schema](architecture/json-result-schema-v1.1.schema.json): 최상위·항목 필드와 상태값.
3. [점검 기준표 v1.1](security-policy/vulnerability-checklist-v1.1.md): 8개 점검 항목, 정책 확정/후보 구분.
4. [통합 검증 체크리스트](integration-checklist.md): 실제 테스트 증거와 완료 기준.
5. [ADR 기록](decisions/ADR-001-governance-and-policy-status.md): 정책·아키텍처 결정 근거.
6. `infrastructure/README.md`의 최신 PR/브랜치, `tests/test_ssh_client.py`, `tests/test_json_contract.py`, B/C/D/E 모듈 PR 및 커밋. **파일이 어느 브랜치에 있는지 확인**.

## 2. 프로젝트·일정

- KT Cloud 사이버보안 부트캠프 6인 팀 프로젝트 SecureOps. 팀장: 양지혁.
- 목표: Linux 취약점 점검·평가·관리자 승인 기반 조치·재진단, Ubuntu/Rocky 비교, 웹 보안 분석 3건.
- 중간발표 2026-11-18, 최종발표 2026-12-02, 제출 마감 2026-12-01 18:00.
- 필수 제출물: PDF 결과 보고서, 5~10분/100MB 이하 MP4, README 포함 저장소 링크.
- 팀장 개인 기술 영역: 공통 SSH MOCK/실서버 연동 준비, 독립 Integration Validator, 웹 취약점 3건 분석, 정책 검토 및 최종 통합 검증.

## 3. 절대 혼동하지 않을 것

- JSON **schema_version=1.1**와 취약점 기준표 **v1.1**, 각 정책 **policy_version**은 다른 개념.
- 최상위 결과: `scan_id/target_id/os/scanned_at/results` (+ schema_version), **server_id는 레거시**.
- 개별 결과: `check_id/status/severity/evidence/recommendation`; `details`는 선택. severity 소문자.
- `pass/vulnerable/error/not_applicable/needs_review`는 보안 판정이지 테스트 프레임워크의 PASS/FAIL이 아니다.
- 팀장 SSH MOCK 테스트와 JSON 계약 테스트 통과 기록 ≠ 실제 중앙 서버 원격 통합 검증.
- FILE-01 임시 ACL·링크 13/13 ≠ passwd/shadow 운영 정책 확정.
- SVC-01 59/282/9 수집, error 0 ≠ 승인된 허용 목록으로 최종 양호/취약 판정.
- A의 VMware NAT 구축 보고 ≠ GNS3 목표 아키텍처 구축 완료.
- PR 생성/병합/기준 승인 모두 다른 단계. 실제 GitHub 상태를 확인한다.

## 4. 다음 대화에서의 작업 절차

- 먼저 사용자가 지금 어느 브랜치와 어떤 테스트를 진행 중인지 현재 대화·저장소에서 확인한다.
- 해당 작업 파일/PR을 실제로 읽고, **완료/진행/대기/계획**으로 분리한다.
- 요청된 코드나 문서 변경은 사용자 브랜치 또는 별도 작업 브랜치에서 진행한다. **main 직접 변경·자동 병합 금지**.
- 기술 설명은 초보자도 따라 할 수 있도록 한 단계씩, 명령어와 성공/실패 확인 기준을 제공한다.
- 단계 완료 시 날짜·브랜치·파일·실행 결과·다음 작업을 `project-status.md` 또는 체크리스트에 업데이트한다.
- 출력·화면·보고서에는 실제 수행한 결과만 넣고 민감정보를 제거한다.

## 5. 참조 링크

- 저장소: https://github.com/YJH-secure/SecureOps
- B PR #10: https://github.com/YJH-secure/SecureOps/pull/10
- A PR #9: https://github.com/YJH-secure/SecureOps/pull/9
- D PR #8: https://github.com/YJH-secure/SecureOps/pull/8
- PR #13은 `main → feature/architecture-yjh` 방향으로 병합된 기록; `main`에 팀장 브랜치를 병합한 것이 아니다.

> 이 문서는 편의를 위한 요약. 확정 판단은 최신 승인 정책·실제 브랜치 소스·테스트 결과·해당 PR의 기록을 근거로 한다.
