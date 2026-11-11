# 팀장 요청 1~4 검토 결과

## 1. 오류 수정과 회귀 테스트

기존 4건은 수정 및 재발 방지 테스트가 존재합니다.

| 항목 | 확인 위치 |
|---|---|
| UID 누락으로 승인 ACL 평가 중단 | tests/test_missing_metadata.py: test_missing_uid_in_approved_acl_returns_error |
| 숫자 GID 누락을 ACL 위반으로 오판 | test_missing_gid_not_treated_as_unauthorized_acl_principal |
| 정책 미정이라 GID 누락을 review로 처리 | test_gid_validation_precedes_pending_group_policy |
| 파일 유형 누락을 review로 처리 | test_missing_file_type_is_error |

기존 v6.1은 사용자 제공 Ubuntu·Rocky 로그에서 단위 98개/임시 13개/JSON14개
통과를 확인했습니다. 실제 진단은 needs_review입니다.
이번에 이름 shadow 없음과 실제 조회 실패를 구분하고 tests/test_group_lookup_state.py의
7개 테스트를 추가했습니다. 로컬 Windows Python 3.12에서 총 105개 통과했습니다.
새 v6.2 Ubuntu는 사용자 제공 로그에서 105개/임시 13개/JSON14개 통과 및
실제 needs_review를 확인했습니다(20261106T064122_458579Z).
Rocky도 사용자 제공 로그에서 105개/임시 13개/JSON14개 통과 및
실제 needs_review를 확인했습니다(20261106T070314_907942Z).
따라서 새 v6.2의 양 OS 실행 검증은 확인됐습니다. AI가 VM에서 직접 실행하지 않았습니다.

## 2. evidence 상태

이전 VM 터미널 로그는 확보했고 전체 실행 성공을 확인했습니다.
13개 시나리오는 임시 파일과 MOCK 승인 정책을 이용한 진단 로직 검증입니다.
운영 정책 승인이나 실제 파일 전체 보안 양호의 증거로 사용하지 않습니다.
Rocky 실제 결과 JSON의 붙여넣기 사본과 Ubuntu 실제 결과 화면의 표시값을 확보했습니다.
VM의 원본 검증 파일과 발표용 스크린샷은 VM_EVIDENCE_GUIDE.md에 따라 별도 보관합니다.
기존 로그의 98개를 새 버전 105개 결과로 바꿔 쓰지 않습니다.

## 3. 정책 조사

POLICY_REVIEW_DRAFT.md에 양 OS 실제 UID/GID/mode, 팀 후보, 공식 자료 및 승인 필요 조건을
분리했습니다. passwd는 양쪽 모두 0/0/0644, shadow는 Ubuntu 0/42/0640, Rocky 0/0/0000입니다.
KISA 적용 판본·첨부 본문 대조와 최종 정책 승인은 미완료입니다.

## 4. 공통 JSON 및 연동

기준 main: ef34632ff03626f0b2462fc61cd348dfcee61c49 (2026-11-06 재확인).
정책은 policy_version + policies[]이고 결과와 분리되어 있습니다.
현재 main 계약/스키마는 check_id/status/severity/evidence/recommendation의 5필드 필수,
evidence 문자열 및 선택 details 객체입니다. 최근 팀장 메시지의 4필드 나열을 이유로
recommendation을 제거하거나 details를 evidence 객체로 되돌리지 않았습니다.
팀장님께 최신 main v1.1 유지가 맞는지 확인 요청합니다.

상태 5개와 위험도 소문자 4종을 유지합니다. FILE-01은 하나의 객체를 반환하고
파일별 결과는 details.files에 보존합니다. error/needs_review를 pass로 정규화하지 않습니다.
schema_version/scan_id/target_id/os/scanned_at/results 생성은 D 담당입니다.
main은 기존 기준 커밋을 유지하고 있습니다. 2026-11-07에 팀원 브랜치의 구현도 확인했습니다.

- D `feature/core-jhm` (`868fb06`): `DiagnosisAggregator.from_results`에 사용자가 제공한 Rocky 9.8 FILE-01 결과를 `system_results=[result]`로 전달하는 로컬 검증을 통과했습니다. v1.1 직렬화 후 원래 항목과 `details`가 보존됐고 `needs_review`가 별도 집계됐습니다.
- SSH `feature/architecture-yjh` (`27bf5cd`): `run_readonly`는 고정된 작업을 실행하며 `target_id`, `operation`, `stdout`, `exit_code`를 반환합니다. `passwd_metadata`의 범위는 권한과 소유자·그룹 이름입니다. 전체 FILE-01에는 passwd/shadow의 숫자 UID·GID와 파일 유형, ACL 및 링크 관련 조회, 필요한 그룹 이름 조회 결과가 더 필요합니다.
- 남은 검증: 공통 SSH 작업 범위 협의, 실제 원격 FILE-01 수집 및 Integration Validator 통합 실행.

## 보고 시점

현재 보고 가능한 표현은 '기존 4건 수정 및 v6.1 양 OS 검증 확인,
추가 그룹 조회 구분 수정과 로컬 및 양 OS 105개 테스트 완료,
정책 초안 작성, 원본 evidence·일부 원문 대조·통합 대기'입니다.
요청 1~4 전체 완료라고 보고하지 않습니다. GitHub 커밋/push/PR은 이번 범위 밖입니다.
