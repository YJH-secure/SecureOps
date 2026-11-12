# 태준님·팀장님 전달 초안

D main `62d1bf72ef52c7455bc0c2dd624206eb8350f925`와 E PR23
`b0ef73a1613ebc40fdd596edcbaf0413d32309b8`을 고정해 11/12 독립 MOCK 검증을 완료했습니다.

- E 기존 테스트 123개, D CVSS/Schema 52개, C 별도 회귀 29개로 기존 204개 범위를 재확인했습니다.
- D 작성 독립 8개 및 최신 D 기존 테스트와 결합한 181개도 실패·오류·Skip 없이 통과했습니다. 실행 범위는 중복되므로 합산하지 않습니다.
- v1.2 입력·계획/승인, execution/plan/approval ID, D 저장/재조회, E 이력 1.0과 진단 1.1/1.2 분리를 확인했습니다.
- save 성공/load 실패에서도 scan_id가 유지되고 E는 failed/최종 미확인을 유지했습니다.
- 롤백 후 재진단이 없으면 final_security_status=null, verified=false였습니다.
- 롤백 후 별도 scan ID의 pass를 확인해도 원래 조치 outcome=failed를 유지했습니다.
- D 보고서 16개와 E 이력 9개를 분리 저장하고 새 프로세스로 재조회했습니다. 기존 보고서는 불변 보존했습니다.

검증 범위에서 E 운영 코드 수정이 필요한 실패는 발견하지 않았습니다.
공통 실행 계층의 실제 계약, 명시적 E 이력 저장 호출, 운영 디렉터리/권한/보관 정책은 별도 협의가 필요합니다.
실제 SSH/VM·운영 변경/복구는 실행하지 않았습니다.
최초 증거 수집기의 import 탐색 및 Dry-run JSON 비교 오류와 최종 재실행 결과를 구분해 보존했습니다.

기존 PR20/25와 이전 자료는 유지했고 Commit·Push·PR 수정·Merge는 하지 않았습니다.
최종 승인·병합 판단을 요청드리기 전 결과 공유용 자료입니다.

[상세 보고서](report.md), [환경·명령·로그](submission-package/python-3.14/environment-and-results.json).
