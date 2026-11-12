# 팀장님·서후님 공유 초안

공식 main `62d1bf72ef52c7455bc0c2dd624206eb8350f925`의 C/D를 별도 Worktree에 고정해
2026-11-12 09:59:39–10:00:02 KST에 D 독립 재검증했습니다. 운영 코드·기존 테스트는 수정하지 않았습니다.

- C 원본 163개, 상태 시나리오 5/5, 거부 28/28 통과.
- 원본 main D 기본 171개 OK/클래스 Skip 1, D 경로 지정 173개 모두 통과.
- PR20 원본 9개, 기존 D 독립 8개 모두 수정 없이 통과.
- 실패·오류 0이며 PR29의 과거 fixture 오류 이벤트 6개도 재발하지 않았습니다.
- 네 실제 모듈 결과를 한 보고서로 수신·검증·집계·저장·재조회했고 고유 ID·details를 보존했습니다.
  pass/vulnerable/error/needs_review 각 1개, 이행률 50%, CVSS pending 1/not_applicable 3, 점수·등급 null입니다.

서후님 ZIP `f4292660d9b6aeba908079f3c0883f0d7a6aa2f8618c231bfd66dd06e1192247`의
87개 소스 Git blob 표식이 실제 main과 일치했고 실행 건수도 일치했습니다.
서후님 Python 3.12.14 스냅샷 실행과 이번 Python 3.14.2 실제 Worktree 실행은 별도 기록입니다.
네 결과의 status/evidence/recommendation/CVSS는 일치했습니다. 일부 details는 합성 정책·호스트·OS 메타데이터와
FW 오류 주입 종류 차이이며, 실행별 C 원본과 D 저장 결과는 모두 일치했습니다.

PR20에는 이번 main 증거를 추가하고 과거 ZIP/병합 전 기록을 보존하는 방식을 제안합니다.
실제 SSH/VM, 공통 실행 계층·권한 인수 및 운영 정책 보류는 여전히 후속 사항입니다.
not_applicable은 계약 fixture이며 운영 자동 제외 판정을 뜻하지 않습니다.

Commit·Push·PR 수정·Merge는 하지 않았습니다. 증거 제출 범위와 후속 조치 승인을 기다립니다.

[상세 보고서](report.md), [실행 환경·명령·로그](environment-and-results.json).
