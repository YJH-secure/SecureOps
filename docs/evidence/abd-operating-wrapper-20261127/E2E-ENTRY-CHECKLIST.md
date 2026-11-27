# A/B/D 실환경 진입 상태 — 2026-11-27

이 파일은 신규 wrapper의 승인 경계를 기록한다. 기존 설계 문서나 동결 증거를 수정하지 않았다.

| 항목 | 상태 | 근거 / 남은 확인 |
|---|---|---|
| GNS3 3-C-2 복구, T5·T6 PASS | 팀장 수령 보고로 갱신 | 이번 사용자 지시. 원본 로그·SHA 미제공/미대조이며 D 독립 실측 아님 |
| 기존 A/B/D 전체 격리 MOCK | 21 PASS 수용 이력 | 과거 기록, 신규 19개와 구분 |
| 신규 receipt wrapper | 격리 MOCK 19 PASS | 신규 results.json 및 로그 |
| 기본 D 회귀 | 경로 지정 173 PASS | main-configured-results.json |
| B S2 설치 | 별도 승인 대기 | 수집기/정책/설정/owner·모드/sudoers를 이 PR에서 배포하지 않음 |
| Central VM 신규 실행 | 별도 승인 대기 | 네트워크 복구 보고가 VM 실행 허가는 아님 |
| 실제 A/B/D E2E | 별도 승인 대기 | 이 wrapper는 A execution 수신 전용이며 SSH 실행 CLI가 아님 |
| 운영 ID 영속 writer | 미구현·계약 미결정 | 반환값 id_link만 제공. 후보 경로·권한·원자성·복구 미확정 |

별도 실환경 승인 전 확인할 사항:

1. 고정 D Core/B/A/D 어댑터 소스·정책·import 경로와 LF 해시를 배포 manifest로 대조.
2. 복구 이후 실제 자산/SSH 별칭/target_id, 중앙 source context, 관측 OS·버전, ACC 대상 계정 재확인.
3. A preflight 네 플래그를 실제 설치·권한·VM·백업 증거로 확인. MOCK True를 실측 증거로 사용하지 않음.
4. 승인된 private report_root/record_root의 소유권·접근·용량·hard link 지원·보존·복구·감사 기준 확인. wrapper가 운영 경로를 생성하지 않음.
5. A 실제 timeout·streaming 상한·stderr STOP·Linux 프로세스 종료·재시도0 범위 확인. Windows fake process 결과로 실환경 완료를 주장하지 않음.
6. 실행 횟수·대상·중단 책임·증거 회수/비식별화·사후 보존 범위를 팀장이 별도 승인.

source mismatch, A stop reason, B 신뢰 오류, D 저장/조회 검증 실패 시 기존 계층 구분을 유지한다. E 조치·D/E FILE-01 통합은 이 승인에 포함되지 않는다. Ready 전환·main 병합·실제 VM/SSH 작업은 하지 않았다.
