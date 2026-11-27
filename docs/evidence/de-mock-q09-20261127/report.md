# D/E 공통 격리 MOCK Q09 반영 보고서

2026-11-27 신규 실행: **26 PASS / FAIL 0 / ERROR 0 / SKIP 0 / exit 0**.

일반 P01~P13 13건 재실행과 신규 FILE-01 Q01~Q13 13건을 구분합니다. 과거 P01~P13 13 PASS, 결합 297 PASS, E 266 PASS, D callback 38 PASS 및 A/B/D 21 PASS를 이번 신규 실행에 합산하지 않습니다. 전체 main 회귀를 이번 작업에서 재실행했다고 주장하지 않습니다.

## Q09 승인 계약 비교

| 경로 | 공통 호출부 옵션 | 실제 E 종료 정책 | 신규 근거 |
|---|---|---|---|
| 일반 SSH-01 실패·롤백 | post_rollback_recheck=False | 추가 재진단 없음, 최종 보안 상태 미확인 | P13, 기존 단언 및 소스 유지 |
| FILE-01 정상 조치·원상복구 성공 | False 유지 | after → post_restore | Q01, callback 2회, E save/load 각 2회 |
| FILE-01 조치 실패·검증된 롤백 | False 유지 | post_rollback | Q02, callback 1회, E save/load 각 1회 |
| FILE-01 복구 검증 실패 | False 유지 | 재진단 성공으로 처리하지 않음 | Q03/Q12 |

기존 STOP은 계약 우선순위 미확정 때문이었습니다. 승인된 Q09가 이를 해소하며, E 엔진 옵션·기대값·정책은 수정하지 않았습니다. C Bridge는 phase 실행 여부를 결정하지 않고 snapshot/mode/expected_identity를 검사합니다.

## 구현 및 원본 비교

`orchestration/de_mock.py`는 승인 원본 SHA-256 `8f12f8361bbc0a6155ddb8307000f03f2a2a9eb651de57226d098ddf159c1a9c`를 검증하여 복사했습니다. Q09 설명 docstring만 보완했고 실행 AST는 원본과 동일합니다. 외부 전달 callback은 E helper의 snapshot/plan/approval/identity 바인딩을 그대로 사용합니다.

일반 P03은 E43에서 FILE-01이 지원되므로 미지원 fixture를 SVC-01로 변경했습니다. 목적·단언은 유지했습니다. P13은 원문 그대로이며 제출 사본 파일 끝의 불필요한 빈 줄만 제거했습니다. 원본 로컬 파일과 STOP 기록은 수정하지 않았습니다.

최종 작업은 신규 공통 호출부, 격리 테스트·runner·manifest 및 비식별 증거에 한정합니다. 기존 D Core/ReportStore/JSON Schema, E/C 소스, A/B/D 동결 자료는 변경하지 않습니다.

## 실행 근거 및 책임

- 명령: `python -B tests/offline_de/run_tests.py` (5개 환경변수는 tests/offline_de/README.md 참조).
- Windows / Python 3.14.2. 정확한 설치 의존성은 integrity.json에 기록합니다.
- D base `0cab3a247d2143fc5556e37f6651440e109eef70`.
- E #43 `57362706701a540247d2eb448099400e6b561749`, #35 `03573429825e02e6400257f19c67f337e454dd71`, #23 `b0ef73a1613ebc40fdd596edcbaf0413d32309b8`.
- C `2fac2a02edb1edf08cf4435138f4a1d543e33ba2`, Bridge SHA 및 callback SHA는 sources.json/results.json에서 대조합니다.
- 실제 import는 results.json의 imports에 기록합니다. core는 이 D worktree, remediation은 E43 고정 전달 소스, C file_check·Bridge·D callback은 각각 외부 검증 사본입니다.
- E.run은 호출당 정확히 1회. callback 내부 ReportStore 생성/save/load는 금지하는 spy로 검증합니다.
- E 어댑터가 phase별 보고서를 저장·재조회하고 전체 dict 동일성을 검사합니다. 공통 호출부는 before 조회 1회 및 E 이력 save/load 각 1회만 추가합니다.
- Q01: before/after/post_restore scan_id 모두 구분, mode 0644/0666, 최초 snapshot·expected_identity 유지, before 파일 byte 불변.
- Q02: 실패 outcome 유지, verified rollback 후 새로운 post_rollback 보고서를 저장·재조회. 이를 조치 성공으로 변경하지 않음.
- Q04: 잘못된 after mode는 Bridge·저장 전에 실패. 복구 뒤 적합한 post_rollback=0666은 별도 검증하며 원래 조치 outcome은 failed 유지.
- Q05/Q06/Q11/Q13: identity·digest·plan·phase·target·CVSS·scan_id 불일치 차단.
- Q07/Q08: 저장 실패·저장 성공 후 조회 실패 분리, ID와 기존 저장 데이터 유지, 자동 삭제·재시도 없음.
- P08/P09/P12 및 Q09/Q10: 이력 저장/조회/동등성 실패와 중복 execution_id 거부, E 자동 재실행 없음.

## 증거 및 실패 이력 보존

최종 unittest.log/results.json/test-matrix.md, Q01/Q02 원본 MOCK 관측 JSON, integrity.json, SHA256SUMS를 제공합니다. 로컬의 전체 13개 Q 관측 JSON과 초기 실패 실행은 별도 보존했습니다. 결과 JSON은 진단·승인·snapshot 모두 합성 MOCK임을 전제로 합니다.

제출 사본은 CRLF 줄바꿈만 LF로 정규화했습니다. JSON 값과 로그 내용은 변경하지 않았으며 원본·제출본 SHA-256 대응은 integrity.json의 publication_provenance에 기록합니다. 개인 경로를 포함하지 않는 최종 로그와 합성 관측 자료만 선별했습니다.

초기 runner import 순서 오류는 테스트 시작 전 발견해 외부 E 소스 우선 로딩으로 정정했습니다. 다음 초기 실행은 구형 P03 fixture, Q04의 유효한 롤백을 잘못 차단한 신규 단언, Q05의 승인 객체 재사용 때문에 실패했습니다. E/C/D 동결 소스는 변경하지 않고 테스트 구성만 수정했습니다. run3 23 PASS 이후 경계 3건을 추가하여 최종 26 PASS로 검증했으며 실행 횟수를 중복 합산하지 않습니다.

## 한계 및 교차 검토 요청

- 실환경 SSH/VM·중앙 배포·운영 권한·Linux·Python 3.12는 이번 범위에서 미검증입니다.
- PR 단독 checkout에 외부 E/C/Bridge/callback 의존성이 자동 공급되지 않습니다. 고정 사본과 해시 확인이 필요합니다.
- E phase별 오류 보고서 누락 및 rollback 실패 표현의 기존 한계는 별도 개선 범위입니다.
- snapshot digest는 무결성 대조이며 승인자 인증·실서버 출처를 증명하지 않습니다. 신뢰된 로컬 MOCK 송신 경계가 전제입니다.
- 단일 E 실행 내부 중복 phase 저장과 ID 충돌은 검사하지만 프로세스 재시작 후 조치 재실행 방지는 구현하지 않았습니다.
- 태준님: Q09 우선순위, phase attempt와 종료 이력, 외부 E 의존성 및 실패 경계 검토 요청.
- 서후님: 고정 Bridge snapshot/mode/expected_identity, permissions pass와 종합 needs_review 구분 및 C 원본 결과 보존 검토 요청.
- Draft PR만 제출하며 Ready 전환·main 병합은 수행하지 않습니다.
