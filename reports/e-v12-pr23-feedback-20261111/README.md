# PR #23 후속 main 호환성·문서 검증

이 문서는 201e557 시점의 과거 117개 검증 기록이다. 이후 로컬 E 실행 이력(16b545c)과 별도 저장소 보완의 최신 상태는 [remediation README](../../remediation/README.md)를 참조한다. 이 문서의 당시 범위·결과를 새 실행 결과로 해석하지 않는다.

작성자: 박태준
범위: 최신 main 통합, 오프라인 회귀 및 B SSH-01 입력 계약 검증, 문서 정리. 실제 SSH·서버 설정 변경 없음.

## 기준 및 Git 통합

- 작업 브랜치: feature/remediation-cvss-v12
- 원격 제출 PR: #23, 기존 제출 HEAD 7e33241defc6f5fd753bb4bb9b0799215a41643d
- 최신 origin/main: e4af8a6659a695a5d7e0152b8c0d831e7736fef1
- PR #10: 병합 완료, d09d9900cff050b73162ac34a987eb8339ac5ceb
- PR #21: 병합 완료, e4af8a6659a695a5d7e0152b8c0d831e7736fef1
- main 통합 커밋: 702b160a74106bb081e92a9df16fe6608bcf38d3
- B 호환성 테스트 추가 및 실제 테스트 HEAD: 511895598e988eb6eaee69b0395f7af48c2f6276

merge-tree 사전 검사 후 일반 merge로 반영했으며 충돌 없음. main에서 B 파일 3개를 정상적으로 가져왔고 임의의 충돌 해결이나 덮어쓰기는 수행하지 않았다. E 런타임·D 코드·기존 24/18/19개 테스트는 기존 제출 HEAD와 동일하다. 추가된 E 측 코드는 최신 B 계약을 확인하는 테스트 파일 1개뿐이다.

이번 문서 커밋은 테스트 HEAD 이후 증거·설명만 정리한다. 원격 Push·PR 업데이트·main 병합은 하지 않는다. 로컬에 main을 반영한 것과 원격 main으로 E를 병합한 것은 구분한다.

실제 실행 구간: 2026-11-11T15:52:31.882559+09:00 ~ 2026-11-11T15:52:37.045871+09:00 (KST)

## 이번 실제 실행 결과

| 묶음 | 통과 | 실패 | 오류 | 건너뜀 |
|---|---:|---:|---:|---:|
| 기존 E v1.1 22+2 | 24 | 0 | 0 | 0 |
| 기존 E v1.2 | 18 | 0 | 0 | 0 |
| 기존 공통 실행 계층 MOCK | 19 | 0 | 0 | 0 |
| D CVSS·JSON Schema | 52 | 0 | 0 | 0 |
| 최신 main B↔D↔E 입력 호환성 추가 | 4 | 0 | 0 | 0 |
| 합계 | 117 | 0 | 0 | 0 |

기존 요청 범위 113개가 모두 통과했고, 최신 B 호환성 4개를 추가했다. 이번에 실제 재실행한 로그이며 과거 14:25 검증 로그를 재사용하지 않았다. 실행 시작·종료 시각과 명령은 results.json 및 각 로그에 기록했다. 과거 결과는 reports/e-v12-final-20261111에 그대로 구분한다. 전체 저장소 테스트 실행을 의미하지 않는다.

## 최신 B 입력 호환성

신규 tests/test_remediation_b_v12_integration.py에서 최신 main의 checks.account.ssh_check를 직접 import한다. B/C/D 소스는 수정하지 않는다.

- 실제 B 정책 파일과 check_ssh_01()의 순수 판정 및 to_result_v1_2() 출력 사용.
- 합성 SSH 설정 문자열에서 vulnerable/pass/error/needs_review를 판정하고, not_applicable 결과도 계약 검사.
- v1.2의 cvss pending/not_applicable, 점수 null, severity 미포함, details 보존을 D/E 계약으로 검증.
- B 기존 v1.1 출력도 E build_plan()에 정상 전달.
- 최초 진단과 재진단에서 동일한 테스트 콜백 → B 순수 함수 → D 집계·저장·재조회 → E 판정 경로 사용.
- pass는 성공, vulnerable/error/needs_review는 기존 MOCK 복구 유지.

find_sshd(), get_sshd_output(), read_config_text()는 호출 시 테스트가 실패하도록 막았다. 따라서 실제 B 프로그램의 순수 판정·출력 호환성 검증이며 Linux 서버 수집·원격 연결·운영 정책 검증을 의미하지 않는다. B의 실제 run_check()를 서버에 실행한 결과로 해석하지 않는다.

## 증거와 개인정보 구분

현재 폴더의 로그와 results.json은 공개용 비식별 사본이다. 실제 로컬 사용자 홈 경로를 <USER_HOME>으로 치환하고 공개용 로그 줄바꿈을 LF로 정규화했으며 테스트 결과·시각·커밋·명령 옵션·종료 코드는 보존한다. 로그 상단의 original_sha256 및 results.json의 원본 해시는 비식별화 전 원본 바이트를 식별한다. 치환된 경로 문자열은 실행 가능한 명령이 아니므로 재현 시 아래 python 명령을 사용한다.

과거 14:25 자료의 원본도 먼저 저장소 밖에 복사한 뒤 공개용 경로를 치환했다. 과거 원본 목록과 SHA-256은 reports/e-v12-final-20261111/original-evidence-manifest.json에 기록했다. 원본 보관 위치는 개인 경로를 공개하지 않도록 저장소 문서에 적지 않으며 필요 시 작성자에게 요청한다. 원본 파일은 바이트 단위로 보존하고 공개용 사본과 구분한다.

이미 제출한 과거 커밋에는 원래 경로가 남아 있을 수 있다. 이번 작업은 현재 파일의 비식별화이며 과거 Git 이력 삭제를 의미하지 않는다. force push·이력 재작성은 수행하지 않는다.

## 재현 환경과 명령

Windows 11 x64, Python 3.12.14, jsonschema[format]==4.26.0, 표준 unittest 사용. 의존성은 기존 임시 경로에서 읽었으며 이번 설치·환경 변경은 없다. 다른 개발자는 Python 3.12 가상환경에서 다음을 실행한다. 저장소 루트와 최신 B가 포함된 tested_head가 필요하다.

```powershell
python -m pip install -r reports/e-v12-pr23-feedback-20261111/requirements-test.txt
python -B tests/run_de_mock.py --d-ref e4af8a6659a695a5d7e0152b8c0d831e7736fef1
python -B -m unittest discover -s tests -p test_remediation_v12.py -v
python -B -m unittest discover -s tests -p test_remediation_execution_integration.py -v
python -B -m unittest discover -s tests -p 'test_cvss*.py' -v
python -B -m unittest discover -s tests -p test_remediation_b_v12_integration.py -v
```

v1.1 통합 2개는 첫 실행기가 SECUREOPS_D_SOURCE를 준비한다. 환경 변수 없이 직접 실행해 건너뛴 결과를 통과로 계산하지 않는다.

## 파일과 로그

- 01~04 로그: 요청한 기존 113개 회귀의 이번 실행 전체 출력
- 05-b-contract.log: 최신 B 입력 계약 4개 추가 검증
- 06-git-comparison.log: 최신 main·PR #10 조상 관계 및 E/D/기존 테스트 보존 검사
- results.json: 실제 환경, 명령, 시각, 건수, 백업 파일 전후 해시, 원본 로그 해시
- requirements-test.txt: 재현에 필요한 테스트 의존성

## 실패 및 미확정 사항

이번 최종 실행의 실패·오류·건너뜀 없음. 런타임 호환성 수정을 요구하는 문제는 발견하지 못했다.

D↔E 롤백 이력 저장·최종 상태 규칙은 이번 작업에서 정하지 않는다. 기존 after_report와 rollback의 의미, MOCK 기능, 승인·백업·허용 목록·복구 동작은 변경하지 않는다. 효민님과 협의 후 별도 반영한다. 실제 서버 SSH 설정 변경·CVSS 계산 기능 추가·D 코드 변경은 수행하지 않았다.

PR #23에 반영되었다고 보고하지 않는다. 이번 변경은 로컬 커밋까지만 준비하며 사용자 승인 전 Push·PR 업데이트를 하지 않는다.
