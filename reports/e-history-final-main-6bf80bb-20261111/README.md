# E 실행 이력 최종 검증 — main 6bf80bb

작성자: 박태준
범위: 로컬 MOCK·임시 파일 저장소 및 주입된 C 단위 테스트. 실제 SSH 접속·서버 설정 조치 없음.

## 기준 및 통합

- E 브랜치: feature/remediation-cvss-v12
- 통합 전 로컬 HEAD: 49c3e0fcfd11116675246442ab961301f2c2542f
- 검증 기준 main: 6bf80bb114458994bec7d640b4fe4ec53b97bb10
- 실제 테스트 HEAD 및 main 통합 커밋: bb050165b21dade0285372745c92cd5dd996123d
- 원격 E 브랜치·PR #23 제출 HEAD: 201e55714330410e9bd87739af1850b894e9bfee

PR #22는 최신 main에서 FW-01·LOG-01 진단과 테스트 등 13개 파일로 반영되어 있다. merge-tree 사전 검사 후 현재 E 브랜치에 일반 merge했으며 충돌 없음. 49c3e0f와 테스트 HEAD의 remediation/ 및 tests/ 트리는 동일하다. checks/와 core/는 최신 main과 동일하며 다른 담당자 코드를 수정하지 않았다. 이번 후속 문서 커밋은 실행 코드를 바꾸지 않는다.

실제 실행 구간: 2026-11-11T17:48:44.235493+09:00 ~ 2026-11-11T17:48:51.677218+09:00 (KST)

## 이번 실제 실행 결과

| 구분 | 묶음 | 통과 | 실패 | 오류 | 건너뜀 |
|---|---|---:|---:|---:|---:|
| 기존 117 | E v1.1 단위·통합 | 24 | 0 | 0 | 0 |
| 기존 117 | E v1.2 | 18 | 0 | 0 | 0 |
| 기존 117 | 공통 실행 계층 MOCK | 19 | 0 | 0 | 0 |
| 기존 117 | D CVSS·JSON Schema | 52 | 0 | 0 | 0 |
| 기존 117 | B 입력 계약 | 4 | 0 | 0 | 0 |
| 실행 이력 38 | scan_id·복구 후 보안 상태 | 20 | 0 | 0 | 0 |
| 실행 이력 38 | ExecutionHistoryStore | 18 | 0 | 0 | 0 |
| C 추가 | PR #22 방화벽 | 17 | 0 | 0 | 0 |
| C 추가 | PR #22 로그 | 12 | 0 | 0 | 0 |

E 검증은 기존 117 + 실행 이력 38 = 155개 통과다. C 신규 테스트 29개는 별도 집계하며, 이번 전체 선택 실행은 184개 통과다. 저장소 전체 테스트를 실행한 결과는 아니다. 과거 117/137/155 기록을 복사하지 않고 위 tested_head에서 실제 재실행했다.

## 코드·테스트 점검 결과

ExecutionHistoryStore는 D ReportStore와 별개다. history.py의 save()가 완성된 임시 파일을 배타적으로 게시하고, load(execution_id)가 디스크 파일을 읽어 검증한다. 동일 ID 저장은 FileExistsError이며 기존 내용을 덮어쓰지 않는다. load는 메모리 캐시를 쓰지 않는다.

test_execution_history_store.py에서 실제 E _run_demo() → Remediator.run()의 반환 결과를 save()한 뒤 새 ExecutionHistoryStore 인스턴스로 load()한다. 별도 Python 프로세스가 같은 execution_id로 재조회하는 테스트도 통과했다. 실패·거부·제외·Dry-run·복구 성공/실패 결과 보존, 중복·동시 저장, 쓰기·읽기 오류와 손상 JSON 거부도 확인했다. 직접 수동 사용 흐름을 추가 실행한 별도 스모크 결과는 없으며, 실제 E 결과 저장·조회 근거는 이 18개 테스트에 포함된 실행이다.

scan_id와 최종 상태의 근거는 test_remediation_execution_history.py의 20개 및 저장소 통합 사례다.

- scan_id는 report["scan_id"]에서 저장 시도 전에 확보하며 save()의 경로 반환값을 ID로 사용하지 않음.
- D 저장 성공·load 실패를 별도 기록하고 after_scan_id 보존. 같은 target_id·scan_id로 후속 조회 가능.
- 이 실패 기록을 E 전용 저장소에 저장하고 새 인스턴스로 읽어도 실패 단계·scan ID·최종 미확인 상태 유지.
- rollback=verified만으로 final_security_status를 pass로 바꾸지 않음. 복구 후 보안 재진단이 없으면 null/false.
- 복구 후 진단은 새로운 scan_id를 post_rollback_scan_id에 연결. 복구 전 ID 재사용과 오래된 시각 거부.
- 복구 후 진단이 pass여도 원래 조치 outcome=failed는 유지. vulnerable 상태를 확인했다는 verified=true를 조치 성공으로 해석하지 않음.

C 테스트는 실제 명령 대신 command_runner 및 OS·경로 메타데이터 MOCK을 사용한다. C 운영 CLI를 실제 서버에 실행한 검증이 아니며 C 모듈을 E 자동 조치 대상으로 확대하지 않았다.

## 실행 환경과 재현

Windows 11 x64 (10.0.26300), Python 3.12.14, jsonschema[format] 4.26.0. 설치된 임시 의존성 경로를 사용했으며 이번에 의존성을 추가 설치하지 않았다. 다른 팀원은 Python 3.12 가상환경에서 저장소 루트 기준으로 다음을 실행한다.

```powershell
python -m pip install -r reports/e-v12-pr23-feedback-20261111/requirements-test.txt
python -B tests/run_de_mock.py --d-ref 6bf80bb114458994bec7d640b4fe4ec53b97bb10
python -B -m unittest discover -s tests -p test_remediation_v12.py -v
python -B -m unittest discover -s tests -p test_remediation_execution_integration.py -v
python -B -m unittest discover -s tests -p 'test_cvss*.py' -v
python -B -m unittest discover -s tests -p test_remediation_b_v12_integration.py -v
python -B -m unittest discover -s tests -p test_remediation_execution_history.py -v
python -B -m unittest discover -s tests -p test_execution_history_store.py -v
python -B -m unittest checks.system.tests.test_firewall_check -v
python -B -m unittest checks.system.tests.test_log_check -v
```

v1.1 24개는 실행기가 지정 main의 D를 임시 디렉터리에 준비해 22+2개를 별도 프로세스로 실행한다. 환경 변수 없이 통합 테스트만 실행하여 건너뛴 결과를 통과로 계산하지 않는다.

## 증거·개인정보·변경 범위

01~09 로그는 각 묶음의 이번 전체 출력, 10-git-comparison.log는 Git 보존 검사, results.json은 SHA·환경·실제 명령·시각·건수·원본 해시를 담는다. 공개용 사본의 사용자 홈 경로만 <USER_HOME>으로 치환했다. 원본은 저장소 밖에 별도 보존하고 해시를 남겼다. 원본 로그나 이전 검증 폴더를 덮어쓰지 않았다.

.bak 2개는 변경·포함하지 않았으며 실행 전후 해시가 동일하다. 저장소의 과거 커밋 이력에 이미 남은 개인 경로는 이번 검증으로 삭제되지 않는다. force push와 이력 재작성은 하지 않는다.

이번 main 반영은 C 파일 13개를 원본 그대로 가져온 변경이고, E 자체 후속 변경은 이 검증 폴더와 remediation/README.md뿐이다. D JSON v1.2·ReportStore·B/C/D 운영 코드·기존 테스트·MOCK 기능을 변경하지 않았다.

## 남은 제약

- E 이력 저장은 호출 측의 명시적 save(result)가 필요하며 Remediator.run()이 자동 저장하지 않음.
- MOCK·로컬 파일 검증으로 실제 공통 SSH 계층·실서버 접근·자동 조치 운영 검증은 미수행.
- 파일 저장소는 하드링크 지원, 전용 디렉터리 권한과 보관 정책 필요. 암호화·서명 감사 저장소는 아님.
- 원격 PR #23은 201e557이며 로컬 변경은 아직 미반영. 이번 작업은 로컬 커밋까지만 수행하고 Push·PR 업데이트·원격 main 병합은 하지 않음.
