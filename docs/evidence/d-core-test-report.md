# SecureOps D 담당 테스트 증거 보고서

2026-11-09 14:54:07~14:54:11 KST에 노트북 작업 환경에서 재실행했다.
이 문서는 이전 보고 수치를 옮긴 것이 아니라 이번 실행 로그를 기준으로 작성했다.

## 1. 결과 및 검증 범위

| 구분 | 이번 결과 | 검증 범위 |
|---|---|---|
| MOCK 실행 계층 | 12개 통과 | 합성 콜백을 통한 단일 서버 실행·검증·저장·실패 처리 |
| JSON v1.1 검증·집계 | 26개 통과 | 입력 형식, 집계, 복사, CLI 등 |
| 결과 통합 | 10개 통과 | 합성 B/C 결과 통합, JSON 왕복, 실행 메타데이터 |
| 저장·이력 | 11개 통과 | 저장·조회·전후 연결, 충돌·동시 저장·실패 처리 |
| 레거시 변환 | 11개 통과 | 명시적 v1.1 변환 및 정보 보존 |
| 원격 JSON 수신 파서 | 14개 통과 | 합성 stdout 및 실행 메타데이터의 수신 검증 |
| 현재 작업 트리 전체 | 87개 발견: **84개 통과, 3개 건너뜀** | B/C 실제 소스가 작업 트리에 없는 조건 |
| 실제 B/C 판정 함수 기반 오프라인 통합 | **3개 통과** | 합성 정책·관측값을 실제 판정 함수에 주입 |
| B/C 소스를 제공한 D 전체 테스트 | **87개 모두 통과** | 기존 84개 + 오프라인 통합 3개 |
| 실제 SSH·VM 연동 | **미실행** | 연결·원격 명령·실제 서버 관측 및 진단 결과는 검증하지 않음 |

모든 실행 명령의 종료 코드는 0이다. 행별 실행은 서로 중복되므로 통과 수를 합산하지 않는다.
여기서 전체 테스트는 `tests/`의 unittest 검색 범위이며 B/C 브랜치 자체의 전체 테스트를 뜻하지 않는다.
현재 작업 트리는 `feature/core-jhm`이며, 기본 브랜치 `main`으로 전환해 테스트한 것은 아니다.

## 2. 환경 및 Git 상태

| 항목 | 값 |
|---|---|
| 실행 운영체제 | Windows |
| Python | CPython 3.14.2 |
| 테스트 도구 | Python 표준 라이브러리 unittest |
| 브랜치 | `feature/core-jhm` |
| D HEAD | `4a48119bff1bad828390b9f612b0de1c77de3a72` |
| 시간 기준 | KST, UTC+09:00 |
| 네트워크 Git fetch | 수행하지 않음 |
| 패키지 설치 | 수행하지 않음 |
| 실제 SSH 및 VM | 실행하지 않음 |

실행 시작 시 Git 상태:

```text
## feature/core-jhm...origin/feature/core-jhm
?? tests/test_bc_offline_integration.py
```

오프라인 통합 테스트 파일은 이전 작업에서 작성된 **미추적 파일**로, 위 D HEAD에 포함되어 있지 않다.
따라서 HEAD만 체크아웃하면 이번 87개 테스트 구성이 재현되지 않는다.
확인할 수 없는 데스크탑 원본을 복구했거나 동일하게 재현한 코드라고 주장하지 않는다.
해당 파일을 포함한 core/test 소스·fixture의 실행 전후 SHA-256은
[환경 및 결과 기록](environment-and-results.json)에 보관했으며 모두 동일했다.
이 작업에서 새로 생성한 파일은 `docs/evidence/` 아래의 증거 자료뿐이다.

## 3. 실행 명령과 원문 로그

각 명령은 저장소 루트에서 실행했다. `-B`로 바이트코드 생성을 억제하고 `-X utf8`로 출력 인코딩을 지정했다.
각 로그에는 시작 시각, 명령, B/C 소스 조건, 종료 코드, 개별 테스트 결과 및 unittest 요약이 포함된다.

공통 명령 형식:

```powershell
python -B -X utf8 -m unittest discover -s tests -p <패턴> -v
```

| 실행 | `-p` 패턴 | 발견 / 건너뜀 | 소요 시간 | 로그 |
|---|---|---:|---:|---|
| MOCK runner | `test_core_runner.py` | 12 / 0 | 0.045s | [01](logs/01-mock-runner.log) |
| v1.1 검증·집계 | `test_core.py` | 26 / 0 | 0.626s | [02](logs/02-json-validation-aggregation.log) |
| 결과 통합 | `test_core_integration.py` | 10 / 0 | 0.002s | [03](logs/03-result-integration.log) |
| 저장·이력 | `test_core_storage.py` | 11 / 0 | 0.093s | [04](logs/04-storage.log) |
| 레거시 변환 | `test_core_legacy.py` | 11 / 0 | 0.008s | [05](logs/05-legacy.log) |
| 원격 JSON | `test_remote_result.py` | 14 / 0 | 0.022s | [06](logs/06-remote-json.log) |
| 현재 작업 트리 전체 | `test*.py` | 87 / 3 | 0.581s | [07](logs/07-full-working-tree.log) |
| B/C 오프라인 통합 | `test_bc_offline_integration.py` | 3 / 0 | 0.149s | [08](logs/08-bc-offline-integration.log) |
| B/C 제공 후 전체 | `test*.py` | 87 / 0 | 0.680s | [09](logs/09-full-bc-offline.log) |

처음 7회는 `SECUREOPS_B_SOURCE_ROOT`, `SECUREOPS_C_SOURCE_ROOT`를 제거한 자식 프로세스에서 실행했다.
오프라인 2회는 아래 임시 소스를 두 환경변수로 제공했다. 부모 환경변수는 변경하지 않았다.

## 4. MOCK과 원격 JSON 수신 검증

MOCK runner는 실제 진단을 수행하지 않는 합성 콜백으로 검증했다.
성공 시 `mock/` 저장 경로, 입력 원본 보존, 호출 실패 시 미저장, 이후 콜백 실행,
잘못된 반환값·중복 check_id 거부, 저장 실패 전달 및 중복 scan_id의 기존 파일 보존을 확인했다.
`mode='real'` 거부 테스트는 실제 모드의 실행 성공을 의미하지 않는다.

`remote_result.py`는 아래 14개 테스트를 재실행했다. 개별 이름은 [원문 로그](logs/06-remote-json.log)에서 확인할 수 있다.

1. 유효 JSON 결과 및 원본 보존
2. 잘못된 JSON·로그 혼합 출력 거부
3. 객체가 아닌 입력 거부
4. 필수 필드 누락 거부
5. 필드 타입·허용값 검증
6. 정상 pass JSON이라도 실행 실패·비정상 종료이면 거부
7. 실행 메타데이터와 stdout의 명시적 타입 검증
8. 중첩 수준을 포함한 중복 키 거부
9. NaN·Infinity·수치 오버플로 거부
10. UTF-8 크기 한도·깊은 JSON 처리
11. 5개 진단 상태 보존
12. 오류 메시지에 입력 원문이 포함되지 않음
13. 합성 응답 → runner → 집계·저장
14. 실행 실패 응답이 저장되지 않음

여기서 stdout·exit_code·execution_succeeded는 모두 합성 입력이다.
실제 SSH 출력 수신, 타임아웃 발생, 연결 실패 및 실제 종료 코드 매핑을 실행한 것은 아니다.
공통 SSH 인터페이스와의 연동은 검증 범위 밖이다.

## 5. 실제 B/C 판정 함수 기반 오프라인 검증

사용자 요청 범위에서 로컬 원격 추적 브랜치의 소스를 읽어 임시 디렉터리로 제공했다.
팀의 별도 승인 이력은 이 실행에서 확인하지 않았으며, 승인 완료나 원격 최신 상태라고 주장하지 않는다.

| 담당 | 로컬 참조 | 이번에 사용한 커밋 | 호출 함수 |
|---|---|---|---|
| B | `origin/feature/account-check-cjw` | `cfbd37b4dbd102ec894a2150d47f751ad5c74afa` | `check_ssh_01(policy, sshd_output, config_text="")` |
| C | `origin/feature/system-check-ksh` | `6bb330feccfc6541bc145db9b6e18f24b4bce394` | `run(policy, collector=None, environment=None)` |

사용한 파일은 B의 `checks/account/ssh_check.py`와 C의
`checks/system/file_check.py`, `common.py`, `policy_rules.py`, `link_check.py`이다.
C 커밋은 이전 실행의 `aaaa03f9e7a34aeed673b5b15afe68199a3d0d39`보다 갱신되었지만,
사용한 C 소스 4개는 두 커밋 간 diff가 없음을 확인했다. 새 SVC-01 기능은 검증하지 않았다.

소스 준비는 다음 읽기 전용 Git 명령으로 수행했으며 정책 파일은 추출하지 않았다.

```text
git rev-parse <로컬 B/C 참조>
git show <확정 커밋>:<사용할 Python 소스 경로>
```

임시 소스는 실행 후 정리했다. 테스트 내에서는 Git 조회나 외부 명령을 실행하지 않는다.
실제 B/C 판정 함수만 호출하고 정책·sshd 출력·파일 관측값·환경은 모두 합성 데이터로 주입했다.
수집 함수, subprocess.Popen, os.system, socket.socket은 호출되면 실패하도록 차단하고 미호출을 확인했다.
정책의 `approved` 값도 테스트 분기를 위한 합성이며 운영 승인을 의미하지 않는다.

3개 테스트의 검증 내용:

1. B 취약 + C 정상 판정을 JSON 수신 파서와 `run_target()`에 연결하여
   v1.1 보고서·집계·저장·재조회 결과 일치를 확인했다. 이행률 50.0%를 검증했다.
2. FILE-01의 환경·파일별 관측값·검사 내역을 포함한 중첩 details를 보존했다.
   정책·관측 데이터·환경·B/C 반환 원본이 변경되지 않았으며,
   실행 후 원본 및 반환 보고서를 변경해도 저장 보고서가 유지됨을 확인했다.
3. error + needs_review, pass + error, needs_review + pass, pass + pass 조합을
   subTest로 실행했다. 상태별 건수, 평가 가능 분모, 이행률 및 취약 항목만의 심각도 집계를 검증했다.

runner는 이 경우에도 `mode='mock'`이다. 실제 판정 코드를 사용했다는 점에서
합성 반환 콜백 테스트와 구분하지만, 서버 수집·전송 출처는 실제 환경이 아니다.

## 6. 건너뜀 사유 및 미실행 항목

현재 작업 트리의 전체 실행에서 오프라인 통합 3개는 모두 다음 사유로 건너뛰었다.
로컬 사용자 경로는 로그에서 `<REPO>`로 치환했다.

```text
B/C 소스 없음: <REPO>/checks/account/ssh_check.py
```

B 소스 검사가 먼저 수행되므로 이번 skip 메시지는 B 파일 부재를 표시한다.
현재 브랜치에는 C 실제 소스도 없다. B/C 소스 제공 후에는 건너뜀 없이 3개가 통과했다.
이번 오프라인 실행에서는 의존 패키지 부재에 따른 건너뜀이 발생하지 않았다.

실제 SSH 연결, 실제 VM의 진단·수집·원격 명령, 공통 SSH API 연동,
Ubuntu/Rocky 실환경 동작 및 Python 3.12 실행은 미실행이다.
이 보고서의 성공 표시는 Windows/Python 3.14.2에서 실행한 명시된 테스트 범위에 한정한다.

## 7. 재현 및 변경 범위

이번 실행에 사용한 수집 스크립트:

```powershell
python -B -X utf8 docs/evidence/run-core-evidence.py
```

[실행 스크립트](run-core-evidence.py)는 실행할 때의 로컬 B/C 참조를 해석하고
확정 커밋·소스 해시·명령·결과를 기록한다. 참조가 바뀌면 재실행 결과의 소스 버전도 바뀔 수 있다.
정확히 이번 버전을 재현하려면 위 커밋의 소스와 기록된 미추적 테스트 파일을 제공해야 한다.
기존 공식 MOCK fixture 테스트는 로컬 `origin/main` 객체의 샘플을 읽으며,
해당 참조의 커밋도 [환경 기록](environment-and-results.json)에 남겼다.
네트워크 조회·checkout·merge 없이 실행했다.

로그에는 로컬 사용자 경로를 치환했고, 인증정보·환경변수 덤프·원격 주소·실제 서버 출력은 저장하지 않았다.
기능·기존 테스트·다른 팀원 파일·공통 SSH 모듈·정책 파일은 수정하지 않았다.
Commit, Push, Merge는 수행하지 않았다.
