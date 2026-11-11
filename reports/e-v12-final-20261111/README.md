# E v1.2 최종 통합·회귀 검증 (과거 main b4bc7e7 기준)

작성자: 박태준

이 문서는 2026-11-11 14:25 KST의 과거 113개 검증 기록이다. 이후 PR #23을 제출했으며, PR #10·#21 병합 후 최신 main 재검증은 [후속 검증 보고서](../e-v12-pr23-feedback-20261111/README.md)에서 별도로 확인한다. 이 문서의 기준 SHA·시각·결과를 최신 검증값으로 덮어쓰지 않는다.

개인 경로가 포함된 원본은 저장소 밖에 바이트 그대로 보존했다. 저장소의 로그·results.json은 공개용 비식별 사본이며 `<USER_HOME>`으로 경로를 치환했다. 원본 해시는 각 파일과 original-evidence-manifest.json에 기록했다. 기존 공개 커밋의 이력 재작성은 수행하지 않아 과거 커밋에는 기존 경로가 남아 있을 수 있다.
검증 일시: 2026-11-11 14:25:34~14:25:40 (KST)
범위: 오프라인 MOCK 및 로컬 D 보고서 검증. 실제 SSH 접속·서버 설정 변경 없음.

## 기준 커밋과 통합 결과

- 브랜치: feature/remediation-cvss-v12
- 사용한 origin/main: b4bc7e7c1764e66e84367f6d34a3aee5b2a2ff37
- 통합 전 E HEAD: 32d5107a4ddfd7994ac32563cb08a69b411f0076
- 실제 테스트한 E HEAD: 6df7caf6a895a919521fb4848ea3d8fc9b473412
- 기존 E v1.1 브랜치 HEAD: c0d3a3161e9e10c75f5e4555c3d734c81f05316f

PR #16의 Merge Commit은 b4bc7e7이며 부모는 4278369와 c0d3a31이다. 최신 main에 기존 E v1.1 커밋이 포함되어 있음을 Git 이력으로 확인했다. merge-tree 사전 검사 후 현재 E v1.2 브랜치에서 일반 merge를 수행했으며 충돌은 없었다. rebase·cherry-pick·기존 브랜치 변경은 수행하지 않았다.

32d5107과 테스트 HEAD의 전체 Git 트리는 동일하다. 이번 main 반영으로 런타임 코드나 테스트가 새로 바뀌지 않았으며, 최종 검증 증거만 별도 후속 커밋에 추가한다. 따라서 tested_head는 문서 커밋이 아니라 실제 검증한 코드 기준점이다.

## 실제 실행 환경

- OS: Windows 11, 빌드 10.0.26300, x64
- Python: CPython 3.12.14
- 테스트 의존성: jsonschema[format]==4.26.0
- unittest: Python 표준 라이브러리
- Git: 로컬 객체에서 지정 main의 D 코드를 임시 디렉터리로 준비

이번 실행은 기존 임시 의존성 경로를 PYTHONPATH에 지정했다. 실행 파일·의존성 경로 및 버전은 results.json에 기록했으며 개인 경로는 공개용 사본에서 비식별화했다. 개인 경로를 다른 팀원이 그대로 사용할 필요는 없으며 아래처럼 별도 가상환경을 준비하면 된다.

## 이번 실행 결과

| 묶음 | 통과 | 실패 | 오류 | 건너뜀 |
|---|---:|---:|---:|---:|
| E v1.1 단위 22 + D↔E 통합 2 | 24 | 0 | 0 | 0 |
| E JSON v1.2 회귀 | 18 | 0 | 0 | 0 |
| 공통 실행 계층 MOCK 통합 | 19 | 0 | 0 | 0 |
| D CVSS·JSON Schema | 52 | 0 | 0 | 0 |
| 합계 | 113 | 0 | 0 | 0 |

모든 결과는 위 tested_head에서 이번에 새로 실행한 결과다. 과거 실행 로그를 재사용하지 않았다. 저장소 전체 테스트 실행 결과를 뜻하지 않으며, 요청한 네 묶음의 결과다. 각 프로세스 종료 코드는 0이다.

## 검증한 동작과 해석 범위

- v1.1 승인·허용 목록·백업·MOCK 조치·재진단·복구 회귀 통과.
- v1.2 CVSS pending/scored/not_applicable 검증, null과 0점 구분, 원본 근거 보존 확인. E의 CVSS 임의 계산이나 점수를 이용한 자동 승인은 없음.
- 최초 진단과 재진단에 동일한 테스트용 실행 계층의 execute() 사용.
- B/C 합성 결과를 D DiagnosisAggregator.from_results()로 집계한 뒤 ReportStore.save()/load()로 저장·재조회.
- E의 조치 대상 SSH-01에서 vulnerable → pass인 경우만 성공. 같은 항목의 vulnerable/error/needs_review/not_applicable은 성공 처리하지 않음. 다른 검사 항목의 상태는 별도 결과로 보존.
- target_id·OS·check_id·새 scan_id·schema_version·완료 시각 검사 및 전후 비교 확인.
- 잘못된 JSON/CVSS, 재진단·저장·조회 실패 시 MOCK 복구 확인.
- MockBackend의 정확한 타입 검사, 실제 실행 백엔드 차단, 승인 거부·Dry-run 시 콜백 미호출 유지.

콜백은 신뢰된 Python 테스트 코드의 주입 지점이며 코드 격리 샌드박스는 아니다. 실제 B/C 호출·SSH 전송·운영 환경과의 연동 검증을 의미하지 않는다.

## 전체 로그

- 01-v11-regression.log: 최신 main D를 사용한 22+2개 전체 출력
- 02-v12-regression.log: v1.2 18개 전체 출력
- 03-execution-mock.log: 실행 계층 통합 19개 전체 출력
- 04-cvss-schema.log: D 52개 전체 출력
- 05-git-comparison.log: 조상 관계, 트리 동일성 및 변경 파일 검증 명령·결과
- results.json: 실제 명령 인자, 시작·종료 시각, 환경, 건수, 백업 파일 해시

## 다른 팀원의 재현 방법

저장소 루트에서 실행한다. 본인에게 공유된 E v1.2 커밋을 준비하고 Git 객체 b4bc7e7이 존재해야 한다. 초기 검증 이후 feature/remediation-cvss-v12를 Push하고 PR #23을 제출했다. 이 문서의 과거 검증 재현에는 tested_head인 6df7caf 기준 코드와 해당 main Git 객체를 사용한다.

Windows PowerShell, Python 3.12 기준:

```powershell
python -m venv .venv-e-verify
.\.venv-e-verify\Scripts\python.exe -m pip install -r reports/e-v12-final-20261111/requirements-test.txt
.\.venv-e-verify\Scripts\python.exe -B tests/run_de_mock.py --d-ref b4bc7e7c1764e66e84367f6d34a3aee5b2a2ff37
.\.venv-e-verify\Scripts\python.exe -B -m unittest discover -s tests -p test_remediation_v12.py -v
.\.venv-e-verify\Scripts\python.exe -B -m unittest discover -s tests -p test_remediation_execution_integration.py -v
.\.venv-e-verify\Scripts\python.exe -B -m unittest discover -s tests -p 'test_cvss*.py' -v
```

가상환경 경로는 예시다. 해당 경로가 이미 있다면 새 이름을 사용한다. 생성한 가상환경은 커밋하지 않는다. 실제 검증은 results.json에 기록된 CPython 실행 파일과 임시 의존성 경로를 사용했으며, 위 명령은 다른 개발자용 동등한 실행 방법이다. Linux에서는 가상환경 실행 파일 경로를 bin/python으로 바꾸되 본 검증의 실측 OS는 Windows다.

v1.1 24개는 단순 unittest 전체 검색이 아니라 run_de_mock.py로 실행해야 한다. 이 실행기가 SECUREOPS_D_SOURCE를 설정하고 두 테스트 묶음을 별도 프로세스로 실행한다. 환경 변수 없이 통합 테스트를 직접 실행해 건너뛴 결과를 24개 통과로 계산하면 안 된다.

## 최신 main 대비 구현 변경 파일

- remediation/README.md
- remediation/__main__.py
- remediation/contract.py
- remediation/engine.py
- remediation/mock.py
- tests/run_de_mock.py
- tests/test_remediation_v12.py
- tests/test_remediation_execution_integration.py

위 8개는 기존 v1.2 구현 차이다. 이번 후속 작업은 이 디렉터리의 검증 보고서·환경·로그만 추가한다. 최종 diff에는 위 구현 8개와 검증 증거 파일이 표시되는 것이 정상이다.

## PR #16 중복 및 비의도적 변경 검사

05-git-comparison.log의 각 검사 종료 코드 0 확인:

1. main 병합 커밋이 테스트 HEAD의 조상으로 포함.
2. 통합 전후 E 전체 소스 트리 동일.
3. PR #16에서 main에 들어간 remediation 및 기존 테스트·실행기는 원래 E v1.1 브랜치와 동일.
4. 최신 main 대비 core/·checks/ 및 기존 v1.1 단위·통합 테스트 파일 변경 없음.
5. 기존 E 코드 전체를 새로 복사하거나 재추가하지 않고, v1.2 수정분만 diff로 표시.

기존 E v1.1 브랜치는 c0d3a31로 유지한다. 미추적 .bak 2개는 전후 SHA-256 동일하며 스테이징·커밋에서 제외한다. 기존 PR #16은 변경하지 않았다. 이후 PR #23을 제출했으며, 이번 후속 작업에서는 추가 Push·PR 업데이트·main 병합을 수행하지 않는다.

## 현재 제출 상태

기존 제출 PR은 [#23](https://github.com/YJH-secure/SecureOps/pull/23)이며 제출 HEAD는 7e33241이다. PR #10·#21 병합 후의 main 호환성 검증은 별도 후속 보고서로 추가한다. 이번 문서 정리와 후속 검증은 로컬에서만 진행하며 Push·PR 업데이트는 수행하지 않는다. 실제 B/C 원격 실행·공통 SSH 계약 및 D↔E 롤백·최종 상태 저장 규칙은 별도 협의 대상으로 유지한다.
