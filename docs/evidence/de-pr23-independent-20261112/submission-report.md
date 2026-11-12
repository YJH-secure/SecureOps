# D↔E JSON v1.2 독립 MOCK 최종 증거 제출

이 PR은 이미 수행한 검증 자료를 제출하는 **증거 전용 Draft**다. 제출 단계에서 테스트를 재실행하지 않았다.
실제 SSH/VM·운영 서버 조치·설정 변경은 미검증이며 Ready 전환이나 Merge를 요청하지 않는다.

## 고정 기준과 제출 기준

- D main: `62d1bf72ef52c7455bc0c2dd624206eb8350f925`.
- E PR #23: `b0ef73a1613ebc40fdd596edcbaf0413d32309b8`.
- 제출 전 fetch한 origin/main도 같은 62d1bf7이다. 검증 이후 다른 main을 재검증한 것으로 표시하지 않는다.
- 별도 제출 브랜치: `docs/de-v12-independent-evidence-jhm`.
- 기존 PR20/25 및 E feature 브랜치와 원본 로컬 증거는 보존했다.
- 기존 D/E/B/C 운영 코드·정책·기존 테스트 변경은 없다. 독립 테스트 8개 소스는 docs 아래 재현용
  스냅샷으로만 포함해 미병합 E 코드가 없는 main의 tests/ 탐색에 영향을 주지 않는다.

## D 담당자의 실제 Python 3.14 독립 실행

원래 실행 시각: 2026-11-12 09:19:14–09:19:50 KST.
Windows 11 / CPython 3.14.2 / jsonschema[format] 4.26.0.
[원래 최종 보고서](report.md), [환경·SHA·명령·결과](submission-package/python-3.14/environment-and-results.json),
[의존성](submission-package/python-3.14/dependencies.txt).

| 실행 범위 | 통과 | 실패 | 오류 | Skip |
|---|---:|---:|---:|---:|
| E 기존 조치/버전/실행 계층/연동/B 계약 | 85 | 0 | 0 | 0 |
| E 이력/승인·시각/버전 저장 | 38 | 0 | 0 | 0 |
| D CVSS·Schema | 52 | 0 | 0 | 0 |
| C 별도 FW/LOG 회귀 | 29 | 0 | 0 | 0 |
| D 독립 통합 | 8 | 0 | 0 | 0 |
| D 기존 173 + 독립 8의 결합 전체 | 181 | 0 | 0 | 0 |

처음 네 행은 E123+D52+C29=204개다. 원래 비식별 stdout과 결과 JSON은
[python-3.14/logs](submission-package/python-3.14/logs)에 있으며 import 경로/해시 증거도 함께 있다.
초기 수집기 탐색·JSON 후처리 오류는 별도 initial-harness-diagnostics/에 보존했다. 이를 최종 통과 로그로 표시하지 않았다.

### 393회 / 309개 / 중복 관계

[실제 ID 인벤토리](submission-package/test-id-inventory.json)와 [교집합 계산](submission-package/test-overlap.json)은
실행한 verbose 로그와 명령을 기준으로 만든 자료다.

- 수행 횟수: 204 + 8 + 181 = **393회**.
- 고유 테스트 ID: **309개**. 같은 ID와 소스 파일 정규화 해시를 묶은 수도 309개다.
- 204와 181 사이 교집합: **76개** = 기존 E v1.1/연동 24 + D CVSS 52.
- 독립 8개는 204와 겹치지 않으며 181 안에 전부 포함된다.
- 181에만 있는 나머지는 97개다. 즉 181 = 76 + 8 + 97.

393개를 서로 다른 테스트 393개로 부르지 않는다. 아래 E208회는 다른 작성자의 실행 증거이며 D393과 합쳐 고유 건수로 표시하지 않는다.

## E 담당자의 Python 3.12 교차 검증 — 새로 확보한 208회 자료

제공 ZIP 파일명: `04-d-cvss.zip`, SHA-256:
`6f746d38ece7738ac92c98294e6f149427988a4c690ce2c0aa316933de12cc54`.
원본 ZIP은 커밋하지 않았다. ZIP의 필요한 텍스트 증거 16개만 비식별·정규화해
[cross-check-e-python312](cross-check-e-python312)에 선별했다. 해당 스크립트를 이번 제출 단계에서 실행하지 않았다.

- E 실행 시각: 2026-11-12 09:27:11–09:27:19 KST.
- E 환경: Windows 11 / Python 3.12.14 / jsonschema[format] 4.26.0 (제공 결과 기록).
- 같은 D62d1bf7 / E b0ef73a를 사용한 것으로 기록돼 있다.
- E가 기록한 결합 트리: `6f98efbf940ef05a8d3307835a059990c408de85`.
  이 제출 단계에서 merge로 그 트리를 재구성하거나 Python 실행 바이너리 자체를 검증하지 않았다.
- 기존 회귀 204개 + 추가 MOCK 4개 = **208회 통과**, 실패·오류·Skip 0.
- 12개 원본 로그의 Ran/OK/exit code와 results.json 건수를 직접 대조했다.
- E204개 ID와 D204개 ID는 정확히 같다. 추가 4개는 verify_flow.py의 PipelineTests 사례이며 D 독립 8개와 별도다.

[E208 검증·ID 데이터](e-208-cross-check.json), [원시 로그 집계 대조](e-208-log-validation.json),
[E 원본 결과의 제출 사본](cross-check-e-python312/results.json), [E 추가 MOCK 4개 로그](cross-check-e-python312/12-full-mock-flow.log).
추가 4개는 v1.2 성공/분리 저장, 롤백 후 새 진단 연결, 롤백 후 미재진단 미확인, v1.1 호환을 검사한다.
저장소는 시나리오 중 임시로 생성·제거되므로 E ZIP에 D16/E9 스냅샷이 들어 있었다고 주장하지 않는다.

**과거 패키지와의 시간 구분:** submission-package/의 README·비교 JSON에는 당시 E204 전체 로그가 없다는 설명이 남아 있다.
그 자료는 기존 패키지의 역사적 스냅샷이다. 이번 제출 준비에서 위 ZIP을 새로 확보해 208회 근거를 확인했고
현재 교차 검증 판단은 본 문서와 e-208-cross-check.json에 추가했다. 과거 184개 공개 로그를 208개로 바꾼 것이 아니다.

D 노트북에는 Python 3.12 실행기가 없어 D 담당자의 로컬 3.12 재실행은 여전히 미실행이다.
E가 제공한 3.12 실행 증거와 D의 3.14 독립 실행 증거를 구분한다.

## 보고서·이력 저장 및 실패 상태

[D 진단 보고서 16개](submission-package/python-3.14/d-diagnoses)와
[E 실행 이력 9개](submission-package/python-3.14/e-executions)는 서로 다른 디렉터리다.
[scan ID 연결 및 새 프로세스 재조회](submission-package/scan-links-and-reload.json),
[독립 시나리오 원본 JSON](submission-package/python-3.14/independent-results.json).

- execution_id, plan_id, 승인된 approval_id와 before/after/post_rollback_scan_id를 별도로 확인했다.
- E 이력 schema_version=1.0 / diagnosis_schema_version=1.1 또는 1.2 / D 보고서 버전을 혼용하지 않는다.
- 핵심 7개 사례는 before와 생성된 after/post 보고서를 모두 보존했다. 버전 호환 두 사례는 after와 E 이력만
  보존했으며, 패키지에 없는 before 스냅샷을 재조회한 것으로 표시하지 않았다.
- 롤백 후 재진단이 없으면 final_security_status=null, final_security_verified=false다.
- D save 성공 후 load 실패에서도 scan ID를 보유하고 재조회할 수 있다. E outcome=failed와 최종 미확인을 유지한다.
- 롤백 후 별도 합성 pass 진단을 얻어도 원래 조치 outcome=failed를 success로 바꾸지 않는다.
- D before 원본 바이트와 중복 scan_id/execution_id의 기존 저장물을 보존했다.

## 재현·원본과 제출본의 차이

원래 worker 명령·실행 환경은 각 결과 JSON/로그에 있다. 재현 입력과 기존 소스 스냅샷 위치는
[reproduction-inputs.json](submission-package/reproduction-inputs.json)을 참조한다.
독립 테스트 스냅샷을 별도 고정 D checkout의 지정 경로에 복원하고 별도 E checkout을 준비한 뒤 실행해야 한다.
현재 증거 PR 자체를 운영 코드 결합이나 자동 테스트 등록으로 사용하지 않는다.

```powershell
<D_PYTHON314> -B -X utf8 docs/evidence/de-pr23-independent-20261112/run-review.py --e-root <E_CHECKOUT> --output-dir <NEW_OUTPUT>
```

E 측 두 재현 스크립트는 제공 ZIP의 자료이며 원래 임시 결합 checkout을 전제로 한다.
자동 실행하지 않았고 현재 main/E 브랜치에 merge/rebase하지 않았다.

[원본→선별 제출 전송 명세](source-transfer-manifest.json)와 publication-normalization.json에 파일별 해시·정리 범위를 기록한다.
비식별 대상은 개인 로컬 경로·실제 내부 IP 등이며, 로그의 결과 수치·SHA·시각·진단/이력 내용은 바꾸지 않는다.
UTF-8/LF와 후행 공백 정리로 바이트 해시가 달라질 수 있다. 과거 패키지 해시는 당시 원본을 뜻하며
현재 제출 파일의 실제 해시는 submission-file-hashes.json에서 확인한다. 원본 로컬 파일과 ZIP은 보존했다.
원래 최종 보고서의 제출 사본에서는 상대 링크만 현재 선별 경로로 조정했다.

## 미완료 및 병합 경계

실제 SSH/VM, 운영 서버 조치·복구, Rocky 실환경 및 E2E는 미검증이다.
MockRecheckAdapter는 E 전용 MOCK 격리이며 실제 공통 원격 실행 계약 인수와 다르다.
E 이력은 명시적 save(result)가 필요하다. 운영 호출부의 저장 책임, 경로/권한/보관·하드링크·장애 복구 정책은 협의가 남는다.
파일 저장소를 암호화·서명 기반 감사 저장소로 표현하지 않는다.
팀장님이 증거와 E 코드를 검토한 뒤 최종 병합을 결정한다. 본 PR은 Draft로 유지하며 Ready 전환·Merge하지 않는다.
