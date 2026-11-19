# D 담당 독립 검증 — E PR #23 JSON v1.2 최종 MOCK

## 검증 기준

- 공식 D main: `62d1bf72ef52c7455bc0c2dd624206eb8350f925`.
  PR #29 fixture 수정과 PR #27 공식 C v1.2가 병합된 상태다.
- E PR #23 HEAD: `b0ef73a1613ebc40fdd596edcbaf0413d32309b8`.
- E 기능 기준 `7730f4ff6d8fc666bd68093f072e7971c79e358a`에서 제출 HEAD까지는 remediation/README.md만 변경됐다.
- 두 소스를 별도 Worktree로 고정했다. D 검증 브랜치: `feature/d-e-v12-independent-review-jhm`.
- 기존 PR20 HEAD 0ed1c5e, PR25 HEAD 34ebff6과 이전 검증 자료는 변경하지 않았다.
- 검증 당시 PR23은 미병합이고 최종 재조회 HEAD도 b0ef73a로 동일했다.

Git blob과 실제 tracked 파일 내용을 CRLF/LF 정규화 후 대조했고, 실행 전후 tracked 파일 해시도 일치했다.
기존 D/E 테스트나 운영 코드를 복사·수정해 결합하지 않았다. 테스트 프로세스에서 공식 D core와
PR23 remediation 패키지를 선택하고 실제 import 파일 경로·SHA-256을 그룹별 imports JSON으로 기록했다.
기존 E CLI 테스트의 자식 프로세스에도 임시 sitecustomize를 통해 동일한 D/E 소스 선택을 적용했다.

## 실제 최종 환경·결과

2026-11-12 09:19:14–09:19:50 KST.
Windows 11 / CPython 3.14.2 / 별도 가상환경 / E 지정 `jsonschema[format]==4.26.0`.
E 측 기존 보고 환경인 Python 3.12.14와 다른 독립 환경이며 Linux 실환경 결과로 표시하지 않는다.
[전체 의존성](submission-package/python-3.14/dependencies.txt), [환경·실행 명령·해시](submission-package/python-3.14/environment-and-results.json).

| 범위 | 통과 | 실패 | 오류 | Skip | 로그 |
|---|---:|---:|---:|---:|---|
| 기존 E 조치·v1.1/v1.2·D 통합·B 계약 | 85 | 0 | 0 | 0 | [01](submission-package/python-3.14/logs/01-e-remediation.log) |
| 기존 E 이력 저장·승인/시간·버전 | 38 | 0 | 0 | 0 | [02](submission-package/python-3.14/logs/02-e-history.log) |
| 최신 D CVSS·JSON Schema | 52 | 0 | 0 | 0 | [03](submission-package/python-3.14/logs/03-d-cvss.log) |
| C FW/LOG 별도 회귀 | 29 | 0 | 0 | 0 | [04](submission-package/python-3.14/logs/04-c-fw-log.log) |
| D 작성 독립 검증 | 8 | 0 | 0 | 0 | [05](submission-package/python-3.14/logs/05-independent.log) |
| 최신 main 기존 테스트 + 독립 8개, E PR23 결합 | 181 | 0 | 0 | 0 | [06](submission-package/python-3.14/logs/06-d-full.log) |

E 기존 123개 + D 52개 + C 29개 = E가 보고한 204개 범위를 새 프로세스로 재확인했다.
이 중 E/D는 175개, C는 별도 29개다. 독립 8개를 더한 앞 다섯 실행은 212회 통과다.
마지막 181개 실행은 최신 main의 기존 173개와 독립 8개이며 앞 실행과 중복된다.
이를 합쳐 서로 다른 테스트 393개로 표현하지 않는다. 어느 최종 실행에도 실패·오류·Skip은 없다.
SECUREOPS_D_SOURCE를 현재 공식 D에 지정했으므로 기존 v1.1 D↔E 클래스도 건너뛰지 않았다.

## 요청 항목 6개 검증축

요청 절차 4–11을 아래 여섯 축으로 묶었다. 모두 실제 MOCK 실행 범위의 통과이며 운영 서버 검증과 구분한다.

| 축 | 판정 | 독립 확인 |
|---|---|---|
| 1. v1.2 입력 → 계획·승인·식별자 | 통과 | 실제 build_plan/Remediator.run 사용, plan_id 일치, 검증된 approval_id 연결, execution_id별 시도 연결. 거부/Dry-run approval_id=null 및 무재진단 |
| 2. 공통 실행 계층 역할 콜백 → D 검증·저장·재조회 | 통과 | E 기존 MockRecheckAdapter와 diagnose fixture 재사용, 실제 D ReportStore, save/load 성공과 원본 일치·집계 확인 |
| 3. E/D 버전 분리·v1.1/v1.2·CVSS | 통과 | E schema_version=1.0, diagnosis_schema_version=1.1/1.2와 D 보고서 버전 일치. 상호 저장소 혼용 거부, pending/not_applicable null·scored/0점 구분은 기존 E/D 회귀 포함 |
| 4. 실패·롤백·기존 보고서 불변·미확인 | 통과 | 기존 before 보고서 바이트 불변, rollback=verified만으로 보안 pass 판정 안 함. 재진단 없으면 final_security_status=null, verified=false |
| 5. 롤백 후 별도 진단 연결 | 통과 | before/after/post_rollback의 세 scan ID 구분. 복구 후 pass여도 원래 outcome=failed 유지 |
| 6. save 성공 후 load 실패 | 통과 | after_scan_id 유지, save=success/load=failed, 후속 같은 ID 조회 성공. E outcome=failed와 최종 미확인 유지. post_rollback의 두 번째 load 실패도 확인 |

독립 테스트는 E 기존 ExecutionHistoryTests fixture와 공개 인터페이스를 재사용하고 D 관점의 단언을 별도로 추가했다.
기존 테스트의 assert를 변경·완화하거나 실패를 Skip 처리하지 않았다.
네트워크/외부 명령은 독립 시나리오에서 차단했고 E는 정확한 MockBackend만 허용한다.
버전 호환 사례는 E의 기존 _run_demo MOCK 경로를 사용한다. 실제 서버 변경을 수행하지 않는다.

## 실제 보고서와 실행 이력 연결

[독립 결과](submission-package/python-3.14/independent-results.json)에 9개 실행 사례를 보존했다.
[D 진단 16개](submission-package/python-3.14/d-diagnoses)와 [E 실행 이력 9개](submission-package/python-3.14/e-executions)는 별도 디렉터리에 저장했다.
새 Python 프로세스에서도 모두 재조회해 JSON 동등성을 확인했다([새 프로세스 검증](submission-package/python-3.14/cross-process-verification.json)).

| 사례 | outcome | rollback | 최종 보안 상태 | 보안 확인 |
|---|---|---|---|---|
| 승인된 조치·D 재진단 성공 | success | not_needed | pass | true |
| 승인 없음 | rejected | not_needed | null | false |
| Dry-run | planned | not_needed | null | false |
| 조치 후 미개선·롤백, 후속 진단 없음 | failed | verified | null | false |
| 롤백 후 별도 합성 pass 진단 | failed | verified | pass | true |
| after 저장 성공·조회 실패 | failed | verified | null | false |
| post_rollback 저장 성공·조회 실패 | failed | verified | null | false |
| v1.1/v1.2 호환 사례 각 1개 | success | not_needed | pass | true |

핵심 7개 사례에는 D before 및 생성된 after/post 보고서를 모두 보존했다.
버전 호환 두 사례의 파일 증거는 after 보고서와 E 이력이다. 해당 _run_demo 내부 before 보고서를
별도 저장한 것으로 표시하지 않는다. v1.1 before/after 저장 연결은 기존 E D 통합 테스트에서도 통과했다.

after 조회가 실패한 사례에서 이후 D 보고서를 읽으면 pass가 나온다. 이 값은 롤백 전 진단이며
E가 이를 복구 후 최종 상태로 승격하지 않았음을 확인했다.
롤백 후 pass 사례는 MOCK callback의 결과를 주입한 제어 흐름 검증이며 실제 복구의 보안 효과를 의미하지 않는다.

ExecutionHistoryStore는 호출자가 명시적으로 save(result)해야 한다. 이번 증거 저장도 실행 후 별도로 호출했다.
동일 execution_id와 scan_id 재저장 충돌 시 이전 바이트 보존을 독립 테스트에서 확인했다.
D에 E 실행 이력 저장 엔진을 중복 구현하지 않았다.

## 명령과 재현

E 원본의 고정 요구사항을 새 가상환경에 설치했다.

```powershell
python -m venv <NEW_REVIEW_VENV>
<REVIEW_PYTHON> -m pip install -r <E_PR23>/reports/e-v12-pr23-feedback-20261111/requirements-test.txt
<REVIEW_PYTHON> -B -X utf8 docs/evidence/de-pr23-independent-20261112/run-review.py --e-root <E_PR23> --output-dir <NEW_EVIDENCE_OUTPUT>
```

runner의 worker는 기존 unittest discovery와 원본 테스트를 그대로 사용한다.
E: test_remediation*.py, test_execution_history*.py; D: test_cvss*.py; C: firewall/log 테스트;
독립: test_de_pr23_independent.py; 전체: 최신 D tests/의 test*.py를 각각 새 프로세스로 실행한다.
정확한 worker 명령과 환경은 최종 JSON/로그에 기록했다. 출력 경로가 이미 실행된 경우 덮어쓰지 않는다.

## 초기 증거 수집기 오류의 구분

루트 logs/와 environment-and-results.json은 최초 jsonschema 4.25.1 환경의 실행 기록으로 보존했다.
E 85+38, C 29개와 독립 8개의 테스트 단언은 통과했으나 다음 수집기 오류가 있었다.

1. D/E 양쪽에 같은 테스트 파일명이 있어 E tests/가 우선인 sys.path로 D discovery가 중단됐다.
   새 수집기의 선택 suite 디렉터리를 먼저 배치해 해결했다. 실제 D/E 운영 모듈 경로는 초기에도 확인했다.
2. 독립 단언 8개 통과 후 Dry-run E 이력의 tuple→JSON 배열 정규화를 Python 객체 그대로 비교해 후처리가 중단됐다.
   E 저장소가 명시한 JSON 직렬화 계약대로 완전한 JSON 동등성을 확인하도록 수집기만 수정했다.
   기존 E 테스트 기대값이나 운영 계약을 완화하지 않았다.

초기 중단을 E 제품 오류나 최종 통과로 표시하지 않았다. final/은 수집기 보정과 정확한 E 요구 의존성을 적용한 새 실행이다.
모든 최종 worker의 exit code가 0이고 import 경로 증거도 남겼다.

## 문제·협의·미검증

이번 고정 커밋 조합의 요청 MOCK 범위에서는 E 운영 코드 수정이 필요한 실패를 발견하지 않았다.
운영 단계로 넘어가기 위한 별도 협의는 남는다.

- MockRecheckAdapter는 E가 격리한 임시 MOCK 연결이다. 팀장 공통 실행 계층의 실제 계약 인수를 뜻하지 않는다.
- E 이력 저장은 명시적 호출이며 운영 호출부가 성공·거부·실패 결과 저장을 책임져야 한다.
- D/E 저장 디렉터리 분리, 권한·보관·하드링크 지원·장애 복구 정책은 운영 환경에서 별도 승인 필요.
- 파일 저장소는 암호화·서명 기반 감사 저장소가 아니며 실제 Windows/Linux 운영 권한을 검증한 결과가 아니다.
- 실제 SSH·VM, 실제 변경/복구, Rocky 및 운영 E2E는 미검증이다. 임의 backend는 E가 거부한다.
- 실행한 Python은 3.14.2다. E 측 3.12.14/대상 OS 환경과 동일하다고 주장하지 않는다.

PR23 승인/병합은 팀장이 결정한다. Commit·Push·PR 생성·수정·Merge는 수행하지 않았다.
기존 D Core/ReportStore/B/C/공통 SSH/E 코드 및 테스트를 수정하지 않았고, 새 독립 테스트·증거만 추가했다.
