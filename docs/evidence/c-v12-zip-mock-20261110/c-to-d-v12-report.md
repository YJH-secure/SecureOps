# C ZIP → D JSON v1.2 오프라인 통합 검증

2026-11-10 KST. 이 기록은 제공 ZIP의 실제 판정 함수와 v1.2 어댑터를 사용한 MOCK 연동이다.
실제 SSH/VM을 사용하거나 C ZIP을 공식 Git 소스로 인증한 검증이 아니다.

## 1. 기준과 격리

- PR #19는 작업 시작 조회 시 main에 병합된 상태였다.
- PR #19 HEAD: 8ae2ca1ba09f45c6b0f4a6c49a6a1572f0caca95.
- 최신 origin/main 및 이번 D Worktree HEAD: f7e4f16d94e68e408087de2cf34a9337a4f63ddf.
- 두 Commit 사이 core/ 및 tests/의 내용 차이가 없음을 확인했다.
- 별도 브랜치: feature/c-d-v12-mock-review.
- Worktree: C:/Users/Public/Documents/ESTsoft/CreatorTemp/SecureOps-c-d-v12-review-b04a33f827.
- C ZIP은 별도 디렉터리에 해제했다. 기존 checks/account, checks/system 및 PR #19 Worktree를 덮어쓰지 않았다.
- ZIP: SecureOps_C_v12_VM.zip.
- SHA-256: **636bca49f28eca129ad973fd0479d7d8b87acc7513ec7fa41b2b4485781999c8**.
- 공식 C 커밋은 제공받지 않았다. 모든 C 출처는 ZIP 해시와 추출 파일별 해시로 기록한다.

57개 항목, 비압축 총 268,608바이트를 확인했다.
절대/상위 경로·드라이브·심볼릭 링크·대소문자 중복·Windows 예약 이름·암호화·크기/압축률을 검사하고
새 디렉터리에만 해제했다. CRC 읽기 및 추출 파일 해시 대조가 통과했다.
[ZIP 검사 및 파일 해시](zip-inspection.json), [실행 환경 및 소스 해시](environment-and-results.json).

## 2. 호출 경로와 합성 입력

실제 C 진단 함수 → 실제 C adapt_result(result, "1.2") → JSON 문자열 →
D parse_result_json(schema_version="1.2", exit_code=0, execution_succeeded=True) →
run_target(mode="mock", schema_version="1.2") → 집계·저장·load·DiagnosisAggregator 재조회.

| 모듈 | 실제 함수 | 합성 관측 |
|---|---|---|
| FILE-01 | file_check.run + result_adapter.adapt_result | ZIP의 Ubuntu 파일 정책. passwd 0666/기본 ACL, shadow 0640/GID 42 등 synthetic collector |
| SVC-01 | service_check.run_from_policy + adapter | ZIP 기본 서비스 정책, 합성 active/unit-file/socket 출력, loopback 8080, 합성 OS/호스트/역할 |
| FW-01 | firewall_check.run_from_policy + adapter | ZIP 기본 방화벽 정책, 합성 ufw active/default deny, nft metainfo, loopback listener |
| LOG-01 | log_check.run_from_policy + adapter | ZIP 기본 로그 정책, 합성 unit/journald/path metadata 및 비어 있는 임시 설정 트리. journal usage에 PermissionError 주입 |

합성 정책 승인을 새로 만들거나 C 정책을 수정하지 않았다.
FILE의 판정은 ZIP 내부 정책의 실제 규칙에 따른 결과이며 운영 정책 승인 완료를 의미하지 않는다.
SVC/FW/LOG의 기본 policies는 비어 있어 보류 또는 수집 오류를 표현한다. 이를 정상/pass로 꾸미지 않았다.
OS/호스트 식별과 명령 출력·파일 메타데이터는 수집 입력 경계에서만 제공했다.
실제 판정 함수·결과 객체를 Mock 반환값으로 대체하지 않았다.
subprocess.Popen/os.system/socket.socket 및 live 수집 fallback은 차단했다.
ZIP의 verify_v12_vm.py는 실행하지 않았다.

## 3. C 4개 결과 수신과 집계

| 항목 | C 진단 status | C CVSS 상태 | 점수·등급 | D 수신/저장/재조회 |
|---|---|---|---|---|
| FILE-01 | vulnerable | pending | null/null | 일치 |
| SVC-01 | needs_review | not_applicable | null/null | 일치 |
| FW-01 | needs_review | not_applicable | null/null | 일치 |
| LOG-01 | error | not_applicable | null/null | 일치 |

진단 합계 4개: vulnerable 1, error 1, needs_review 2, pass 0.
평가 가능 분모는 1이고 양호 이행률은 0.0%이다.
CVSS 상태는 scored 0 / pending 1 / not_applicable 3이며 모든 등급별 취약 건수는 0이다.
null을 0.0점으로 바꾸지 않았다.

status/evidence/recommendation 및 details를 C 원본과 비교했다.
C v1.2 어댑터가 제거한 severity 외의 기존 필드는 동일했고, FILE 중첩 details의 복사 독립성과 저장 원본 보존도 통과했다.
[C v1.1/v1.2 실제 결과 및 D 보고서·집계](c-results-and-d-summary.json).

실제 D ReportStore로 저장한 v1.1/v1.2 보고서를 다시 load하여 동일함을 확인했다.
[영구 저장 보고서 경로 및 검증](saved-report-verification.json).
saved-reports/의 JSON은 위 실제 저장 파일이다.

## 4. 진단 오류와 실행 실패 구분

- 유효한 error JSON + 종료 코드 0 + 명시적 실행 성공은 진단 오류로 수신·집계했다.
- 종료 코드 1/255 또는 execution_succeeded=False는 같은 정상 JSON이라도 RemoteResultError로 거부했다.
  runner는 RunFailed를 발생시키고 보고서를 저장하지 않았다.
- 빈/깨진/배열/로그 혼합/다중 문서/중복 키 JSON도 거부했다.
- pending에 숫자 점수 입력, bool 점수, 잘못된 평가 상태·Vector·빈 rationale을 거부했다.
- 공식 계산용 기존 D MOCK에서 점수를 9.7로 바꾼 음성 입력은 Vector/점수 불일치로 거부했다.
  이는 검증용 음성 데이터이며 C가 생성한 결과라고 표시하지 않았다.

추가로 실제 C main()을 네 모듈 × v1.1 기본/v1.2 선택의 8개 호출로 검사했다.
수집 실패 입력만 주입하고 실제 main/진단/어댑터를 실행했다.
8회 모두 반환 코드 0과 status=error JSON을 출력했고 D가 동일하게 수신했다.
버전별 4개 오류 결과를 통합·저장·재조회했으며 error_count=4, 이행률 N/A였다.
LOG CLI의 설정 탐색도 합성 입력으로 제공하여 호스트 /etc를 탐색하지 않았다.
[추가 CLI 결과](cli-error-validation.json), [추가 CLI 확인 로그](logs/04-actual-c-cli-errors.log).
이 8개 호출은 unittest 메서드 수에 합산하지 않는다.

## 5. v1.1/v1.2 및 CVSS 범위

- C adapt_result의 기본값과 C CLI 인자 기본값은 1.1이다. D 기본 수신·runner도 1.1이다.
- v1.1은 severity를 보존하며 기존 경로로 저장·조회됐다.
- C v1.2와 D v1.2는 각각 명시적으로 선택해야 한다. 개별 C 객체에는 최상위 schema_version을 넣지 않는다.
- C 어댑터는 CVSS 메트릭이나 점수를 생성하지 않는다. vulnerable은 pending, 그 외는 not_applicable이다.
- 따라서 이 C ZIP에서 실제 scored 결과를 수신했다고 주장하지 않는다.
- scored는 기존 D 공식 계산용 MOCK을 별도 테스트에서 검증했다. 9.8 Critical이 유효했고 불일치 점수는 거부됐다.
  이 MOCK을 C의 네 결과 보고서에 섞지 않았다.
- 기존 FIRST 공식 5개 사례, Roundup, null/0.0 구분은 전체 회귀에서 유지됐다.

## 6. 실제 테스트 결과와 환경

Windows 11 / AMD64 / CPython 3.14.2 / jsonschema 4.25.1.
최종 자동 실행: 2026-11-10 19:02:53~19:02:57 KST.

| 실행 | 발견 | 통과 | 건너뜀 | 실패 | 오류 | 로그 |
|---|---:|---:|---:|---:|---:|---|
| C ZIP → D 전용 | 9 | 9 | 0 | 0 | 0 | [01](logs/01-c-zip-to-d.log) |
| 소스 미제공 D 전체 | 158 | 136 | 22 | 0 | 0 | [02](logs/02-default-full.log) |
| 전체 외부 소스 제공 | 158 | 158 | 0 | 0 | 0 | [03](logs/03-full-all-offline.log) |

158개는 기존 D 149개 + 신규 C ZIP 9개이다.
22개 skip은 과거 B/C 3개 + 최신 B 10개 + C ZIP 9개의 소스 부재다.
전체 제공 실행은 과거 B/C 고정 커밋, 최신 B 커밋 및 C ZIP을 별도 환경변수로 분리했다.
기존 D CVSS 52개 및 v1.1 84개를 수정하지 않고 재실행했다.
ZIP 문서에 기재된 C 자체 163개 단위 테스트를 이번에 실행했다고 주장하지 않는다.

첫 개발용 집중 실행은 LOG 임시 설정 메타데이터 접근까지 새 테스트 가드가 막아 9개 메서드에서 실패 이벤트 14개를 보였다.
새 D 테스트에서 해당 입력 경계를 합성 폴더 안으로 한정해 제공하도록 고쳤다. C/D 운영 코드는 변경하지 않았다.
첫 실행의 전체 로그는 보관되지 않았으며 이 사실과 원인은 환경 기록에 표시했다.
위 표는 수정 후 실제 새 프로세스의 최종 실행 결과다.

재현 명령:

```powershell
python -B -X utf8 docs/evidence/c-v12-zip-mock-20261110/run-c-zip-evidence.py --c-source-root <C_ZIP_SOURCE_ROOT>
```

이 스크립트는 제공 ZIP의 해시 및 추출 내용이 일치하는지 확인하고, 증거가 이미 있으면 덮어쓰지 않는다.
추가 CLI 검증은 별도의 Python 입력 프로세스로 실행했다. 기존 C main에 입력 collector만 주입했으며 결과 JSON에 실제 반환 코드를 기록했다.

## 7. 남은 사항 및 인터페이스

현재 제공된 C v1.2 어댑터와 D는 운영 소스 수정 없이 호환됐다.
중앙 실행 계층에서 C의 --result-version 1.2와 D의 schema_version=1.2 선택을 일치시키면 된다.
전송 성공과 진단 status=error를 구분하는 종료 코드·execution_succeeded 매핑이 필요하다.

추가 확인 사항:

- 공식 C Git 브랜치/커밋 SHA 제공과 ZIP 내용의 일치 여부. 이 ZIP을 정식 Git 기준선으로 표시하지 않는다.
- C의 실제 scored 평가에 필요한 메트릭·공격 조건·영향 근거. 현재는 미평가 null이 정상 출력이다.
- LOG metadata_reader는 로그 경로 메타데이터에만 적용되고 설정 탐색은 path_metadata를 직접 호출한다.
  오프라인 입력 주입 시 별도 합성 config_root/입력 경계가 필요했다. 이번에는 테스트에서만 처리했다.
- FILE 및 서비스·방화벽·로그의 운영 정책 승인, 실제 OS별 관측 및 접근성 검증.
- 실제 SSH/VM 연결, C의 VM 검증 스크립트, Linux 실환경 및 E 연계는 미실행이다.

이 브랜치는 테스트 및 신규 증거만 추가했다. 기존 PR #19, C 소스·정책·공통 SSH·D Core·CVSS 계산기는 변경하지 않았다.
Commit·Push·PR 생성·Merge는 수행하지 않았다.
