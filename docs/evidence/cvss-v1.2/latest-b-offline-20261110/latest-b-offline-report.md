# PR #19 보완: 최신 B SSH-01 → D v1.1 오프라인 연동

실행일: 2026-11-10 KST. 기존 CVSS·main 재검증·과거 실패 기록은 수정하지 않고 신규 증거를 추가했다.

## 기준 및 보존

- 작업 브랜치: feature/cvss-core-jhm-main-review.
- 작업 시작 HEAD: f35d07b43ec13d185df0bf1d8cdf13ddbc64f26a, 기존 PR #19 Commit.
- 작업 시작 Git 상태: 깨끗함. 보존해야 할 미커밋 코드·증거 변경은 없었다.
- git fetch origin feature/account-check-cjw 수행 후 FETCH_HEAD와 origin/feature/account-check-cjw가 일치했다.
- 최신 B 커밋: **3eda5a56ed3e9fd56d162676507c526ea0d1a1c1**.
- B source/정책/단위 테스트를 위 커밋에서 임시 경로로 읽어 사용했다. D checkout의 checks/account에 복사하지 않았다.
- 기존 추적 파일 전체의 실행 전후 SHA-256이 동일했다. CVSS 계산기·v1.1 검증기·기존 테스트·과거 증거는 변경하지 않았다.
- 변경 사항은 신규 D 테스트 1개와 이 증거 디렉터리뿐이다. Commit·Push·PR 수정·Merge는 수행하지 않았다.

## 정책 출처와 승인 표기

정책 사본: [source-policy.json](source-policy.json). 원본 출처:
[B 정책](https://github.com/YJH-secure/SecureOps/blob/3eda5a56ed3e9fd56d162676507c526ea0d1a1c1/checks/account/policies/ssh_policy.json).
사본은 원본 바이트와 동일하며 SHA-256은 [환경 기록](environment-and-results.json)에 있다.
policy_version=1.0은 정책 JSON 형식 버전이며 결과 JSON v1.1 및 CVSS v1.2와 별개다.
정책의 192.0.2.10은 문서용 예시 주소이고 실제 서버에 연결하지 않았다.

B 정책 reference, 코드·단위 테스트 주석 및 [PR #10 본문](https://github.com/YJH-secure/SecureOps/pull/10)은
2026-11-09 팀장 승인 기준이라고 명시한다. main의 취약점 기준표 v1.1에도 같은 판정 조건이 있다.
다만 오래된 docs/project-status.md에는 SSH-01 승인/PR 검토 대기 문구가 남아 있고,
조회한 PR #10 댓글에는 팀장 계정의 별도 승인 기록이 없었다.
따라서 여기서는 **B가 승인 반영으로 명시한 현행 정책에 대한 구현·연동 정합성**을 검증했다.
정책의 운영 승인이나 main 문서의 상태를 새로 확정하지 않았으며, 문서 간 승인 상태 정리는 팀장 확인 사항이다.

## 실제 인터페이스 검증

| 항목 | 확인 내용 |
|---|---|
| vulnerable_values | 비어 있지 않은 dict. 각 설정값과 위반 사유는 비어 있지 않은 문자열 |
| 충돌 검사 | expected를 소문자로 비교했을 때 vulnerable_values의 키와 같으면 ValueError |
| test_connection | user/host/addr 모두 비어 있지 않은 문자열. 쉼표·공백 금지, user는 정확히 root |
| 실제 함수 | check_ssh_01(policy, sshd_output, config_text="", root_output=None) |
| 정책 검증 경계 | check_ssh_01 내부는 정책 검증을 자동 호출하지 않는다. 테스트가 실제 B load_policy/validate_policy를 먼저 호출 |
| 정상 | no → pass |
| 취약 | yes/prohibit-password/without-password/forced-commands-only → vulnerable |
| 수집 관측 부재 | None/빈 출력/설정값 누락 → error |
| Match + root_output 부재 | root 관련 Match의 유효 설정을 확인할 수 없으면 needs_review |
| root_output 제공 | root 조건에서 확인한 값을 사용. root 출력이 잘못되면 error |
| 조건부 Match | root 값이 no여도 다른 주소·사용자 조합에서 허용 가능성이 남으면 needs_review |
| 반환 | check_id, status, severity, evidence, recommendation의 v1.1 객체. CVSS 생성 없음 |

인터페이스 전용 문서는 B 브랜치에서 발견되지 않았다. 실제 코드 docstring, 정책 reference,
B 단위 테스트와 PR #10 설명을 근거로 확인했다.

## 신규 D 테스트

파일: tests/test_latest_b_offline_integration.py, unittest 메서드 10개.
SECUREOPS_LATEST_B_SOURCE_ROOT를 사용하여 기존 SECUREOPS_B_SOURCE_ROOT의 과거 B/C 회귀와 분리했다.
소스/정책이 없는 환경에서는 이유를 표시해 건너뛴다.
예전의 수작업 정책 dict를 재사용하지 않고 최신 B의 실제 load_policy로 정책을 로드했다.

검증 사례:

1. 최신 정책 로딩·검증 및 함수의 실제 인자·기본값.
2. no 정상 설정.
3. 정책 JSON에 정의된 취약 값 4개와 각 위반 사유.
4. None·빈 값·공백·필수 설정 누락의 error.
5. Match User root가 있지만 root_output이 없는 needs_review.
6. root_output에서 허용/차단이 확인된 경우와 잘못된 root 출력.
7. Address와 User Match가 겹치는 조건의 보류·명시적 취약·전면 차단.
8. vulnerable_values 누락·타입·빈 값·사유 오류·expected 충돌.
9. test_connection의 필수 키·root 조건·쉼표/공백 오류.
10. 같은 SSH-01의 조치 전후 합성 결과 저장·이력·check_id 연결.

실제 판정 함수는 Mock으로 바꾸지 않았다. B의 수집 진입점과 subprocess.Popen/os.system/socket.socket을
호출하면 실패하도록 차단하고 미호출을 확인했다. B의 원본 단위 테스트도 수정 없이 별도로 실행했다.
그 단위 테스트가 원래 제공하는 수집 mock은 그대로이며 테스트를 통과시키기 위한 우회는 추가하지 않았다.

## B 결과 및 D 통합 증거

[latest-b-cases.json](latest-b-cases.json)에 합성 입력, B 실제 결과, D 보고서·집계를 기록했다.
각 유효 결과는 다음 경로를 통과했다.

실제 B validate_policy/check_ssh_01 → JSON 문자열 → D parse_result_json(v1.1) →
run_target(mode=mock, schema_version=1.1) → 집계 → ReportStore 저장·load → DiagnosisAggregator 재조회.

유효 결과 **19건**: pass 4 / vulnerable 7 / error 5 / needs_review 3.
이는 10개 unittest 메서드 내의 subTest/시나리오 수이며 별도 테스트 건수로 합산하지 않는다.
각 사례의 status/severity/evidence/recommendation/check_id를 원본과 비교했고 입력 정책도 변경되지 않았다.
scanned_at 등 D 실행 메타데이터는 합성이며, 개별 B 결과에는 임의 필드를 넣지 않았다.
B의 현행 반환값에는 details가 없으므로 새 details를 꾸며 넣지 않았다.
기존 FILE-01 details 보존은 기존 회귀 테스트에서 재확인했다.

단일 결과 집계는 pass=100.0%, vulnerable=0.0%, error/needs_review=N/A이다.
오류·보류는 pass가 되지 않고 이행률 분모에서 제외됐다.
잘못된 정책 **17건**은 실제 B validate_policy의 ValueError로 D 실행 전 거부했고, 보고서를 저장하지 않았다.
정책 오류 경로도 latest-b-cases.json에 별도 기록했다.

JSON 수신의 exit_code=0/execution_succeeded=True는 합성 성공 실행 메타데이터다.
진단 status=error는 수집 실패를 표현하는 유효한 v1.1 결과이며 실행 전송 실패와 구분했다.
실제 원격 프로세스나 종료 코드를 관측했다고 주장하지 않는다.

## 환경·실행 결과

Windows 11 / AMD64 / CPython 3.14.2 / unittest / jsonschema 4.25.1.
정확한 명령·시각·소스 해시 및 stdout 해시는 [환경 기록](environment-and-results.json)에 있다.
신규 로그는 UTF-8과 LF로 기록했으며 과거 로그는 수정하지 않았다.

| 실행 | 발견 | 통과 | 건너뜀 | 실패/오류 | 로그 |
|---|---:|---:|---:|---:|---|
| 최신 B → D 통합 | 10 | 10 | 0 | 0/0 | [01](logs/01-latest-b-to-d.log) |
| B 기존 단위 테스트 | 34 | 34 | 0 | 0/0 | [02](logs/02-b-unit-unchanged.log) |
| 기존 CVSS/v1.2 | 52 | 52 | 0 | 0/0 | [03](logs/03-cvss-regression.log) |
| 기존 v1.1 Core | 70 | 70 | 0 | 0/0 | [04](logs/04-v11-core-regression.log) |
| 기존 v1.1 원격 JSON | 14 | 14 | 0 | 0/0 | [05](logs/05-v11-remote-regression.log) |
| 과거 고정 B/C | 3 | 3 | 0 | 0/0 | [06](logs/06-pinned-bc-regression.log) |
| 소스 미제공 전체 | 149 | 136 | 13 | 0/0 | [07](logs/07-full-without-bc.log) |
| 고정 B/C + 별도 최신 B 전체 | 149 | 149 | 0 | 0/0 | [08](logs/08-full-pinned-bc-and-latest-b.log) |

B 단위 테스트 34개는 D의 149개 검색 범위 밖에서 실행했으므로 전체 149개에 포함하지 않는다.
이전 D 139개에 최신 B 테스트 10개를 추가하여 149개다.
미제공 환경의 skip 13개는 과거 B/C 3개와 최신 B 10개로 구분된다.
FIRST 공식 사례 5개 및 PR #18 MOCK 9.8 Critical은 기존 CVSS 테스트 그대로 재실행해 통과했다.

고정 B/C는 B cfbd37b4dbd102ec894a2150d47f751ad5c74afa 및 C 6bb330feccfc6541bc145db9b6e18f24b4bce394이다.
전체 실행에서 과거 B/C 테스트는 이 고정 소스를 사용하고,
최신 B 테스트만 별도 3eda5a56ed3e9fd56d162676507c526ea0d1a1c1 소스를 사용했다.
최신 B를 과거 테스트에 대입해 기대값을 바꾸거나 기존 테스트를 수정하지 않았다.

재현:

```powershell
python -B -X utf8 docs/evidence/cvss-v1.2/latest-b-offline-20261110/run-latest-b-evidence.py
```

이 명령은 로컬 Git 객체를 임시 경로에 읽어 사용한다. fetch는 별도로 수행해야 하며,
소스 참조가 기록된 SHA에서 바뀌면 재검토하도록 중단한다.
최신 B 모듈·정책·단위 테스트 자체는 실행 전후 원본과 해시가 같다.

## 해결된 문제와 남은 문제

기존 D의 낡은 합성 정책에 vulnerable_values/test_connection이 없고,
prohibit-password를 보류로 기대하던 입력 정합성 문제를 신규 테스트에서 해소했다.
현행 정책의 취약 값과 root/Match 관측 조건을 실제 B 인터페이스에 맞춰 제공했으며,
B 실제 v1.1 결과의 D 수신·집계·저장·이력 처리가 통과했다.

이전 실패 로그는 당시 실행 사실이므로 그대로 유지한다.
이제 **기록된 최신 B 커밋과 D v1.1의 오프라인 연동은 검증됨**으로 PR #19를 보완할 수 있다.
다만 최신 B 운영 승인 표기의 문서 간 정리, 실제 B/C v1.2 어댑터 및 E 연계는 별도다.
최신 C 전체 검증도 수행하지 않았다.
실제 SSH/VM, Linux 실환경 및 Python 3.12 테스트는 미실행이다.
OS 판별 및 applies_to 적용은 B 판정 함수가 보장하지 않으며 통합 실행 계층의 별도 책임이다.

Commit/Push와 PR #19 본문·코멘트 수정은 하지 않았다. 사용자 승인 후 업데이트할 수 있으며 병합은 팀장 결정이다.
