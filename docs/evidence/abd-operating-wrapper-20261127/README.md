# A/B/D 최소 운영 연결 wrapper — Draft 검토 자료

2026-11-27 승인 범위: 신규 연결 wrapper와 격리 MOCK 시험. 실제 SSH/VM/중앙 실행·B 설치·metadata writer는 포함하지 않는다.

## 구현과 소유 범위

신규 `orchestration/abd_diagnosis.py::diagnose_abd_execution(execution, *, profile, store, evidence_ref=None)`는 **이미 생성된 A execution의 수신 전용 함수**다. A run_b_read/SSH를 실행하지 않는다.

1. A b_read_stop_reason()을 먼저 적용한다. 사유가 있으면 B/D/저장을 호출하지 않는다.
2. A b_read_trusted_context()와 승인된 D ApprovedProfile의 대상·네 필드(host/addr/os_id/os_version)를 대조한다.
3. 기존 D receive_b_collector_result()에 실제 B 함수와 CollectorTrustError를 전달하고 정확히 한 번 위임한다.
4. B 판정, D v1.2 검증·집계·ReportStore save/load 및 전체 dict 비교는 기존 D 어댑터가 소유한다. wrapper가 B를 별도로 호출하거나 재저장하지 않는다.
5. D 응답과 실패 계층을 보존하고, A execution_id와 D scan_id를 반환값 id_link에 연결한다. ID를 새로 만들거나 파일로 기록하지 않는다.

공통 JSON v1.2와 E outcome/실행 이력 계약을 변경하지 않는다. 반환값은 wrapper의 별도 in-memory 운영 응답이며 새로운 네트워크 API나 공통 Schema가 아니다. integration_success는 진단 데이터 경로 성공이며 diagnosis pass나 실서버 안전을 뜻하지 않는다.

유효한 error/needs_review, evidence/recommendation/details/CVSS/null을 보존한다. 공식 v1.2 B 결과에는 severity가 없으며 임의 추가/자동 변환하지 않는다. 잘못된 severity 포함 결과는 D 검증에서 거부한다.

## 소스 기준 및 외부 의존성

| 대상 | 기준 |
|---|---|
| D Core | 0cab3a247d2143fc5556e37f6651440e109eef70 |
| A v2 | 승인된 dda9f8a 제공 LF 소스 |
| B 입구 | 20805d2c5fbdfcd46cbd19d1ac1d3efc03fbeb0f |
| 기존 D adapter | 미커밋 검증본 SHA-256 2b41af01a55c9a8ce7703219798b8e73ac22ac3e753f4cf287c01df118065b2f |
| A transport 파일 SHA-256 | 6d5103bbfb7f3dc0e675a7bedbc1c4ec59cbb98513f10559f21a5e1e435338b8 |
| B collector_entry LF SHA-256 | fd87bf768807727be0e44b18001a18af0ef766040423db5dcb64e149df464bf1 |

파일별 raw/LF 해시는 `tests/offline_abd/dependencies.json`에 있다. B ZIP CRLF 사본은 LF 환산 비교만 하고 원본을 변경하지 않는다.

PR #36/#39/#44 계열은 고정 B 20805d2의 의존 소스를 사용한다. A v2는 PR #40의 후속 제공 소스이며 PR #40 HEAD와 동일하다고 가정하지 않는다. D 어댑터는 PR #42의 FILE-01 어댑터와 다른 별도 미커밋 B 연결 파일이다. PR #24/#26 SSH-01 실행기를 호출하거나 병합하지 않는다.

**순수 main에는 이 고정 A v2/B 입구/D 어댑터가 모두 존재하지 않는다.** 이 PR은 외부 동결 의존성을 명시한 Draft이며 단독 운영 배포본이 아니다. A/B/D 동결 소스를 이 PR에 복사하거나 수정하지 않았다. E 및 C는 이 wrapper의 실행 의존성이 아니다.

## 신규 실행 결과

환경: Windows 로컬 Python 3.14.2, 기존 jsonschema 4.25.1. 패키지 설치 없음.

| 범위 | PASS | FAIL | ERROR | SKIP | exit |
|---|---:|---:|---:|---:|---:|
| 신규 wrapper W01~W19 | 19 | 0 | 0 | 0 | 0 |
| D 소스 경로 지정 기본 회귀 | 173 | 0 | 0 | 0 | 0 |

초기 기본 discover는 SECUREOPS_D_SOURCE 미설정으로 기존 클래스 1개를 Skip했다(171 실행, 170 PASS, FAIL/ERROR 0). 원본 로그는 로컬에 별도로 보존했다. 이어 같은 고정 Worktree를 명시하여 새 프로세스로 실행한 최종 회귀가 위 173 PASS다. Skip을 삭제하거나 기대값을 바꾸지 않았다.

기존 A/B/D 전체 체인 21 PASS는 과거 공식 수용 기록이다. 신규 19개·기본 173개와 합산해 새 전체 체인 실적으로 표현하지 않는다. W18/W19는 실제 B 함수 반환 뒤 비정상 severity/결과 누락·중복을 주입한 **D 경계 fault 시험**이며 정상 B가 그런 결과를 만든다는 뜻이 아니다.

제출용 신규 manifest/driver의 줄바꿈을 LF로 정리한 후 최종 19개를 다시 실행했다. 초기 실행 로그는 로컬에 보존하고 반복 실행을 고유 시험 수에 합산하지 않았다. 제출 로그는 원본 출력의 비식별/LF 사본이며 원본 바이트 로그는 별도 로컬 증거에 보존했다.

## 재현 방법 — 명시적 오프라인 작업

승인된 외부 의존 소스 폴더에는 integration/{__init__,a_file01_cli,a_ssh_transport,bd_collector_adapter}.py 및 고정 checks/account 소스·정책·MOCK 보조 파일이 필요하다. 해당 원본을 별도로 확보해야 하며 이 PR은 비공개 자료나 외부 ZIP을 업로드하지 않는다.

```powershell
$env:SECUREOPS_ABD_DEPS_ROOT = '<승인된 동결 의존 소스 루트>'
$env:SECUREOPS_ABD_RESULTS_DIR = '<새 로컬 증거 폴더>'
python -B -X utf8 tests/offline_abd/run_tests.py
```

```sh
SECUREOPS_ABD_DEPS_ROOT='<approved-frozen-dependency-root>' \
SECUREOPS_ABD_RESULTS_DIR='<new-local-evidence-directory>' \
python3 -B -X utf8 tests/offline_abd/run_tests.py
```

Linux 명령은 재현 제안이며 Linux 실행 완료 증거가 아니다. driver는 누락·SHA 불일치 시 명시적으로 실패하고 Skip하지 않는다. 기존 의존 파일을 복사/설치하지 않는다. tests/offline_abd는 기본 discover에 혼입되지 않는 별도 작업이며 __init__.py를 추가하지 않았다.

기본 회귀 명령은 `SECUREOPS_D_SOURCE=<이 고정 Worktree>` 설정 후 `python -B -X utf8 -m unittest discover -s tests -v`다. 실제 실행에서는 socket 차단 guard와 명령 범위 safe.directory 설정을 사용했으며 상세 코드는 main-configured-results.json에 보존했다. 글로벌 Git 설정은 변경하지 않았다.

## 실패·ID 계약

- A 실패 사유, B 신뢰 stage/reason, D validation/save/load/verify 실패를 분리한다. B stage/reason은 기존 D의 failure.collector_trust를 유지한다.
- 저장 실패는 unconfirmed이며 파일 부재를 단정하지 않는다. save 성공/load 실패 시 ID·경로·원본 보고서를 유지하고 성공 오판·자동 재시도·삭제를 금지한다.
- 예상 밖 D 응답 유실도 D_response/response_unavailable로 처리한다. scan_id 미수신을 실제 보고서 미생성 증거로 해석하지 않는다.
- id_link는 기존 ID의 in-memory 연결이다. `<record_root>/<execution_id>/d_link.json`은 후보일 뿐 생성하지 않는다. 저장 경로·권한·원자성·중복 방지·보존·복구는 미결정이다.

## 현재 승인 경계와 검토 요청

GNS3 3-C-2 복구와 T5/T6 PASS는 **2026-11-27 사용자 지시에서 팀장님 수령 사실로 전달된 보고**를 근거로 상태를 갱신했다. 원본 네트워크 로그를 이번에 독립 검증하거나 새로 실행하지 않았다. B S2 설치·실제 Central VM 신규 실행·A/B/D 실환경 E2E는 별도 승인 대기다. [E2E-ENTRY-CHECKLIST.md](E2E-ENTRY-CHECKLIST.md) 참조.

- 민우님: A STOP 선행·고정 context/profile·receipt-only 범위·배포/실행 승인 경계 검토.
- 종욱님: B raw bytes/네 context 키·결과 매핑·CollectorTrustError 보존·판정 단일 호출 검토.
- D/팀장님: 미커밋 D 어댑터 공급/동결 방식 및 추후 metadata writer 계약 검토.

D/E FILE-01 호출부·E 정책·C Bridge·기존 Ubuntu/Rocky 성공본은 이번 작업에서 변경하지 않았다. 실제 SSH/VM, Linux killpg·운영 권한·실환경 timeout·중앙 Python 전체 체인은 미검증이다. Draft 해제나 main 병합은 하지 않는다.

## 2026-11-27 후속 의존성 확인 — 문서 보완만 수행

위 19 PASS·173 PASS·과거 21 PASS는 기존 기록이다. 이번에는 테스트를 재실행하지 않았고 소스·테스트·dependencies.json·실행 증거를 변경하지 않았다. 아래 내용은 원격 상태, 공유 ZIP과 기존 파일의 읽기 전용 대조 및 향후 공식 반영 제안이다.

### A v2 로컬 미push 의존성

- A v2 기준은 `dda9f8a`이며 민우님의 `feature/a-b-read-v1-kmw` 로컬 미push 소스다. 공유 README와 2026-11-27 원격 브랜치 목록에서 이를 대조했다. **A 전체 40자리 commit SHA는 현재 확보하지 못했으며 추정해 확장하지 않는다.**
- 검증 근거는 `a-b-read-v1-share-v2-261127.zip`의 Git 원본 LF 제공 파일과 SHA256SUMS다. ZIP SHA-256은 `0d81fa5192468eec083a01baee9c4a62ab6c557e12fb11ca7a4442b3f1d53689`. 내부 해시 6개와 압축 무결성을 확인했고 실제 사용한 integration 파일 3개는 검증 작업본과 byte 단위로 일치했다. 이 대조는 민우님 PC의 로컬 Git commit 객체 자체를 독립 검증한 것은 아니다.
- A 브랜치 원격 push 및 선행 병합은 팀장 승인 대기다. 현재 PR #40 HEAD `0b95a12bc4b260199cef35b1c8828dd9463a0522`는 FILE-01 전송 기준이며 A v2와 동일하지 않다. A 공유 README의 계보는 `0b95a12 → 84042d4 → f5ea7bd → dda9f8a`로, 뒤 세 개의 전체 commit 객체는 미확보다.
- **PR #45 단독으로 전체 의존성을 재현하거나 병합할 수 없다.** 파일 간 Git 병합 충돌 유무와 별개로 A v2, B 공식 입구, 별도 D adapter의 공식 공급·선행 반영·검토가 필요하다. 실제 병합 가능 승인을 의미하지 않는다.
- wrapper는 기존 A execution을 수신하는 `diagnose_abd_execution()` 전용 함수이며 실제 SSH나 `run_b_read()`를 호출하지 않는다. 민우님의 A STOP·trusted context 정상 확인은 담당자 회신으로 기록하며 추가 실환경 시험 결과로 표시하지 않는다.

### 최종 동결 파일 대조

기존 [dependencies.json](../../../tests/offline_abd/dependencies.json)의 22개 의존 파일 raw/LF SHA와 D Core·Schema 6개 LF SHA를 재대조했다. 모두 일치한다. B 파일 18개는 원격 고정 commit의 Git blob과 LF 기준으로 일치한다. commit SHA, blob SHA-1, SHA-256을 서로 바꾸어 표기하지 않는다.

| 소스 | 고정 기준 / SHA-256 | 현재 공식 반영 상태 |
|---|---|---|
| D Core | `0cab3a247d2143fc5556e37f6651440e109eef70` | 원격 main과 일치 |
| A transport | `6d5103bbfb7f3dc0e675a7bedbc1c4ec59cbb98513f10559f21a5e1e435338b8` | dda9f8a 공유 LF 소스, 로컬 미push |
| A CLI | `b095a3619a3ca1a59a730f8ed1851726f561556ac2091a6aeb0f57d5fde1ecf8` | 동일 A 공유본, 테스트 보조로 사용 |
| B 입구 | `20805d2c5fbdfcd46cbd19d1ac1d3efc03fbeb0f` / LF `fd87bf768807727be0e44b18001a18af0ef766040423db5dcb64e149df464bf1` | 원격 feature/collector-entry-cjw 존재, 해당 head PR 없음·main 미반영 |
| D B adapter | `2b41af01a55c9a8ce7703219798b8e73ac22ac3e753f4cf287c01df118065b2f` | 검증된 미커밋 외부 소스, 공식 별도 PR 없음 |
| PR #45 wrapper | `03e6818c593141d818db586554e703d259b81d14240ce704d880427bf9eeda81` | 기존 소스 commit 876ac2da3942ce851b0fe4fa69c9752cba3b6491, 이번에 변경 없음 |

B 제공 `b-entry-20805d2.zip` SHA-256은 `227c80f99d6fa272cbff05d5b41ceac6abb3996c9cdd4eaefc463b3656bbc510`. ZIP의 CRLF 18개 파일은 작업본 raw와 일치하고 LF 환산 Git blob은 원격 B commit과 일치한다. 줄바꿈 차이를 소스 변경으로 오인하지 않으며 ZIP 원본은 수정하지 않았다.

### 선행 PR 및 공식 반영 순서 — 제안, 병합 승인 아님

| 대상 | 실제 HEAD | 관계 및 승인 대기 |
|---|---|---|
| #33 SSH-02 | `0eefcd079d5b48b03cb96ba30c64e4d6a8b90a51` | main 기준 신규 3개, 미병합 |
| #36 ACC | `62cf5c9dd3c122ad3e0034307b8d321969ce1e89` | main 기준 신규 5개, 미병합 |
| #39 payload adapter | `ed26b63dc988d0119e30414e8ee55b2615908a21` | Draft, #33 및 이전 #36 소스 포함. 실제 main diff 10개이므로 선행 병합 뒤 중복 diff 재확인 필요 |
| #44 B collector | `bc22f7b7d19774d8e9bffdc04199397c0e01d301` | Draft, base #39, 직접 diff collector/test 2개 |
| B 공식 입구 | `20805d2c5fbdfcd46cbd19d1ac1d3efc03fbeb0f` | 부모 77fd29d685a3db10ad3bf00c858c5f870d4576a7이 #44와 최신 #36을 결합. 입구/test 2개 추가. 정식 PR·병합 승인 필요 |
| #40 A FILE-01 | `0b95a12bc4b260199cef35b1c8828dd9463a0522` | Draft, main 기준 4개. A v2는 이를 기반으로 한 미push 후속 소스이며 #40만으로 B 전송 기능 충족 불가 |

B 측 제시 순서 `#33 → #36 → #39 → #44 → B 공식 입구`를 우선 검토한다. #39의 이전 ACC 소스와 최신 #36 차이는 B 입구 부모 merge에서 결합됐으므로 선행 PR을 단순 중복 적용하지 말고 담당자가 최종 diff·동결 파일 해시를 재확인해야 한다. A 계열은 별도로 `#40 → A v2 정식 반영`이 필요하다. 두 계열은 승인 범위 안에서 병렬 검토 가능하며, **A v2 + B 공식 입구 + D adapter가 공식 공급·반영된 뒤 #45를 최종 검토**하는 의존 관계다. 기존 PR의 base 변경이나 merge/rebase를 이번에 수행하지 않았다.

### D adapter 공식 Draft PR 방안 — 이번에는 생성하지 않음

팀장 승인 후 D 전용 브랜치에서 검증된 `integration/bd_collector_adapter.py`와 그 버전에 맞는 관련 테스트를 별도 Draft PR로 제출하는 방안을 제안한다. PR #45에 무단 복사하지 않고 FILE-01용 PR #42와도 구분한다. 후보 테스트는 최종 공식 B 결합 검증본의 `tests/test_bd_collector_adapter.py`이며 SHA-256 `79506ee4683810c345bfa0f75b407038af26720590917aca864655195452cbff`. 초기 D 작업본의 document/context 호출용 테스트와 혼동하지 않는다.

기존 D 자체 28 PASS, 공식 B 결합 18 PASS, 선별 53 PASS는 각기 과거 증거로 보존한다. 제출 전 실제 원본·테스트 해시, import 환경, B 의존성 및 소유 범위를 재확인하고 신규 승인 범위로 검증해야 한다. 패키지 __init__는 A #40/후속 source와 충돌 여부를 먼저 검토하며, 이를 이유로 세 번째 파일을 임의 추가하지 않는다. D Core·Schema 수정은 제안하지 않는다.

### 중앙 Python import·실행 경로

기존 19건 실행에서 확인한 경로는 `tests/offline_abd/run_tests.py`가 설정한다. `<WRAPPER_ROOT>`는 PR #45 checkout, `<DEPS_ROOT>`는 별도 승인된 동결 소스 루트다.

- `orchestration.abd_diagnosis`, `core.main`, `core.storage`: WRAPPER_ROOT. main 고정 파일 LF SHA를 driver가 확인한다.
- `integration.a_ssh_transport`, `integration.bd_collector_adapter`: DEPS_ROOT/integration. driver가 명시적으로 integration 패키지를 로딩하여 다른 설치본과 섞이지 않게 한다.
- `collector_entry`, `central_adapter`, B 보조 모듈: DEPS_ROOT/checks/account. 현재 B 입구가 해당 폴더를 sys.path에 추가하는 top-level import 계약이다. 별도 패키지 import로 임의 변경하지 않는다.
- runner는 `sys.path`에 WRAPPER_ROOT, tests/offline_abd, DEPS_ROOT/checks/account를 넣는다. 기존 19건 재현에는 전역 PYTHONPATH 변경이 필요하지 않다. 직접 중앙 호출 시에는 동일 경로 분리와 실제 module.__file__·core.__path__ 검증이 필요하며, 배포 레이아웃·직접 실행 진입점은 미확정이다.

기존 오프라인 명령은 `SECUREOPS_ABD_DEPS_ROOT`와 새 `SECUREOPS_ABD_RESULTS_DIR` 지정 후 WRAPPER_ROOT에서 `python -B -X utf8 tests/offline_abd/run_tests.py`다. Windows Python 3.14.2/jsonschema 4.25.1 기존 결과이며 중앙 시스템 Python/venv 경로, Python 3.12 전체 체인, Linux killpg 및 실제 파일시스템 권한은 이번에 확인하지 않았다. A/B 및 D runtime의 확인된 import는 표준 라이브러리 중심이며 jsonschema는 현재 격리 테스트 의존성이다. 중앙 패키지 설치·변경은 수행하지 않는다.

### 독립 오프라인 패키지 구성 제안 및 승인 대기

새 패키지 생성·배포는 이번 범위가 아니다. 승인 후 PR #45 고정 checkout, 승인된 A LF ZIP, B 20805d2 checkout/ZIP, 별도 고정 D adapter·대응 테스트, 기존 dependencies.json, 파일별 raw/LF SHA, 재현 README와 기존·신규 결과를 구분한 로그를 묶는 방안이다. ZIP SHA/내부 해시·필수 파일·import 경로를 사전 확인하고 누락 시 명시적 실패한다. 승인된 MOCK만 사용하고 비공개 자료·실서버 설정을 공개하지 않는다. 온라인 fetch 없이 해시 확인 가능한 폴더를 구성하되 이번 작업에서는 만들지 않는다.

- 민우님: A 전체 commit SHA·원격 반영 승인·B STOP/trusted context 동결 기준·중앙 배포 경로 확인. A STOP·context 정상 의견은 수령했으나 실제 중앙 실행 승인과 구분한다.
- 종욱님: B 공식 입구, CollectorTrustError stage/reason, 원본 bytes 전달, B 판정 단일 호출 검토 회신 대기. **기존 ABD13~18 실패 계층 분류는 합의 전까지 변경하지 않는다.** #39/#36 결합·B 입구 정식 PR 및 source 공급 검토 필요.
- D/팀장님: 별도 D adapter Draft PR의 정확한 파일 범위와 검증 승인, A/B 선행 반영 순서, 비공개 패키지 공유 범위 결정 필요.
- B S2 설치, 실제 Central VM/A-B-D E2E, 운영 metadata writer·영속 ID 연결, Ready 전환·main 병합은 별도 승인 대기다. 이번에는 의존성 문서 1개만 Commit·일반 Push한다.
