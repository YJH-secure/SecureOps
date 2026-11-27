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
