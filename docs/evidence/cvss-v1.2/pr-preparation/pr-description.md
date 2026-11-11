이 PR은 main에 병합된 PR #8의 D Core에 CVSS v3.1 Base 및 JSON v1.2 경로를 추가합니다.
기존 v1.1의 severity·집계·저장 동작을 유지하고, v1.2는 severity 없이 cvss 객체를 명시적으로 검증합니다.
PR #18의 정책·계약·Schema·MOCK은 main 버전을 그대로 사용합니다.

## 변경 사항

- core/cvss.py: FIRST Base 계산, Scope별 PR 가중치, 정규 Vector 검증, Appendix A Roundup 및 등급 산정.
- core/cvss_validation.py: v1.2 상태 조합, 공식 점수·등급 일치, null·JSON 타입·날짜·중복 ID 검증.
- core/cvss_assessment.py: 명시적 적용 여부·근거 검토에 따른 scored/pending/not_applicable 생성. 메트릭 추측 및 v1.1 severity 변환 없음.
- core/main.py, runner.py, remote_result.py: 기본 v1.1 유지, 명시적 schema_version=1.2 지원, 평가 상태·채점된 취약 등급별 집계.
- core/storage.py: 양 버전 원본 저장·조회·이력 유지. 서로 다른 버전의 직접 전후 비교는 오류 처리.
- tests/test_cvss.py, test_cvss_v12.py, test_cvss_assessment.py 및 requirements-test.txt 추가.
- docs/evidence/cvss-v1.2/: 과거 증거 보존 및 최신 main 재검증 증거 추가.

5종 status, pass/(pass+vulnerable) 이행률, FILE-01 details와 입력 원본을 보존합니다.
점수 없는 항목을 0.0으로 채우거나 CVSS 평균/합계를 서버 위험도로 표시하지 않습니다.
B/C 담당 코드·공통 SSH 모듈·기존 테스트·정책 원문은 변경하지 않습니다.

## 검증 환경과 결과

기준 main: d1f7534b3d0d3b9978d15bbea3ae9633eaf43d75.
Windows 11 / AMD64 / CPython 3.14.2 / unittest / jsonschema 4.25.1.
2026-11-10 KST, 별도 feature/cvss-core-jhm-main-review Worktree에서 실제 실행했습니다.

| 테스트 | 통과 | 건너뜀 | 실패·오류 |
|---|---:|---:|---:|
| 신규 CVSS/v1.2 | 52 | 0 | 0 |
| 기존 v1.1 회귀 | 84 | 0 | 0 |
| 기본 환경 전체 | 136 | 3 | 0 |
| 고정 B/C 소스 제공 전체 | 139 | 0 | 0 |

기본 환경의 3개 skip은 B/C 실제 소스 부재 때문입니다. 중복 실행 행은 합산하지 않습니다.
Schema 구조 검사와 D 런타임 검증을 실행했습니다. 선택적 JSON Schema date-time checker는 설치되어 있지 않아,
실제 날짜·시간대 의미 검사는 D 런타임 테스트로 확인했습니다.
git diff --check 통과, 기존 v1.1 검증 함수 본문 AST 보존, 파일 전후 SHA-256 일치를 확인했습니다.

FIRST Examples §3~§7의 6.4/3.1/9.9/4.2/7.2와 모두 일치했습니다.
PR #18 MOCK Vector는 9.8 Critical입니다. Scope·Roundup 경계·오류 Vector·점수/등급 불일치·null을 검증했습니다.
2592개 Base 조합의 불변식도 확인했으나 전체 조합을 독립 공식 기대값과 대조한 것은 아닙니다.
공식 출처: https://www.first.org/cvss/v3-1/examples 및 https://www.first.org/cvss/v3-1/specification-document.

## 증거와 재현

최신 결과: docs/evidence/cvss-v1.2/main-review-20261110/main-review-report.md.
환경·명령·커밋·해시: 같은 경로의 environment-and-results.json, transfer-manifest.json, final-verification.json.
실행 로그: main-review-20261110/logs/ 및 과거 실행·실패 기록 경로.
보존된 과거 로그 11개와 main 재검증 로그 10개를 합쳐 21개를 포함 대상으로 준비했습니다.

재현:

```powershell
python -B -X utf8 -m unittest discover -s tests -v
python -B -X utf8 docs/evidence/cvss-v1.2/main-review-20261110/run-main-review-evidence.py
```

고정 B/C 소스는 B cfbd37b4dbd102ec894a2150d47f751ad5c74afa,
C 6bb330feccfc6541bc145db9b6e18f24b4bce394입니다.
재실행 스크립트는 이 고정 소스로 오프라인 검증하며 과거 증거를 수정하지 않습니다.
main-review 스크립트는 검증 당시 HEAD를 고정 검사하므로 이 PR을 커밋한 후에는 별도 검증 Worktree 또는
명시적으로 검토한 기준선 설정이 필요합니다. 일반 unittest 실행에는 이 제한이 없습니다.
Windows CRLF/LF 차이로 과거 수집기의 raw blob 비교가 불일치한 사실과,
main 내용·정확한 checkout 해시를 별도 검증해 통과한 결과도 함께 보존했습니다.

## 남은 문제 및 범위

- 최신 B의 criteria.vulnerable_values 필수 입력과 판정 변경으로 기존 오프라인 테스트와 호환 문제가 있습니다.
  최신 B 전체가 통과한 것이 아닙니다. 실패 기록은 attempts/current-bc-20261110에 보존했습니다.
- 실제 B/C 판정 함수 검증은 고정 과거 커밋의 v1.1 결과입니다. 신규 v1.2 B/C 파이프라인 입력은 합성 데이터입니다.
- B/C에서 적용 가능 여부, 8개 메트릭의 관측·분석 근거, source/rationale 및 검토 기록을 제공해야 합니다.
- 최신 B 입력 정합성, 실제 B/C v1.2 어댑터와 E 모듈 연계는 미완료입니다.
- 실제 SSH·VM 수집/진단/조치, Linux 실환경, Python 3.12 실행은 미실행입니다.

본 PR의 완료 범위는 D의 CVSS/v1.2 구현과 명시된 오프라인 검증입니다.
