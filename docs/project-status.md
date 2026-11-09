# SecureOps 프로젝트 진행 현황 — 2026-11-09

> 단일 현황 문서 (팀장 관리 초안). **완료 / 검증됨 / 구현 중 / 승인 대기 / 계획**을 구별한다. 이 문서는 기존 JSON 계약서나 보안 정책을 대체하지 않는다.
> 마지막 확인: 2026-11-09. 기록에 없는 기능은 완료로 간주하지 않는다.

## 1. 공식 기준·일정

- 주제: Linux 서버 취약점 진단·평가·승인 기반 조치·재진단 자동화, 격리된 웹 보안 테스트 3건.
- 기본 프로젝트 중간발표: **2026-11-18(수)**.
- 최종발표: **2026-12-02(수)**, 팀당 **20분 발표 + 10분 질의응답**.
- 최종 제출: **2026-12-01(화) 18:00까지**, 조교에게 제출.
- 필수 산출물: (1) PDF 결과 보고서/발표 자료 (2) **5~10분, 100MB 이하 MP4 시연 영상** (3) README를 포함한 GitHub 저장소 URL.
- 공식 과제 추적: 서비스 구축 / 서버 취약점 진단 / 평가 및 보안 조치 계획 / 웹 취약점 분석 보고서 3건 / 자동 스캐닝.

## 2. 현재 환경 — 구축 보고와 향후 계획 구분

- A 인프라 문서의 **실제 구축 보고 환경**: VMware VMnet8 NAT, 192.168.10.0/24, 중앙 관리 서버 `central-mgmt`(Ubuntu Server 24.04.5, 192.168.10.10), 진단 대상 `ubuntu-a`(Ubuntu Desktop 24.04.5, 192.168.10.20), `rocky-b`(Rocky 9.8 Desktop, 192.168.10.30). SSH TCP 22 원격 접속, 진단/조치 전용 계정과 키 인증.
- 관련 근거: [A 인프라 PR #9](https://github.com/YJH-secure/SecureOps/pull/9), [A 인프라 브랜치 문서](https://github.com/YJH-secure/SecureOps/blob/feature/kmw-infrastructure/infrastructure/README.md).
- **GNS3 + 방화벽/망 분리 + DNS/FTP 확장**은 목표 설계이며, 해당 망의 실제 적용과 접근 통제 검증은 아직 확인되지 않음. **GNS3 구축 완료로 기재 금지**.

## 3. 6인 팀 역할 (변경 시 공지 및 기록)

| 담당 | 개발/관리 책임 | 현황 |
|---|---|---|
| 양지혁 (팀장) | 요구사항, 아키텍처, 정책 승인, 공통 SSH 개발, 독립 Integration Validator, 웹 취약점 분석 보고서 3건, 통합 검증·산출물 총괄 | SSH MOCK·JSON 계약 테스트 증거 있음; Validator/웹 보고서 구현 예정 |
| 김민우 (A) | VM·네트워크·계정/SSH 기반 인프라 | VMware 3대 구성 및 키 인증 검증 보고; GNS3/망 정책 검증 대기 |
| 최종욱 (B) | SSH·계정·인증 진단 | [PR #10](https://github.com/YJH-secure/SecureOps/pull/10) 열림; SSH-01 판정/Match 정책·통합 검증 확인 필요 |
| 김서후 (C) | FILE-01/SVC-01/FW-01/LOG-01 | FILE-01 임시 ACL·링크 13/13 MOCK 일치 보고, SVC-01 Rocky 수집 성공; 정책·실제 원격 연동 미완료 |
| 조효민 (D) | 진단 결과 정규화·집계·위험도·리포트 | [PR #8](https://github.com/YJH-secure/SecureOps/pull/8) 열림; B/C 실환경 원격 연동 검증 대기 |
| 박태준 (E) | 관리자 승인·백업·조치·재진단·복구 | 설계/개발 진행, 승인된 실제 조치→재진단 E2E 증거 확인 필요 |

## 4. 기준선 / 확정사항

- [공통 JSON 결과 계약 v1.1](architecture/json-result-contract-v1.1.md) **개발 기준 확정**. 최상위: `schema_version=1.1`, `scan_id`, `target_id`, `os`, `scanned_at`, `results`. 개별 결과 필수: `check_id/status/severity/evidence/recommendation`.
- 상태값: `pass`, `vulnerable`, `error`, `not_applicable`, `needs_review`; `severity`는 소문자. `evidence`는 문자열, 구조화 정보는 선택적 `details`.
- [취약점 점검 기준표 v1.1](security-policy/vulnerability-checklist-v1.1.md)은 **JSON 스키마 버전과 별개의 정책 기준표**. 세부 OS·서비스 승인 조건은 여전히 미확정 가능.
- A/B/C는 개별 진단 결과를 생성; D가 스캔 메타데이터를 추가하여 최상위 v1.1 보고서 구성. 미정 원격 실행·판정 인터페이스는 별도 합의/검증 필요.
- GitHub: 기능 브랜치 → PR → 팀장 검토·테스트 → `main` 병합. **PR 생성 = 승인 또는 병합 아님**.

## 5. 오늘 확인한 개발 증거 — 완료 과장 금지

| 내용 | 근거/상태 | 남은 확인 |
|---|---|---|
| 공통 SSH MOCK 5개 | 2026-11-09 팀장 실행 결과 5/5 OK 보고 | 실제 `central-mgmt → ubuntu-a/rocky-b` 원격 명령 검증 |
| JSON 계약 자동 테스트 8개 | 2026-11-09 팀장 실행 결과 8/8 OK 보고; `tests/test_json_contract.py`는 `feature/architecture-yjh`에 존재 | 다른 모듈 실제 출력으로 재실행; `main` 반영은 별도 검토 |
| PR #13 | `main → feature/architecture-yjh` 방향 병합 확인. **main으로의 병합이 아님** | 필요할 때 팀장 브랜치의 검증된 변경만 별도 PR |
| FILE-01 | 임시 ACL·심볼릭 링크 시나리오 13/13 기대 결과 일치 보고 | OS별 passwd/shadow 정책 확정, 실제 대상 결과·회귀 테스트, D/SSH 연동 |
| SVC-01 Rocky 9.8 | 서후님 제공 `svc01-result.json`: active_units 59, unit_files 282, listeners 9, errors 0, `needs_review`, `medium`, `approval_status=pending` | 자산 매핑 확인, 서비스 승인 목록, 원격 접근성, 수정 코드 회귀·통합 테스트 |
| SVC-01 소켓 요약 | TCP 21(0.0.0.0), 22(0.0.0.0/::), 631(loopback); UDP 323(loopback), 5353(0.0.0.0/::) | FTP·SSH 허용 출발지, IPv4/IPv6, mDNS 필요성, 방화벽 근거 |
| 웹 취약점 3건 | 팀장이 SQLi/XSS/파일 업로드 분석 담당 의사 확정 | 격리 실습 환경·허용 범위 확정, 분석·개선·검증 보고서 작성 |
| 자동 스캐닝 | Python 진단 및 집계 모듈 개발 진행 | 스케줄/원격 실행/저장·관리 실제 연결·증거 확인 |

> 최신 SVC-01 JSON 원본은 팀 대화에서 제공된 자료다. 공개 가능한 증거만 검토하여 PR/보고서에 추가할 것. 자산 IP·자격증명·개인정보·내부 상세 설정의 무분별한 공개 금지.

## 6. 미해결 의사결정 — 팀장 승인 전 확정 금지

1. **SVC-01**: 모든 활성 유닛은 evidence에 수집하되 주요 네트워크/정책 지정 서비스 중심으로 판정하는 안; 허용 목록 밖 관측은 '무조건 취약'이 아니라 **승인된 기본 차단 정책의 존재 및 접근 근거**에 따라 `needs_review` 또는 `vulnerable` 구분. UDP 5353·FTP 21·SSH 22의 서버 역할별 승인 범위 미확정.
2. **FILE-01**: Ubuntu/Rocky `/etc/shadow`·`/etc/passwd` 그룹/권한·ACL·링크 최종 운영 승인과 회귀 검증.
3. **SSH-01**: `PermitRootLogin` 모드 및 `Match`의 조건별 유효 설정 판정 승인/PR #10 검토.
4. **원격 통합**: B/C 로컬 판정을 중앙에서 실행하는 방법, D 최종 v1.1 집계, E 승인·백업·조치·재진단 연결.
5. **인프라**: A 실제 VM 기준선과 GNS3 최종 토폴로지/서버별 역할·방화벽/IPv6 정책 대조.
6. **제출물**: 공식 과제 5단계 충족 표, 웹 분석 3건, PDF·MP4·README, 발표·시연 증거.

## 7. 다음 작업 및 검수 게이트

- **팀장**: [통합 검증 체크리스트](integration-checklist.md) 기준으로 실제 SSH 실행·JSON v1.1·모듈 연동 테스트 및 결과 기록.
- **A↔C**: Rocky 자산 식별·서비스 승인 목록·포트/출발지·방화벽 허용 범위를 공동 검토.
- **B/C↔D**: 개별 결과 → 중앙 원격 수집 → 최상위 v1.1 결과가 되는 샘플 경로 확정.
- **D↔E**: 조치 전·후 `scan_id` 분리, 승인 상태 및 오류 처리 확인.
- **팀장/웹 분석**: 실습 환경 구축·분석 보고서 3건과 실제 검증 증거 확보.
- **중간발표 우선순위**: 실제 서버 연결 + 진단 + JSON 결과 + 규격 검증이 연속으로 동작하는 최소 시나리오.
- **최종 승인 게이트**: 정책 근거, 정상/오류 테스트, 재현 가능한 명령 및 evidence, 비밀정보 검수, 리뷰 및 최종 병합 승인.

## 8. 업데이트 규칙

1. 개발·정책 결정 때마다 날짜, 담당, 작업 브랜치/PR, 테스트 명령, 기대/실제 결과, 미해결/승인 여부를 남긴다.
2. '완료'는 실행 결과가 있을 때만, '통합 완료'는 중앙 관리 서버에서 실제 연결·수집·집계까지 확인했을 때만 표시한다.
3. 정책을 바꿀 때는 [의사결정 기록](decisions/ADR-001-governance-and-policy-status.md)에 근거와 영향을 남긴다.
4. ChatGPT 또는 다른 AI에 프로젝트를 설명할 때 [AI 인수인계 요약](PROJECT_CONTEXT_FOR_AI.md), 이 현황 문서, 확정 JSON 계약·정책, 해당 PR을 **순서대로 확인**한다. 요약이 실제 코드와 다르면 최신 검증 근거를 우선하며 차이를 표시한다.
