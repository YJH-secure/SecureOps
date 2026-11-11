# SecureOps 통합 검증 체크리스트 (팀장 관리) — 2026-11-11 최신

> **신규 개발 계약: [JSON v1.2](architecture/json-result-contract-v1.2.md) + [CVSS v3.1 Base 정책](security-policy/cvss-scoring-policy-v1.2.md).** [기존 v1.1](architecture/json-result-contract-v1.1.md)은 레거시 입력/회귀에만 유지. **v1.1에서 쓰던 severity 필드는 v1.2 개별 결과에서 금지**하며 v1.2의 cvss 필수. 지난 11/09 G-01/G-02 결과는 역사적 증거로 보존하고 최신 통합 검증으로 오인하지 않는다.
>
> 상태 구분: 완료=해당 범위 증거 검증 / 부분 완료=오프라인 또는 구형 실습 VM 등 범위 제한 / 미완료=목표 실환경 증거 없음. **단위 테스트/PR 제출/Mock 실행만으로 신규 중앙 관리 서버 E2E 완료로 인정하지 않는다.**

## 0. 공통 정책·경계

- 허가된 실습 환경 한정. 읽기 전용 진단과 승인형 조치를 구분하고 관리자의 명시 승인·백업/복구 확보 전에 실제 설정을 바꾸지 않는다.
- 공식 신규 VM: A [PR #9](https://github.com/YJH-secure/SecureOps/pull/9) 기준 central-mgmt(192.168.10.10) → ubuntu-a(192.168.10.20), rocky-b(192.168.10.30). A 기준 SSH 연결 검증은 팀장 진단기 실제 실행과 별개의 증거다.
- 상태 5개: pass / vulnerable / error / not_applicable / needs_review. CVSS 평가 3개: scored / pending / not_applicable. pending·not_applicable의 점수는 null. 취약/양호/오류는 서로 바꾸지 않는다.
- 이행률 pass/(pass+vulnerable); 0분모 N/A. CVSS 점수 집계는 scored인 vulnerable만. 미평가를 0점으로 바꾸지 않는다.
- JSON 최상위는 schema_version='1.2', scan_id, target_id, os, scanned_at, results. 개별 결과는 check_id/status/evidence/recommendation/cvss 필수, details 보존, 검사 ID 중복 거부.
- 실측 결과·샘플·MOCK·ZIP 소스 검증을 구분하고 코드 SHA·환경·로그·시각·비식별 증거를 기록한다.

## 1. 검증 관문 (2026-11-11 현황)

| ID | 검증 내용 | 증거 기준 | 현재 상태 |
|---|---|---|---|
| G-01 | 공통 SSH 단위 / MOCK 검증 | 고정 명령 허용·거부, SSH 키/실패/타임아웃 | **부분 완료**: 11/09 5/5 역사 기록, 11/11 PR #24/#26 기반 로컬 9/9 보고. 신규 VM 실연동과 구분 |
| G-02 | JSON 계약 검증 | v1.2 Schema·CVSS Vector 점수/등급·상태 5종·중복 키/시간 | **부분 완료**: 기존 v1.1 8/8, D #19 v1.2 회귀 통과 보고. 최신 main 전체 재실행 필요 |
| G-03 | central-mgmt → ubuntu-a 읽기 전용 진단 | SSH 별칭/키, 수집기 최소권한, B/C 실제 값과 원격 JSON | **미완료**: A는 SSH 접속 성공; 수집기 미설치, 중앙 실행기 미검증 |
| G-04 | central-mgmt → rocky-b 읽기 전용 진단 | 동일 조건 및 Rocky SELinux·Python 3.9·수집권한 | **미완료**: A는 SSH 접속 성공; 수집기 미설치, 중앙 실행기 미검증 |
| G-05 | SSH-01 → B 판정 → D JSON v1.2 집계 | evidence/CVSS pending/scan_id/저장·재조회 | **부분 완료**: 팀장 개인 linux2 Ubuntu 22.04.5 실서버 1건 성공, 신규 VM 재현 전 |
| G-06 | FILE-01 → D 공식 결과 | ACL·group·권한 details 보존, OS별 정책·오류 | **부분 완료**: C 코드 main #15, C ZIP→D #20 오프라인 검증; 공식 v1.2 최신 main/실서버 전 |
| G-07 | SVC/FW/LOG → D 공식 결과 | 서비스·방화벽·로그 수집 근거, 미승인 needs_review | **부분 완료**: C #15/#22 main, #27 v1.2 PR Open, 공식 C SHA에 대한 D 독립 재검증 전 |
| G-08 | 집계 상태·CVSS | 이행률, CVSS scored/pending/not_applicable 및 저장·조회 | **부분 완료**: D #19 main/오프라인 검증; 신규 VM 다항목 수집 전 |
| G-09 | E 승인 → 백업 → 조치 → 새 scan_id 재진단 | 승인 ID·실행 ID·전후 증거·접속 유지 | **부분 완료**: #16 main MOCK, #23 v1.2 MOCK 117 테스트. 실제 승인·조치 미검증 |
| G-10 | E 실패 복구 및 최종 상태 | 복원 증거, 복원 후 미재진단은 '미확인' | **미완료(실환경)**: MOCK 기록과 별개로 VM 시험 없음 |
| G-11 | Ubuntu/Rocky 동일 점검 비교 | 배포판별 명령/권한/SELinux, 정당한 정책 예외 | **미완료(진단기 E2E)** |
| G-12 | 네트워크 서비스 접근성 | 실제 접근 시험, socket 바인딩만으로 외부 노출 단정 금지 | **미완료**: GNS3·망 분리·OPNsense/IDS/WAF 증거 필요 |
| G-13 | 웹 취약점 분석 3건 | 허가된 테스트 SQLi/XSS/파일 업로드 각각 영향·개선·재검증 보고서 | **미완료** |
| G-14 | 제출물 | PDF, MP4 5~10분/100MB 이하, README, PPT·발표 증거 | **미완료** |
| G-15 | 신규 공식 C v1.2 인수 | #27 공식 코드 SHA·CLI 출력과 D 최신 main 결과 비교 | **미완료**: C 163/5/28/5 자체 검증 보고, D 독립 재실행 필요 |
| G-16 | sudoers/원격 수집기 경계 | 기존 scan sudoers 보존, 별도 수집기 sudoers, 무인자 고정, root 파일 보호, visudo/SELinux | **미완료**: #24 Draft, A 서버 미설치; 관리자 승인 전 설치 금지 |
| G-17 | VM 백업 복원 | ZIP/해시/스냅샷/격리망 부팅·원본 비교 | **부분 완료**: A 7z/SHA 일치 보고, .vmx.lck·autoinst.iso 검토 및 복원 시험 대기 |
| G-18 | 운영 자동화·대시보드 | 자동 스캔 실행/이력·에러 격리·사용자 화면 실제 시연 | **미완료** |
| G-19 | GNS3 보안 확장 | OPNsense/IDS/WAF/DNS/FTP, 내부·DMZ·외부 라우팅/접근통제 증거 | **미완료** |

## 2. 기능별 인계·실행 결과 필수 메타데이터

1. 담당자, 날짜/시간(KST), 사용 호스트/target_id, OS/커널, 브랜치+커밋 SHA, PR/병합 여부.
2. 진단 스키마 버전, 정책/결정 근거, 명령어와 sudo 허용 경계, 입출력 파일명·JSON 원본 해시, 테스트 수·실패 수.
3. 입력 출처 구분(실측·MOCK·fixture·외부 ZIP/커밋), 기대/관측 결과, 5개 status와 CVSS 결과의 근거.
4. 민감정보 비식별 터미널 캡처·로그와 재진단 scan_id, 승인 ID, 오류/복구 증거. 개인키/암호/백업 ZIP 등은 커밋 금지.
5. 실제 설정 변경은 별도 명시 승인 후만; 원본 sudoers·기존 성공 코드/증거 보존. 검증되지 않은 값을 PASS나 scored로 바꾸지 않는다.

## 3. 담당 경계와 필수 인계 (중복개발 금지)

- **A 김민우**: VM·GNS3·계정/SSH·sudoers/복원. SSH 별칭/BatchMode·source IP·키 정보(공개 지문만)와 서버 실행 권한 증거 → 팀장·B/C.
- **B 최종욱**: SSH-01·SSH-02·ACC-01/02의 판정/테스트·SSH Match 근거, v1.2 개별 JSON → D/팀장. 현재 #10/#21 main.
- **C 김서후**: FILE/SVC/FW/LOG 진단/정책 보류·OS별 수집 동작, #27 공식 v1.2 SHA·CLI·로그 → D/팀장.
- **D 조효민**: 입력 규격·집계/CVSS·scan_id/저장/재조회, B/C 공식 소스 독립 재검증, E와 전후 보고서 계약 → 팀장. #20/#25는 과거 ZIP/고정 SHA 증거.
- **E 박태준**: 승인·계획 무결성·백업·조치·재진단·복구·별도 실행 이력. 실환경 권한 변경은 팀장 승인과 복원 시험 이후.
- **팀장**: SSH 공통 실행기·독립 Validator, 통합·정책 승인, 웹 보고서 3건·시연/발표 총괄. #24가 #26 선행 의존.

## 4. 중간 발표 최소 성공 경로 및 일정

- **11/12**: SSH 별칭·키/출발 IP 재확인, 최소권한 적용 검토, 중앙 관리 실행 환경 승인; 공식 C→D 최신 SHA 검증 착수.
- **11/13**: B/C→D 공식 JSON v1.2 수용 시험 + E MOCK 계약 검토, 미승인 운영 정책·OS별 차이 표 제출.
- **11/16**: central-mgmt → ubuntu-a 또는 rocky-b 1대 실제 읽기 전용 진단 → v1.2 D 저장·재조회·검증 1건, 로그·실패 사례 증거.
- **11/17**: 발표 리허설·PPT·대본·스크린샷, 실패시 안전한 복구 절차, 기능/미구현 경계 명시.
- **11/18**: 중간 발표. 완료된 것은 **증거 범위 내에서만** 시연하고, 아직 구현되지 않은 GNS3/대시보드/조치/웹 실험은 향후 일정으로 제시.

> 이 통합 체크리스트는 프로젝트 현황 기록이며, 코드 병합·서버 설치·관리자 승인 자체를 의미하지 않는다. 최신 범위는 [프로젝트 현황](project-status.md)에서 확인한다.
