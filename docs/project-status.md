# SecureOps 프로젝트 진행 현황 — 2026-11-11

> **최신 팀장 관리 현황(2026-11-11 17:45 KST 기준)**. 이 문서는 현재 실행/병합 상태와 미완료 게이트를 구분한다. 완료 증거 없이 실제 통합 완료로 표시하지 않는다.
>
> **개발 신규 기준선: JSON 결과 계약 v1.2 + CVSS v3.1 Base (2026-11-10 승인·main 반영). 기존 JSON v1.1은 호환/기존 보고서 경로로 유지하며 삭제·일괄 변경하지 않는다.**
>
> 코드·PR 상태는 실제 GitHub main 및 각 브랜치 기준. 이 문서는 규격 자체를 재정의하지 않으며 실제 계약·정책을 우선한다.

## 1. 공식 일정 및 제출물

- **2026-11-18(수) 중간 발표**: 신규 중앙 관리 VM에서 진단 대상 1대 이상 읽기 전용 SSH 진단 → B/C 판정 → D JSON v1.2 검증·저장 → 근거 화면의 최소 실서버 시연 목표.
- **2026-12-01(화) 18:00 최종 제출**, **12-02(수) 최종 발표**(20분 발표 + 10분 질의응답).
- 최종 제출 요구사항: PDF 결과 보고서·발표 자료, 5~10분/100MB 이하 MP4 시연, README 포함 GitHub URL. 실제 과제 범위: Linux 서버/네트워크·진단·조치·자동 스캔 및 웹 취약점 SQLi/XSS/파일 업로드 분석 보고서 3건.
- 아래 마감은 **팀장 제안 실행 목표**이며 외부 공식 마감이 아니다: 11/12 인프라·계약 인수, 11/13 공식 B/C→D 재검증, 11/16 중앙 VM 통합·시연, 11/17 발표 리허설·증거 동결.

## 2. 유일한 신규 개발 계약 / 정책

- [JSON 결과 계약 v1.2](architecture/json-result-contract-v1.2.md), [JSON Schema v1.2](architecture/json-result-schema-v1.2.schema.json), [CVSS 정책 v1.2](security-policy/cvss-scoring-policy-v1.2.md): **신규 개발의 확정 기준**.
- 기존 [JSON v1.1](architecture/json-result-contract-v1.1.md) 및 [취약점 점검 기준표 v1.1](security-policy/vulnerability-checklist-v1.1.md)는 레거시 형식/검사 정책 근거로 보존. **JSON 버전과 진단 기준표 버전은 다른 개념**이다.
- 스캔 최상위: **schema_version="1.2", scan_id, target_id, os, scanned_at, results**. 개별 결과 필수: **check_id, status, evidence, recommendation, cvss**. v1.2 개별 결과에는 **severity를 사용하지 않는다**.
- status 5종: **pass / vulnerable / error / not_applicable / needs_review**. status와 CVSS 평가 상태 **scored / pending / not_applicable**를 혼동하지 않는다.
- CVSS는 **v3.1 Base**, 근거 있는 scored만 공식 메트릭·Vector·점수·등급 검증. 미평가 시 **null** (0.0으로 치환 금지), 기존 severity를 CVSS 점수/등급으로 환산 금지.
- 이행률: **pass / (pass + vulnerable)**, 분모가 0이면 N/A. error/not_applicable/needs_review는 이행률 분모 제외.
- D는 입력 계약 검증/집계/scan_id 생성·저장·재조회, B/C는 읽기 전용 진단, E는 **승인·백업·조치·재진단·복구**, 팀장은 원격 실행과 **독립 통합 검증·정책 승인** 담당. 임의 중복 개발 금지.
- 기준: [PR #18 정책](https://github.com/YJH-secure/SecureOps/pull/18), [PR #19 D CVSS Core](https://github.com/YJH-secure/SecureOps/pull/19) 이미 병합.

## 3. 인프라 실제 상태 / 미확정 구분

- A [PR #9](https://github.com/YJH-secure/SecureOps/pull/9) 문서·실측 기준: 중앙 **central-mgmt (Ubuntu Server 24.04.5, 192.168.10.10)**, 대상 **ubuntu-a (Ubuntu Desktop 24.04.5, 192.168.10.20)** 및 **rocky-b (Rocky Desktop 9.8, 192.168.10.30)**. VMware VMnet8 NAT 192.168.10.0/24. 실제 중앙→두 대상 SSH 키·계정 분리 접속 성공 보고.
- **secureops-scan sudoers 초안 v0 유지, PR #24 전용 수집기는 신규 대상 2대에 미설치**. 기존 sudoers를 덮어쓰기 금지. 전용 최소 권한·root 소유권·Rocky SELinux·실제 SSH 별칭/키·-C 컨텍스트 검증 후 팀장 승인으로 진행.
- A 담당 11/11 보고: VM ZIP 3개 SHA-256 일치, 7z 무결성 검사 통과, 스냅샷·디스크 참조 확인. 다만 **격리 네트워크 복원 시험과 원본 비교 미완료**, central-mgmt ZIP의 .vmx.lck 및 ubuntu-a ZIP의 autoinst.iso 포함은 별도 민감정보/복원성 확인 필요.
- **GNS3·OPNsense/방화벽·내부/DMZ/외부 구분, Suricata IDS, WAF, DNS/FTP, 웹 대상 환경**은 별도 실제 연동·접근통제 증거가 없으면 구축 완료로 쓰지 않는다.

## 4. 팀원별 구현/검증 상태 (2026-11-11 GitHub 실측)

| 담당 | 코드/PR 증거 | 오늘 기준 상태 | 다음 인수 조건 |
| --- | --- | --- | --- |
| 양지혁(팀장) | [PR #24 SSH 수집기](https://github.com/YJH-secure/SecureOps/pull/24) Draft / [PR #26 중앙 실행기](https://github.com/YJH-secure/SecureOps/pull/26) Draft; 기존 linux2에서 SSH-01→B→D v1.2 JSON 저장 성공, SSH 회귀 9/9 보고 | **개인 실습 VM 연동 성공, 민우 신규 VM 미실행** | A SSH 별칭·권한 검증 → 승인된 수집기 설치·회귀 → 신규 VM 증거, 독립 Validator |
| 김민우(A) | [PR #9](https://github.com/YJH-secure/SecureOps/pull/9) Open; 인수문서 HANDOFF.md | VM 3대·키 접속 확인, 복원/수집기 연동 대기 | SSH 별칭·출발 IP 명령 결과, 복원·sudo 0440/visudo 증거, GNS3 연결 |
| 최종욱(B) | [PR #10 SSH-01](https://github.com/YJH-secure/SecureOps/pull/10), [#21 B v1.2](https://github.com/YJH-secure/SecureOps/pull/21) **main 병합**; 47개 단위 통과 보고 | SSH-01/JSON v1.2 완료, 추가 진단 및 실서버 연동 대기 | SSH-02, ACC-01/02 범위·테스트, root Match 오판 방지, A/D 연계 |
| 김서후(C) | [#15 FILE/SVC](https://github.com/YJH-secure/SecureOps/pull/15) 및 [#22 FW/LOG](https://github.com/YJH-secure/SecureOps/pull/22) **main 병합**; [#27 C v1.2](https://github.com/YJH-secure/SecureOps/pull/27) Open. 163개 C 테스트·v1.2 5시나리오·D MOCK 5건 보고 | 네 진단 모듈 v1.1 코드 반영, v1.2 리뷰 중 | 공식 C SHA/CLI를 D에 전달, 정책 보류 항목/OS별 권한 정리 |
| 조효민(D) | [#8 Core](https://github.com/YJH-secure/SecureOps/pull/8), [#19 CVSS](https://github.com/YJH-secure/SecureOps/pull/19) **main 병합**; [#20 C ZIP 오프라인](https://github.com/YJH-secure/SecureOps/pull/20), [#25 B 오프라인](https://github.com/YJH-secure/SecureOps/pull/25) Draft | JSON v1.2 점수 검증·집계 구현, 고정 소스 오프라인 통합 통과 | #27 공식 C→D 최신 main 독립 재실행, B/C 다중 결과 저장·조회, E 계약 공유 |
| 박태준(E) | [#16 E MOCK](https://github.com/YJH-secure/SecureOps/pull/16) **main 병합**; [#23 E v1.2](https://github.com/YJH-secure/SecureOps/pull/23) Open; 117개 회귀 통과 보고 | 관리자 승인·MOCK 조치 경로 존재, v1.2 리뷰 중 | 승인/백업/롤백/최종 보안상태 규칙, 실서버 안전한 검증 계획 |

## 5. 현재 PR 의존성과 병합 위험

- **main**에는 B #10/#21, C #15/#22, D #8/#19, E #16, CVSS 기준 #18이 병합돼 있다.
- **#24 → #26**: #26 중앙 실행기는 #24의 common/ssh_client.py에 의존. **#24 먼저 리뷰·병합 승인 → 최신 main에서 #26 전체 재실행·검토 → 순차 승인**. 두 PR 모두 현재 Draft.
- **#27 (C v1.2)**: C의 본인 공식 코드/테스트 결과와 **D 담당자의 최신 main 독립 검증**을 구분; #27 검토 후 승인 결정.
- **#23 (E v1.2)**: MOCK 117개 기록은 실제 서버 조치 증거가 아니다. 승인·백업·재진단·실패 복구 절차 및 로그 검증 필요.
- **#9 (A)**: 작업 브랜치가 과거 v1.1 공통 문서까지 포함한다. 최신 main 계약/README를 덮어쓰지 않도록 **인프라 관련 파일 위주로 분리·검토**.
- **#20/#25 (D)**: 제공 ZIP/고정 커밋의 오프라인 자료. 현재 main/공식 C 브랜치 기준 재실행과는 구분. PR #25는 **2026-11-11 재조회 시 GitHub 병합 가능**으로 확인됐지만 Draft이므로 검증 증거·최신 커밋 정합성 심사 전 병합 금지.

## 6. 실제 통합/정책 미해결

1. **중앙 SSH**: 중앙 VM SecureOps checkout/venv/비밀키 관리 방식; alias→전용키 검증, SSH-01 래퍼 별도 sudoers(원본 유지), root Match 전체 미수집 시 보수적 needs_review, Rocky Python 3.9/SELinux.
2. **B·C→D**: 각각 실제 Ubuntu/Rocky 수집 → 결과 5종 → v1.2 Schema·CVSS 정합성 → target_id/os/scan_id/시간 → 보고서 저장·재조회. 동일 scan_id 내 check_id 중복 금지.
3. **검사 정책**: FILE-01 /etc/passwd·shadow ACL·권한, SVC-01 중요 서비스/소켓, FW/LOG 승인 기준과 실제 접근성; 정책 미승인 값은 무조건 pass나 취약으로 단정 금지.
4. **E**: execution_id/plan_id/approval_id와 전후 scan_id 분리; 조치 후 상태·원복 후 미재진단은 '미확인'으로 표시. 실제 변경은 관리자 승인, 백업/복구·접속 유지 준비 후 허가된 VM에만.
5. **확장 기능/산출물**: GNS3/OPNsense/IDS/WAF/DNS/FTP, 자동 스캔 스케줄러·대시보드, 웹 취약점 분석 3건, PDF·MP4·발표 PPT·README/개인 취업 포트폴리오. 전부 남은 범위로 추적.

## 7. 팀장 제안 다음 일정 및 완료 판단 (2026-11-11 마감 공지용)

| 기한(KST) | 담당 | 요구 산출물 / 완료 기준 |
| --- | --- | --- |
| **11/11 종료 전** | 전원 | 오늘 최종 커밋·PR/브랜치·테스트 수·완료/미완료·차단 이슈·도움 필요한 사람을 팀장에게 1회 공유. 새 main 병합 금지(팀장 승인). |
| **11/12 12:00** | A + 팀장 | 중앙 SSH -G/BatchMode·출발 IP 확인, ZIP 복원/서버 접근·권한 확인 상태, 수집기 분리 sudoers 적용 계획. **현재 설정 변경 금지**. |
| **11/12 18:00** | B + C + D | #27 공식 C SHA 기반 B/C→D v1.2 최신 main 검증, 각자 테스트 로그·검증표·실패 입력·정책 보류 목록 제출. |
| **11/13 18:00** | B + C | B 추가 진단 항목 범위 확정과 실행형 테스트; C FILE/SVC/FW/LOG 운영 정책 보류·배포판별 수집 명령 매핑 표 제출. |
| **11/13 18:00** | D + E | E #23 입력 계약·롤백 최종상태 정의 및 MOCK 전후 JSON 실례, 독립 회귀 결과 제출. |
| **11/16 18:00** | A + 팀장 + B/C/D | 신규 중앙 VM → Ubuntu 또는 Rocky 실제 읽기 전용 진단 → JSON v1.2 저장/재조회 E2E 1건 이상. 승인된 접근만. |
| **11/17 18:00** | 전원 | 중간 발표 시연·실패 복구 화면·PPT·대본·증거 동결 및 전체 리허설. |
| **11/18** | 전원 | 중간 발표 (구현/오프라인/실환경 검증 범위 정확히 구분). |

## 8. 변경·검증·AI 인수인계 규칙

1. 소스 우선순위: **현재 main 코드/팀장 승인된 v1.2 계약 → 해당 담당 공식 PR/커밋 → 재현 테스트 로그 → 대화 요약**. 오래된 AI 기억이나 v1.1 README 문구가 최신 계약을 덮어쓰지 않는다.
2. 각 보고: 담당/날짜·브랜치/SHA·실행 서버·입력 자료 분류(실측/MOCK/fixture/ZIP)·테스트 수·명령·기대/실제·오류·민감정보 비식별 결과·PR 링크.
3. 상태는 **완료(병합/실측 검증), 개발 중, Draft 검토 중, 승인 대기, 미검증**으로 구분. PR 제출은 병합이 아니며 MOCK은 실환경 E2E가 아니다.
4. **서버 권한 변경, sudoers·방화벽/SSH 변경, E 조치, main 병합은 별도 명시 승인 후 수행**. 개인키·비밀번호·백업 ZIP·autoinst.iso·민감 로그를 GitHub/외부 공유하지 않는다.
5. 통합 관문별 증거는 [통합 검증 체크리스트](integration-checklist.md), 팀원별 합의는 [의사결정 기록](decisions/ADR-001-governance-and-policy-status.md)에 업데이트한다.
