# SecureOps 프로젝트 진행 현황 — 2026-11-19 갱신

> **기준일:** 2026-11-19 (KST) · **원본 main:** `2fac2a02edb1edf08cf4435138f4a1d543e33ba2` · **문서 상태:** docs 전용 PR 검토 중.  
> 기존 11/12 기준 기록은 아래 부록에 내용 그대로 보존하되, 문서 안의 제목 계층만 조정했다. 현재 상태 판단은 **이 문서 상단의 11/19 기록과 [통합 검증 체크리스트](integration-checklist.md)**를 우선한다.  
> **증거 구분:** 팀장 직접 실행 보고 / 담당자 제출 증거 / GitHub PR 상태 / 향후 구축 계획을 구별한다. 신규 원본 로그·SHA 대조 또는 제3자 독립 재검증을 실시하지 않은 사항은 완료로 승격하지 않는다.

## 1. 11/19 전체 현황

| 구분 | 11/19 판단 | 증거·한계 |
| --- | --- | --- |
| **기본 중간발표** | **완료(11/18)** | 팀장 발표 완료 및 화면공유 녹화·21분 26초 영상 업로드. 최종 제출용 MP4/PDF/README 완료와 구분 |
| **SSH-01 중앙 E2E (Ubuntu)** | **완료(11/16, 팀장 직접 실측)** | central-mgmt → ubuntu-a; 승인된 읽기 전용 수집 → B 판정 `vulnerable` → JSON v1.2/CVSS `pending`·`null` → D ReportStore 저장·재조회 확인 |
| **SSH-01 중앙 E2E (Rocky)** | **완료(11/16, 팀장 직접 실측)** | central-mgmt → rocky-b; 위 흐름을 **별도 실행**으로 확인. 두 대 동시 일괄 스캔 완료로 해석하지 않음 |
| **최소권한 SSH 수집** | **SSH-01 범위 실측** | 수집기 허용 1건과 비허용 3건 차단, 복구 절차·기존 sudoers 보존 확인. 일반 C 수집 sudo 권한 승인과 별개 |
| **B/C → D** | **오프라인 수신·집계·저장 근거 확보 / 실제 전체 중앙 수집 미완료** | C의 11/12 Ubuntu/Rocky 실제 CLI JSON 16개와 D의 11/13 오프라인 보고서 4개 저장·재조회; B SSH-02/ACC, C FILE/SVC/FW/LOG 원격 수집 계약 미확정 |
| **E 조치** | **MOCK 검증 / 실서버 조치 미실시** | PR #23 관련 기존 MOCK 204개와 후속 Draft PR #35의 MOCK 회귀 216개(204개+신규 12개) 통과 보고. 후자는 PYTHONUTF8=1 검증 환경 기준; 실서버 조치 미실시, 두 PR 모두 미병합 |
| **GNS3/OPNsense·망분리·서비스·IDS/WAF** | **설계·착수 준비, 구축 미완료** | A의 11/19 PC 점검: GNS3/GNS3 VM 미설치. Windows 로컬 GNS3+VMware VM 노드 **1단계 연동 확인만 승인**. 설치·통신 증거 수신 전 구축 완료 표기 금지 |
| **웹 취약점 3건** | **대기(최종 필수)** | 팀장 담당. 허가·격리된 환경에서 SQLi / XSS / 파일 업로드 각 분석 보고서 및 수정·재검증 증거 확보 필요 |
| **자동 실행·대시보드** | **후속 구현·시연 필요** | ReportStore 보유 사실만으로 자동 반복 실행 또는 대시보드 완성으로 표기하지 않음 |

11/16 실측의 `PASS`는 **진단 파이프라인 동작 성공**을 뜻한다. 서버 SSH 정책 판정은 양쪽 모두 `vulnerable`(`PermitRootLogin without-password`)이며, 실제 서버 보안 조치를 완료했다는 뜻이 아니다. 신규 11/19 실VM 재실행을 수행했다고 주장하지 않는다.

## 2. 11/19 팀원별 작업과 인계 조건

| 역할 | 확인된 진행 | 다음 승인/검증 단계 |
| --- | --- | --- |
| 팀장(양지혁) | 11/16 Ubuntu·Rocky SSH-01 개별 E2E 직접 검증, 11/18 중간발표, 11/19 팀 승인 원칙 공지 및 A/D 회신 | 11/20 공통 증거·통합 게이트 검토, #24→#26 코드·테스트 확인, 웹 3건의 안전한 실습/보고서 설계, 최종 정책 승인 |
| A(김민우) | 11/19 인프라 v1.0 토폴로지·VM/네트워크·리소스 계획 보고. 본인 PC에서 원본 3대 실행·GNS3 미설치 확인 | **1단계:** 로컬 GNS3 설치/VMware 26 연동 검증만 승인. **2단계:** 원본 백업·복제 승인 대기. **3단계:** OPNsense 신규 구축 승인 대기. 기존 E2E 원본 및 팀장 PC VM 변경 금지 |
| B(최종욱) | SSH-01 `#10/#21` main 병합; SSH-02 `#33`, ACC-01/02 `#36` Open·미병합 | D와 원격 수집 계약·계정/OS 문맥 협의, 실제 중앙 연동 검증 필요 |
| C(김서후) | FILE/SVC/FW/LOG 모듈·11/12 실VM CLI 수집 증거; 당시 FILE/SVC `needs_review`, FW/LOG `error`. LOG 가시성 이유 보완 `#34` Draft·미병합 | 11/20 기존 승인 범위 읽기 전용 재검증 준비. A와 실서비스/허용 명령 대조, D와 원격 수집 계약 협의. FILE/SVC 정책과 FW/LOG 추가 조회 권한 승인 대기 |
| D(조효민) | 11/19 PR 의존성 점검, 기존 MOCK 결합 198개 통과 근거; B/C JSON v1.2 오프라인 처리·ReportStore 기능 보유 | 11/20 **최신 main 기반 오프라인 회귀 실행 승인**. B/C/E 신규 인터페이스 제안 및 #26 문서 불일치 정리. 실제 SSH·VM 신규 실행은 별도 허가 |
| E(박태준) | 승인/백업/조치/재진단/실패 복구 MOCK 근거; `#23` Open·미병합(기존 204개 보고), `#35` Draft(후속 216개, UTF-8 환경 기준·별도 브랜치) | D와 `before_scan_id / execution_id / after_scan_id` 계약 협의. 실서버 조치 및 운영 권한 변경은 별도 팀장 승인 전 금지 |

기능이 존재하는 것, PR이 병합된 것, 11/16 실제 VM에서 성공한 것, 11/20 새로 재검증한 것은 **서로 다른 완료 조건**이다.

## 3. GitHub 기준 및 미병합 관리

11/19 GitHub 대조 기준: main `2fac2a02`. 아래는 확인된 주요 Open PR이며, 별도 승인 없이 병합하지 않는다.

| PR | 상태 | 구분 |
| --- | --- | --- |
| [#24](https://github.com/YJH-secure/SecureOps/pull/24) / [#26](https://github.com/YJH-secure/SecureOps/pull/26) | 둘 다 Draft·미병합 | SSH-01 수집기와 중앙 실행기. **#26은 #24에 의존**; 11/16 E2E 성공은 해당 통합 실험 환경의 근거이며 순수 main 완료가 아님 |
| [#20](https://github.com/YJH-secure/SecureOps/pull/20) / [#25](https://github.com/YJH-secure/SecureOps/pull/25) / [#30](https://github.com/YJH-secure/SecureOps/pull/30) | Draft·미병합 | D의 연동/교차 검증 근거. 증거 PR을 런타임 main 구현과 혼동 금지 |
| [#23](https://github.com/YJH-secure/SecureOps/pull/23) | Open·미병합 | E v1.2 및 MOCK 재진단·이력. 최신 main에 실행 이력 연동이 반영된 것으로 표기 금지 |
| [#33](https://github.com/YJH-secure/SecureOps/pull/33) / [#36](https://github.com/YJH-secure/SecureOps/pull/36) | Open·미병합 | B 추가 진단 항목. 실제 중앙 원격 실행 근거 별도 |
| [#34](https://github.com/YJH-secure/SecureOps/pull/34) | Draft·미병합, HEAD `db7afd0` | LOG-01 journal 가시성 제한 이유만 보완; `error` 판정 유지. 신규 VM 비교 검증 전 배포·병합 보류 |
| [#35](https://github.com/YJH-secure/SecureOps/pull/35) | Draft·미병합 | E 범용화 작업. `#23`에 의존하는 브랜치이며 실제 서버 조치 승인과 무관 |

## 4. 공통 기술·승인 운영 규칙 (11/19 팀장 공지)

1. B/C/D/E/A 담당자 간 **기술 협의 및 담당 브랜치 독립 개발·MOCK 테스트는 직접 진행**한다. 팀장이 모든 토론을 중계하지 않는다.
2. **공통 정책, JSON v1.2 계약, 모듈 간 인터페이스 확정, 서버/방화벽/SSH/sudo 권한 변경, 실제 배포, main PR 병합은 팀장 최종 승인 후** 적용한다. 담당자들끼리 협의했다는 이유만으로 승인으로 간주하지 않는다.
3. 승인 요청은 **목적·대상·변경 전후·영향 모듈·검증 증거·안전/복구 대책**을 제시한다. **착수 승인**과 **반영·병합 승인**은 별개다.
4. JSON v1.2 다섯 상태: `pass / vulnerable / error / not_applicable / needs_review`. CVSS v3.1 `pending` 점수는 `null`, 임의 수치 변환 금지. 판정 불가능·권한 부족을 `pass`로 만들지 않는다.
5. 11/19 A에게는 **GNS3 1단계(로컬 설치·VMware 연동 확인)**만 승인했으며 2·3단계, VMnet 대체안, WAN 경유 관리 GUI 임시 개방은 대기한다. GNS3 전용 SSH-01 `ROOT_CONTEXT`/`targets.json`은 B/D/A 협의 후 **기존 원본 덮어쓰기 없이** 팀장 최종 승인한다.
6. C에게는 **기존 승인 범위 읽기 전용 11/20 재검증 준비**만 승인. 신규 FILE/SVC 판정 기준, FW/LOG 추가 sudo 조회 권한, #34 배포·병합은 보류한다.
7. D에게는 **11/20 최신 main 오프라인 통합 회귀**만 승인. B/C/E 인터페이스와 신규 SSH·VM 실행은 별도 승인 대상으로 남긴다.
8. 계정 비밀번호·개인키·접근 토큰·민감 설정/백업 ZIP·비식별 전 원본 로그를 공개 저장소와 채팅방에 게시하지 않는다. 검증 산출물은 원본 보관 위치와 해시를 접근 제한 하에 관리한다.

## 5. 11/20 검증 계획과 팀장 인수 기준

| 주체 | 우선 제출물(11/20) | 팀장 확인 기준 |
| --- | --- | --- |
| A | GNS3 로컬/VMware 연동 결과, VM 인식 성공 또는 오류 로그·대체안 영향 | 원본 VM 및 팀장 PC 불변, 연동 증거; 성공 전 단계 2·3 실행 금지 |
| B+D | SSH-02/ACC 진단 중앙 수집 계약 초안, OS/SSH 문맥·스키마 | 단독 로컬 테스트와 실제 중앙 실행을 구분, 미확정은 제안으로 표시 |
| C+A+D | FILE/SVC/FW/LOG 현재 서비스·권한 대조 및 읽기 전용 검증 증거/차단 요인 | 실행 대상·명령·권한·종료 코드·OS·JSON v1.2·오류 사유 보존; 미승인 정책은 `needs_review` 유지 |
| D+E | 조치 이력 ID 연계 계약안 및 최신 main 오프라인 회귀 로그 | `before_scan_id / execution_id / after_scan_id` 무결성 제안, MOCK/실서버 혼동 금지 |
| 팀장 | 정책·권한/네트워크/인터페이스 최종 승인표, PR #24→#26 및 문서 갱신 검토 | 실제 증거 없는 완료 체크 금지, 코드/설정 변경 승인과 병합 승인 분리 |

**최종 일정(기존 팀 계획):** 12/01(화) 18:00 제출 목표, 12/02(수) 발표. 기본 과제 1~4단계(서버·네트워크/자동 진단·조치/통합·대시보드/웹 SQLi·XSS·파일 업로드 보고서 3건)와 PDF·PPT·MP4·README 재현 자료는 아직 최종 완료가 아니다. 심화 단계의 IDS/WAF·대규모 네트워크 확장은 실제 검증과 필수 과제 충족 여부를 구분한다.

---

## 부록 A. 2026-11-12 기존 프로젝트 현황 (역사적 스냅샷, **현재 기준 아님**)

> 아래는 11/12 당시 문구와 숫자·대기 상태를 그대로 보존한 자료다. 예를 들어 “중간발표 준비 중”, “신규 VM SSH-01 미실시”는 **11/19 현재 사실이 아니다**. 최신 판단은 반드시 위 1~5장을 따른다.


### SecureOps 프로젝트 진행 현황 — 2026-11-12 갱신

> **기준**: 2026-11-12 팀장 검토, **기능 검증 당시의 main 기준 커밋** `62d1bf72ef52c7455bc0c2dd624206eb8350f925` 및 아래 PR/팀원 보고. 현재 main HEAD는 관리 문서 병합으로 달라질 수 있으므로 본 SHA를 실험 재현 기준으로 해석한다. `main에 병합` / `오프라인 검증` / `신규 VM 실측` / `정책·권한 승인`을 구별한다. **11/11 원문은 Git 이력으로 보존하며 아래가 최신 팀장 관리 상태다.** 직접 재실행하지 않은 숫자는 담당자 제출 로그·화면에 기초함.

#### 1. 기본·심화 일정과 범위

**[4개 발표·제출 마일스톤 상세](milestones-basic-deep-20261112.md)**

| 단계 | 일자(KST) | 확정할 범위 |
| --- | --- | --- |
| 기본 프로젝트 중간 발표 | **11/18(수)** | 시스템 설계와 신규 VM 최소 1대 중앙 SSH-01→B 판정→D v1.2 저장·재조회 실측 목표; C 오프라인, E MOCK를 실제 결과와 구분 |
| 기본 프로젝트 최종 제출/발표 | **12/01(화) 18:00 / 12/02(수)** | 기존 과제 1~4단계(서버·네트워크 / 자동 진단·조치 / 통합·대시보드 / 웹 취약점 **SQLi·XSS·파일 업로드 분석 보고서 3건**)와 PDF·PPT·MP4·README |
| 심화 프로젝트 중간 발표 | **12/22(화)** | **제안 범위**: GNS3 내부/DMZ/외부·OPNsense·Suricata/IDS·WAF·DNS/FTP 구축·초기 이벤트 연계 |
| 심화 프로젝트 최종 발표 | **2027/01/11(월)** | **제안 범위**: 서버 진단 + 네트워크/웹 경보 + 승인 조치·재진단·감사 이력의 통합 검증 |

> 심화 주제·평가 요구는 강사/공식 심화 가이드의 승인 전까지 확정된 필수 과제라고 표시하지 않는다. 기본 발표는 심화 전체 기능을 요구하지 않는다.

#### 2. 현재 합의된 데이터·보안 기준

- 신규 결과 JSON **v1.2**, CVSS **v3.1 Base**. 기존 v1.1은 선택 출력·호환 경로로 유지.
- 스캔: `schema_version=1.2`, `scan_id/target_id/os/scanned_at/results`. 개별: `check_id/status/evidence/recommendation/cvss`, 선택 `details`. v1.2 개별 `severity` 사용 금지.
- 상태: `pass/vulnerable/error/not_applicable/needs_review`; CVSS 평가: `scored/pending/not_applicable`. 평가 보류 점수는 **null**; severity를 임의 점수로 환산하지 않음.
- 이행률 `pass/(pass+vulnerable)`; 오류·해당없음·검토필요 제외.
- sudoers·운영 정책·보안 조치는 명시적 관리자 승인·백업/복구·권한 확인 뒤에만. 개인키/비밀번호/해시/백업 ZIP을 커밋하지 않음.

#### 3. 팀원별 실제 상태 — 11/12

| 담당 | 구현·오프라인/로컬 검증 증거 | 아직 완료하지 않은 관문 | 다음 담당 |
| --- | --- | --- | --- |
| **팀장 양지혁** | PR [#24](https://github.com/YJH-secure/SecureOps/pull/24) SSH-01 수집기·[#26](https://github.com/YJH-secure/SecureOps/pull/26) 중앙 실행기 **Draft**; 새 로컬 Worktree `feature/ssh01-main-verify-yjh-1112`에서 PR24+PR26를 main 62d1bf7에 결합, Windows Python 3.14.10 D/SSH 180회(179 pass, 클래스 Skip 1), C 163/163, git diff/check 통과(사용자 제공 화면). **로컬 검증이지 신규 VM 실측 아님.** | 기존 sudoers와 SSH-01 전용 파일 분리 최종 검토, SSH 별칭·`sshd -T -C` 컨텍스트 확정, 승인된 대상 1대에서 실행 및 D 저장; PR24→26 리뷰/병합 | A·팀장, D |
| **A 김민우** | PR [#9](https://github.com/YJH-secure/SecureOps/pull/9) Open, `0a9773d`; central-mgmt `.10`→ubuntu-a `.20`/rocky-b `.30` SSH 키 별칭/출발 IP 확인; ubuntu-a `user1` 비밀번호 조치, ISO/FLOPPY 제거·재부팅, 새 스냅샷 및 ZIP 해시·파일·복원 부팅 검증을 문서/증거로 보고 | 팀장 요청 SSH -G/Host/Match 문맥, 기존·전용 sudoers 확인; GNS3·망 분리 실연동, central/rocky 복원성 추가 검증 | A·팀장 |
| **B 최종욱** | SSH-01 [#10](https://github.com/YJH-secure/SecureOps/pull/10), v1.2 [#21](https://github.com/YJH-secure/SecureOps/pull/21) **main 병합**. SSH-02 판정안 제출·팀장 읽기 전용 개발 방향 승인, 개인 Ubuntu 실측(정책 제안) | SSH-02 코드/Mock, ACC-01/02 개발·납기 검증, 신규 VM 판정, 계정별 Match 처리 | B·팀장 |
| **C 김서후** | FILE/SVC/FW/LOG #15/#22와 v1.2 [#27](https://github.com/YJH-secure/SecureOps/pull/27) **main 병합**; C 163, 상태 5/5, 거부 28/28, D 원본 MOCK; Python 3.12 공식 main 재검증. C 원격 수집 어댑터·권한 인계 분석 완료 보고 | 실제 대상의 FILE/LOG metadata, SVC/FW OS·hostname, sudo/권한 예외, LOG-01 자동 판정·미승인 정책; 신규 VM 실측 | C·A·팀장 |
| **D 조효민** | D Core [#8](https://github.com/YJH-secure/SecureOps/pull/8), CVSS [#19](https://github.com/YJH-secure/SecureOps/pull/19) **main 병합**; C→D 최신 main 독립 MOCK 증거 [#20](https://github.com/YJH-secure/SecureOps/pull/20) Draft/커밋 `b72909d`(88개 추가); D↔E 독립·교차 검증 [#30](https://github.com/YJH-secure/SecureOps/pull/30) Draft/커밋 `d5a6a6f`(증거 93개). Windows Python 3.14 별도 D 204+8+181 실행(중복 제거 고유 ID 309), E Python 3.12 208 실행 증거 교차 확인 | 신규 VM B/C 실측 JSON 수신·집계·저장·재조회, 자동 실행·간단 대시보드, E 운영 저장 호출 계약 | D·팀장·E |
| **E 박태준** | E v1.2/CVSS·실행 이력 [#23](https://github.com/YJH-secure/SecureOps/pull/23) **Open·미병합**, `b0ef73a`; MOCK 204개 및 Python 3.12 추가 MOCK 포함 **208 실행 통과 보고**, D 독립 교차 검증 [#30](https://github.com/YJH-secure/SecureOps/pull/30) 자료 | #23 병합 전 증거·코드 최종 확인; 실제 조치 권한·승인·백업/복구 사전 계획, 중간 발표 E MOCK 시연 | E·D·팀장 |

#### 4. 주요 PR·Issue 상태와 처리 방침

- **main 병합 완료**: B #10/#21, C #15/#22/#27, D #8/#19, E 초기 MOCK #16, fixture 수정 #29, JSON/CVSS 개발 정책 #18 등. `main` 공식 SHA 62d1bf7.
- **Open·미병합**: A [#9](https://github.com/YJH-secure/SecureOps/pull/9), E [#23](https://github.com/YJH-secure/SecureOps/pull/23), 팀장 [#24](https://github.com/YJH-secure/SecureOps/pull/24) → [#26](https://github.com/YJH-secure/SecureOps/pull/26), D 근거 자료 Draft [#20](https://github.com/YJH-secure/SecureOps/pull/20)/[#25](https://github.com/YJH-secure/SecureOps/pull/25)/[#30](https://github.com/YJH-secure/SecureOps/pull/30), 역사 문서 Draft [#17](https://github.com/YJH-secure/SecureOps/pull/17).
- **병합 순서/안전성:** #24의 최소권한 배포 문서·코드 확인 후 #24 → #26. E #23은 #30 증거 교차 대조 후 검토·병합. A #9은 인프라 한정 변경 검토 후. D 증거 Draft는 중복 ZIP/과거 테스트 포함 여부를 살펴 필요할 때만 병합. 기존 PR을 임의 병합·닫지 않음.
- 담당 기능 이슈 [#2](https://github.com/YJH-secure/SecureOps/issues/2)~[#7](https://github.com/YJH-secure/SecureOps/issues/7)은 전부 Open. **코드 일부가 완료여도 이슈 전체에는 실서버·발표·정책 승인 게이트가 남으므로 무조건 닫지 않는다.** 초기 체크리스트와 오늘의 검증 근거를 별도 표기한다.

#### 5. 실제 인프라·원격 실행 게이트

- VMware VMnet8 NAT: central-mgmt Ubuntu 24.04.5 `192.168.10.10`; ubuntu-a Ubuntu Desktop 24.04.5 `.20`; rocky-b Rocky 9.8 Desktop `.30`. 중앙 `secureops-scan`/별도 `secureops-fix` 키 인증 보고. **실제 SSH-01 중앙 수집기 신규 VM 설치·실행은 아직 미완료.**
- PR24 안전 방침: 별도 `/usr/local/sbin/secureops-ssh01-read` 및 `/etc/sudoers.d/secureops-ssh01-read` 제안. 기존 `/etc/sudoers.d/secureops-scan`은 보존. root 소유·0440·sudoers 정확한 무인자 실행·SELinux/visudo 검증 및 관리자 승인 전 설치 금지.
- `sshd -T -C`의 `addr`은 client 출발지 `.10`, `host`는 평가용 클라이언트 호스트 문맥(SSH alias와 무관)으로 별도 검증. 승인되지 않은 값은 작성·운영 배포 금지.
- C 실제 실행 설계: 1차로 **대상 VM에서 C CLI 로컬 진단**, 중앙 서버가 승인된 SSH로 고정 작업을 트리거하고 JSON을 수신하는 방향. FILE collector/environment·LOG metadata/config·OS 정보·실행 오류 경계를 분리. 자동 sudo 없음; 세부 명령별 승인 필요.
- 인프라 ubuntu-a 신규 백업 복원 검증 완료 보고; 과거 00/01 스냅샷 및 백업에는 이전 자격증명 상태가 남으므로 보관 접근 제한·일반 복구 사용 금지, 삭제는 별도 승인. central/rocky 동일 수준 복원 테스트는 별도 확인.

#### 6. 11/18 전에 해결해야 하는 일과 최종 제출 위험

| 우선 | 기한 | 담당 | 증거 기준 |
| --- | --- | --- | --- |
| P0 | **11/12~13** | A+팀장 | SSH alias 설정, SSHD 평가 컨텍스트, 별도 sudoers·고정 명령·권한 계획; 원본 설정 변경 금지 |
| P0 | **11/16 18:00** | 팀장+A+B/D | 신규 VM 한 대에서 SSH-01 읽기 전용→B JSON v1.2→D 저장·재조회, 실제 명령/로그/원시 결과; 실패 시 MOCK과 명시적 구분 |
| P1 | **11/13** | B+C | SSH-02/ACC 남은 범위·납기, C OS별 명령·권한·미승인 정책 목록 동결 |
| P1 | **11/16** | D+E | E #23/#30 리뷰, E MOCK 발표 화면·승인/롤백 스토리; 운영 서버 조치 승인 없음 |
| P0 | **11/17 18:00** | 전원 | 20분 발표/10분 질의응답용 PPT·시연·대본 및 리허설·증거 동결 |
| P0 | **12/01 18:00** | 전원 | 기본 1~4단계, 웹 SQLi/XSS/파일 업로드 보고서 3건, PDF·MP4(5~10분·100MB 이하)·README/PPT 제출 |

- **심화 네트워크 확장:** GNS3/OPNsense/Suricata/WAF/DNS/FTP·내부/DMZ/외부 구현 증거는 아직 완성으로 인정하지 않음. 기본 최종의 필수 1~4단계를 우선하고 심화 마일스톤은 별도 킥오프·가이드로 확정.
- **웹 3건**: 현재 공식 완료 증거가 부족함. 팀장 주도 허가된 격리 웹 분석·보고서를 기본 최종 전에 별도 일정 확보.
- **자동 실행/대시보드**: D Core JSON 저장과 구별, 기본 최종에 최소 동작 화면·반복 실행 증거 필요.
- **운영 정책**: FILE/SVC/FW/LOG·LOG-01 등 미승인 조건을 `pass`/CVSS scored로 오표기 금지.

#### 7. 유지관리 규칙

1. **PR 병합/독립 검증/실서버 성공 때 해당 Issue 체크와 이 문서의 상태를 함께 갱신**한다. GitHub PR 병합이 문서·이슈를 자동으로 수정하지 않는다는 점을 전제로 한다.
2. 로그에는 날짜·담당·SHA·OS/Python·데이터 출처(MOCK/fixture/old ZIP/new VM)·테스트 건수/Skip·증거 링크를 반드시 기록. 중복 실행 횟수를 고유 테스트 수로 표시하지 않는다.
3. 기본 중간 발표, 기본 최종 발표, 심화 프로젝트를 서로 다른 관문으로 취급한다. [통합 검증 체크리스트](integration-checklist.md)의 실제 실환경 완료 증거만 발표에서 '실환경 검증 완료'로 선언한다.
4. **관리 문서 수정은 별도 docs PR로 검토 후 반영**하여 운영 브랜치와 PR을 건드리지 않는다. 자동 마감 점검 보고는 별도로 실제 파일 수정이 완료됐는지 확인해야 한다.
