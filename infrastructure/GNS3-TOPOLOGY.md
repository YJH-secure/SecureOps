# SecureOps GNS3 토폴로지 v1.0 (최종 프로젝트 착수안)

**작성:** 김민우 (A · 서버·네트워크 인프라) · 2026-11-19  
**기준:** `NETWORK-PLAN.md` v0.3(2026-11-12 6대 구성 채택, 11-13 WEB→DB 설계 예외 승인)을 실제 구축용으로 구체화했다.  
**상태:** **1단계 완료(11/19), 2단계 완료(11/20, 결과 수용).** 3단계(OPNsense 구축·복제본 GNS3 연결·IP 변경)는 아직 승인 전이며, 이후 단계도 단계별 검증 후 승인한다(아래 승인 현황, 7장, 9장).

## 승인 현황 (2026-11-19 팀장 회신)

| 항목 | 결정 |
| --- | --- |
| 방향 | 원본 VM과 팀장 PC E2E 환경은 유지하고, GNS3 작업은 복제본·신규 VM에서만 진행하는 방향에 **동의**. 단계별로 검증한 뒤 다음 단계를 승인 |
| D1 (GNS3 VM 미사용) | Windows 로컬 GNS3 + VMware VM 연동 방식으로 **우선 검증하도록 승인**. 조건: VBS를 해제하지 않고 기존 VM 설정을 바꾸지 않음 |
| 1단계 | **승인 → 완료(11/19), 결과 접수.** GNS3 2.2.61 설치, VMware 26에서 VM 3대 인식(R2 해소), VPCS ping·Wireshark ICMP 확인, 설치 전후 기존 VM NIC·VMware 망 설정 차이 0건. 증거 `evidence/gns3-host/gns3-host-*-261119.png` 9장 |
| 2단계 | **승인(11/19, 11/20 실행).** 범위: 원본 백업(파일별 SHA-256, VM별 ZIP 3개, 압축 무결성, 1개 복원 시험), Full Clone, 복제본 망 분리, 원본 재검증. 조건: ① 정상 종료·종료 시각 사전 공유·진행 중 SSH/E2E 없음 확인 ② 스냅샷·관련 디스크 누락 없음 ③ 인증정보 포함 백업·복제본은 접근 제한 로컬 저장소, GitHub·공유 금지 ④ 원본과 다른 경로, 복제본 NIC 전원 켤 때 연결 안 함(VMnet8 연결 금지) ⑤ 원본 재기동 후 NIC·스냅샷·SSH 동일 확인 ⑥ 복제본만 정리(원본 삭제·덮어쓰기 금지). **범위 밖:** 복제본 부팅, GNS3 연결, 신규 IP, 방화벽 **→ 완료(11/20 10:59 종료 시작, 11:33 원본 재가동), 결과 수용(11/20).** 상세 9장 |
| 3단계 | 2단계 검증 후 **별도 승인** (복제본 부팅·GNS3 연결·신규 IP 포함, OPNsense 설치, 방화벽 정책 적용) **(11/20 팀장)** 복제본 3대는 전원 OFF·NIC 자동 연결 해제를 유지하고, 남아 있는 VMnet8 지정·원본 MAC은 3단계에서 별도 승인된 네트워크·MAC 처리 후 부팅한다. OPNsense 구축·IP 변경은 **아직 승인 안 됨** |
| D3 (IP 대역) | 관리 `10.40` / DMZ `10.20` / 내부 `10.30` / 시험 `10.10` 설계 방향 **유지** |
| R2 (연동 실패 시) | VMnet 대체안으로 **바로 전환하지 않는다.** 오류 증거와 대체안의 영향을 먼저 보고 |
| R5 (SSH-01 문맥) | B(최종욱)·D(조효민)와 직접 협의. 기존 `targets.json`·수집기 설정은 덮어쓰지 않고, 실제 접속 문맥을 검증한 뒤 GNS3 전용 설정안 제출 → 팀장 승인 후 적용 |
| R7 (GUI 접근) | WAN 임시 개방은 **승인하지 않음.** 관리망에서 접근하는 대안을 먼저 검토 |

## 0. 11/19 점검 결과 (사용자 PC, 읽기 전용 확인)

VM을 켜거나 설정을 바꾸지 않고 `vmrun`·VMX 파일·Windows 정보만 읽었다.

| 항목 | 결과 | 의미 |
| --- | --- | --- |
| 실행 중인 VM | **3대 모두 실행 중** (`vmrun list`) | 복제(7장 2단계) 전에는 3대를 정상 종료해야 한다 |
| `central-mgmt` | 2 vCPU · 4GB · NIC e1000 · VMnet8 / 스냅샷 `00-initial-setup` → `01-ssh-security-configured` | 정상 |
| `ubuntu-a` | 2 vCPU · 4GB · NIC e1000 · VMnet8 / 스냅샷 `00` → `01` → `01-ssh-security-configured-passwd` | 정상 (일반 복구 기준 `-passwd`) |
| `rocky-b` | 2 vCPU · 2GB · NIC **vmxnet3** · VMnet8 / 스냅샷 `00` → `01` | 정상 |
| VM 폴더 크기 | 6.6GB / 9.6GB / 10.6GB (합계 약 27GB) | 복제·백업 공간 계산 근거 |
| SSH-01 수집기 | 사용자 PC VM에는 **없음** (`02-pre-ssh01-collector-20261116` 스냅샷도 없음) | 수집기는 팀장 PC VM에만 있다 |
| VMware Workstation | 26.0.0 설치됨 | GNS3 연동 버전 호환은 설치 후 확인 필요 (6장 R2) |
| GNS3 / GNS3 VM | **설치 안 됨** | 실행 상태 점검 대상 없음 → 설치부터 필요 |
| Windows VBS(가상화 기반 보안) | **실행 중** | VMware가 Hyper-V 위에서 동작 → GNS3 VM 안에서 중첩 가상화(KVM)가 사실상 불가 (6장 R1) |
| 가상 네트워크 | VMnet1 `192.168.54.0/24`, VMnet8 `192.168.10.0/24` | 추가 VMnet 없음 |
| 호스트 자원 | RAM 31.9GB, i7-12700KF 12코어/20스레드 | 시험 중에는 다른 프로그램 사용을 제한한다 |
| 디스크 | C 여유 **87GB**(11/12 130GB에서 감소), E 여유 1,447GB | 신규 VM·복제본·백업은 **E 드라이브** |

> 팀장 PC VM(수집기 설치본)의 상태는 이번에 확인하지 못했다. 팀장 PC VM은 **건드리지 않는 기준 환경**으로 둔다(4장).

## 1. 결정 사항 요약 (제안)

| # | 제안 | 이유 |
| --- | --- | --- |
| D1 | **GNS3 VM은 쓰지 않는다.** GNS3(Windows 로컬 서버) + VMware VM 노드 + GNS3 내장 스위치로 구성 | VBS 때문에 GNS3 VM 안에서 KVM 가속이 안 된다. 모든 장비를 VMware VM으로 두면 중첩 가상화가 필요 없고 RAM 4GB도 아낀다 |
| D2 | **기존 VM 3대는 원본을 그대로 두고, 전체 복제(Full Clone)본을 GNS3에 쓴다** | 원본(VMnet8)과 SSH-01 E2E 환경이 전혀 바뀌지 않는다. 문제가 생기면 복제본만 버리면 된다 |
| D3 | IP 대역은 v0.3 값을 **그대로 확정** (관리 `10.40` / DMZ `10.20` / 내부 `10.30` / 외부 시험 `10.10`) | 이미 팀 문서·발표 자료에 쓴 값이라 혼동이 없다. 현재 `192.168.10.0/24`와 겹치지 않는다 |
| D4 | 방화벽 기본 정책은 **모두 차단, 허용 목록 방식** | v0.3 4장 원칙 유지 |
| D5 | Suricata는 **IDS(탐지)만** 먼저, IPS는 자원·일정 검토 후 | 팀장 지시. 오탐 시 서비스가 끊기는 위험이 없다 |

## 2. 토폴로지 v1.0

```
                     [Windows 호스트 · VMware NAT VMnet8 192.168.10.0/24 · GW .2]
                                         |
                                (GNS3 Cloud 또는 직접 연결, R4)
                                         | WAN  vmx0  192.168.10.100 (고정, 확정 전)
                              +----------+-----------+
                              |      OPNsense        |  Suricata IDS (WAN·OPT1·OPT3 감시)
                              |  GW for all zones    |
                              +--+------+------+-----+
            LAN vmx1 10.40.0.1   |      |      |   OPT3 vmx4 10.10.0.1
           +---------------------+      |      +----------------------+
           |                 OPT1 vmx2  |  OPT2 vmx3                  |
           |                 10.20.0.1  |  10.30.0.1                  |
     [SW-MGMT]                 [SW-DMZ]  [SW-INT]                [SW-EXT]
           |                  /       \        \                      |
   central-mgmt-g      ubuntu-a-g   rocky-b-g  rocky-int        kali (시험 시만)
   10.40.0.10          10.20.0.10   10.20.0.20 10.30.0.10        10.10.0.10
   진단·조치 출발지      웹+WAF        DNS        DB+FTP            외부 접근 시험
```

- `-g`는 GNS3용 복제본(D2). 원본 VM 이름·스냅샷은 그대로 둔다.
- SW-*는 GNS3 내장 Ethernet switch(추가 VM 없음).
- 모든 구간의 기본 게이트웨이는 OPNsense 해당 인터페이스 `.1`.

## 3. VM·IP·서비스 목록

| 구간 | 노드 | OS | vCPU·RAM | 디스크 | IP / GW | 서비스 (예정) | 진단 대상 | 구분 | 담당 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 경계 | OPNsense | OPNsense (FreeBSD) | 2 · 4GB | 32GB (E) | WAN `192.168.10.100`, 각 구간 `.1` | 방화벽, NAT, Suricata IDS, Unbound DNS(구축 초기), syslog 송신 | 아님 | 신규 | A |
| 관리 | `central-mgmt-g` | Ubuntu 24.04.5 Server | 2 · 4GB | 복제 약 7GB (E) | `10.40.0.10/24` / `10.40.0.1` | 중앙 실행기, 결과 저장(D), 승인·조치(E), syslog 수신(예정) | 아님 (진단 주체) | 복제 | A (설정), 팀장·B·D·E (기능) |
| DMZ | `ubuntu-a-g` | Ubuntu 24.04.5 Desktop | 2 · 4GB | 복제 약 10GB (E) | `10.20.0.10/24` / `10.20.0.1` | 웹(Apache/Nginx 미정) + ModSecurity, SSH | 예 | 복제 | 팀장 (WEB), A (망) |
| DMZ | `rocky-b-g` | Rocky 9.8 Desktop | 2 · 2GB | 복제 약 11GB (E) | `10.20.0.20/24` / `10.20.0.1` | DNS(BIND 후보, 재귀 제한), SSH | 예 | 복제 | C |
| 내부 | `rocky-int` | Rocky 9 Server (최소 설치) | 2 · 2GB | 30GB (E) | `10.30.0.10/24` / `10.30.0.1` | DB(MariaDB 후보) + FTP(vsftpd 후보), SSH | 예 (신규 등록 필요) | 신규 | C (서비스), A (설치·망) |
| 외부 시험 | Kali | Kali Linux | 2 · 4GB | 40GB (E) | `10.10.0.10/24` / `10.10.0.1` | 접근·IDS 탐지 시험 도구 | 아님 | 신규, 시험 시만 가동 | A + 팀장 |

**서비스 포트 (C 확정 전 초안):** 웹 TCP 80/443, DNS UDP·TCP 53, DB TCP 3306, FTP TCP 21 + 패시브 포트 범위(설치 시 확정, 예: 30000–30100), SSH TCP 22, syslog UDP 514.

## 4. 예상 자원 사용량

| 노드 | RAM | 동시 가동 (평시) | 동시 가동 (Kali 시험) |
| --- | --- | --- | --- |
| OPNsense (Suricata 포함) | 4GB | O | O |
| `central-mgmt-g` | 4GB | O | O |
| `ubuntu-a-g` | 4GB | O | O |
| `rocky-b-g` | 2GB | O | O |
| `rocky-int` | 2GB | O | O |
| Kali | 4GB | - | O |
| GNS3 프로그램·uBridge·내장 스위치 | 약 0.5GB | O | O |
| **합계** | | **약 16.5GB** | **약 20.5GB** |

- 호스트 31.9GB 기준 평시 약 15GB, 시험 시 약 11GB가 Windows 몫으로 남는다. **시험 중에는 다른 프로그램 사용을 제한한다.**
- vCPU 합계 10~12개 / 호스트 20스레드: 여유 있음.
- 디스크(E): 신규 VM 최대 102GB(OPNsense 32 + rocky-int 30 + Kali 40) + 복제본 약 27GB + 원본 백업 ZIP 약 27GB 이하 = **약 160GB 이하**. E 여유 1,447GB로 충분. C(여유 87GB)에는 새로 만들지 않는다.
- 원본 VM(VMnet8)과 GNS3 복제본은 RAM 때문에 **동시에 켜지 않는다.**

## 5. OPNsense 인터페이스와 방화벽 정책 초안

### 5-1. 인터페이스

| OPNsense 이름 | NIC (vmxnet3) | 연결 | 주소 | 비고 |
| --- | --- | --- | --- | --- |
| WAN | `vmx0` | VMnet8 (NAT) | `192.168.10.100/24`, GW `192.168.10.2` | 고정 IP. 기존 `.10/.20/.30`·DHCP 범위와 겹치지 않는지 설치 시 확인 |
| LAN (관리) | `vmx1` | SW-MGMT | `10.40.0.1/24` | 관리 GUI·SSH는 이 구간에서만 |
| OPT1 (DMZ) | `vmx2` | SW-DMZ | `10.20.0.1/24` | |
| OPT2 (내부) | `vmx3` | SW-INT | `10.30.0.1/24` | |
| OPT3 (외부 시험) | `vmx4` | SW-EXT | `10.10.0.1/24` | 인터넷 경로 없음 |

- NIC 이름은 설치 후 콘솔의 인터페이스 할당 화면에서 확정한다.
- OPNsense 기본값 중 **LAN의 "LAN net → any 허용" 규칙은 삭제**하고 아래 허용 규칙으로 바꾼다(관리 GUI 접근은 기본 Anti-lockout 규칙이 유지).

### 5-2. 별칭(Alias)

| 별칭 | 값 |
| --- | --- |
| `H_CENTRAL` | `10.40.0.10` |
| `H_WEB` | `10.20.0.10` |
| `H_DNS` | `10.20.0.20` |
| `H_DBFTP` | `10.30.0.10` |
| `NET_PRIVATE` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| `P_FTP` | 21, 패시브 범위 (C 확정 후) |

### 5-3. 규칙 (위에서부터 먼저 적용, 들어오는 인터페이스 기준)

모든 허용·차단 규칙에 **로그를 켠다**(증거용). 각 인터페이스 맨 아래는 기본 차단.

| # | 인터페이스 | 동작 | 프로토콜 | 출발 | 도착 : 포트 | v0.3 대응 | 적용 시점 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| L1 | LAN | 허용 | TCP | `H_CENTRAL` | DMZ net, OPT2 net : 22 | #1 | 1단계 |
| L2 | LAN | 허용 | TCP | `H_CENTRAL` | This Firewall : 443, 22 | #2 | 1단계 |
| L3 | LAN | 허용 | UDP·TCP | LAN net | This Firewall : 53, 123 | 구축용 DNS·NTP | 1단계 |
| L4 | LAN | 허용 | UDP·TCP | LAN net | `H_DNS` : 53 | #6 | DNS 구축 후 |
| L5 | LAN | 허용 | TCP | LAN net | `H_DBFTP` : `P_FTP` | #7 | FTP 구축 후 |
| L6 | LAN | 허용 | TCP | LAN net | !`NET_PRIVATE` : 80, 443 | #11 (업데이트) | 1단계 |
| D1 | OPT1 | 허용 | TCP | `H_WEB` | `H_DBFTP` : 3306 | #8-1 (설계 예외) | **별도 승인 후, 그전까지 비활성** |
| D2 | OPT1 | 허용 | UDP·TCP | OPT1 net | This Firewall : 53, 123 | DNS 전달·NTP | 1단계 |
| D3 | OPT1 | 허용 | TCP | OPT1 net | !`NET_PRIVATE` : 80, 443 | #11 | 1단계 (구축 후 끌 수 있음) |
| D4 | OPT1 | 차단(로그) | any | OPT1 net | LAN net, OPT2 net, This Firewall | #8, #9 | 1단계 |
| I1 | OPT2 | 허용 | UDP·TCP | OPT2 net | `H_DNS` : 53 | #6 | DNS 구축 후 |
| I2 | OPT2 | 허용 | UDP·TCP | OPT2 net | This Firewall : 53, 123 | 구축용 | 1단계 |
| I3 | OPT2 | 허용 | TCP | OPT2 net | !`NET_PRIVATE` : 80, 443 | #11 | 1단계 (구축 후 끌 수 있음) |
| I4 | OPT2 | 차단(로그) | any | OPT2 net | LAN net, OPT1 net, This Firewall | #9 | 1단계 |
| E1 | OPT3 | 허용 | TCP | OPT3 net | `H_WEB` : 80, 443 | #3 | 웹 구축 후 |
| E2 | OPT3 | 허용 | UDP·TCP | OPT3 net | `H_DNS` : 53 | #4 (권한 응답만, 재귀 거부는 `rocky-b` 설정) | DNS 구축 후 |
| E3 | OPT3 | 차단(로그) | any | OPT3 net | any (관리·내부·OPNsense·인터넷) | #5 | 1단계 |
| W1 | WAN | 차단 | any | any | any | 기본 | 기본값 유지 |
| S1 | (OPNsense 자체) | 송신 | UDP | This Firewall | `H_CENTRAL` : 514 | #10 syslog | `central-mgmt` 수신 설정 승인 후 |

- **NAT:** WAN 아웃바운드 자동 NAT만 사용(업데이트용). 포트 포워딩은 만들지 않는다.
- **DNS:** 구축 초기에는 모든 서버가 OPNsense(Unbound, 각 구간 `.1`)를 DNS로 쓴다. C가 `rocky-b` DNS를 구축하면 L4·I1·E2를 켜고 서버 DNS 설정을 바꾼다.
- **같은 구간 안의 통신은 OPNsense를 지나지 않는다** (예: `ubuntu-a` ↔ `rocky-b`, 둘 다 DMZ). 이 구간은 호스트 방화벽(FW-01 진단 범위)으로 보완한다(6장 R6).

### 5-4. Suricata (IDS)

| 항목 | 초안 |
| --- | --- |
| 모드 | IDS(탐지만). IPS 차단은 자원·오탐 확인 후 결정 |
| 감시 인터페이스 | OPT3(외부 시험) → OPT1(DMZ) → WAN 순서로 켠다. 처리량 부족 시 줄인다 |
| 규칙 | ET Open 중 scan·web·attack_response 등 최소 범주부터 |
| 탐지 성공 시험 (11/20~) | ① Kali에서 DMZ 웹으로 `nmap` 스캔 → ET SCAN 경보 ② DMZ 서버에서 공개 IDS 시험 페이지 요청 → attack_response 경보 (구체 명령은 시험 문서에 따로) |
| 로그 | OPNsense 경보 화면 캡처 + `central-mgmt`로 syslog 전송(S1) |

## 6. 문제점·위험과 대응

| # | 문제·위험 | 영향 | 대응 |
| --- | --- | --- | --- |
| R1 | Windows VBS(Hyper-V)가 켜져 있어 GNS3 VM 안 중첩 가상화가 사실상 불가 | GNS3 VM에 OPNsense를 QEMU로 올리면 매우 느림 | D1: GNS3 VM을 쓰지 않고 모든 노드를 VMware VM으로. VBS를 끄는 것은 보안 설정 변경이라 하지 않는다 |
| R2 | VMware Workstation 26.0.0과 GNS3의 연동 호환이 확인되지 않음 | GNS3가 VMware VM을 인식·제어하지 못할 수 있음 | 설치 직후 GNS3 VMware 설정에서 VM 목록 인식 확인. 실패하면 **대체안: GNS3 없이 VMware 사용자 정의 VMnet(호스트 전용)으로 같은 구간 분리**(정책·IP 동일). 대체안 사용 여부는 팀장 결정 |
| R3 | GNS3가 VM의 NIC 설정을 자기 vmnet으로 바꿈. 어댑터 종류가 바뀌면 리눅스 인터페이스 이름이 바뀜(`rocky-b`는 vmxnet3 → `ens160`, Ubuntu는 e1000 → `ens33`) | IP 설정이 안 붙어 SSH 불가 | 원본이 아닌 복제본만 GNS3에 등록(D2). 노드별 어댑터 종류를 원본과 같게 지정(Ubuntu e1000, Rocky vmxnet3). 복제 시 MAC이 바뀌므로 netplan/nmcli가 MAC에 묶여 있는지 확인 |
| R4 | WAN을 VMnet8에 붙이는 방식(GNS3 Cloud 노드 vs GNS3가 관리하지 않는 NIC) 미확정 | 인터넷(패키지 업데이트) 경로 | 설치 후 두 방식 중 동작하는 것을 선택. 인터넷이 꼭 필요한 기간은 패키지 설치 때뿐 |
| R5 | **`central-mgmt` IP가 `192.168.10.10` → `10.40.0.10`으로 바뀜.** `ssh01_context`(`targets.json`)와 수집기 `ROOT_CONTEXT`에 `192.168.10.10`이 글자로 들어 있음 | GNS3 환경에서 SSH-01 실행 시 `context mismatch`로 거부 | 원본 환경은 그대로라 기존 E2E는 영향 없음. **B 확인(11/19):** `UseDNS no`이면 `host=`·`addr=`에 둘 다 출발지 IP를 넣는 방식이 GNS3에서도 맞고, 문맥 값은 실행 시 지정하는 값이라 B 코드·테스트·결과 JSON 형식은 영향 없음. 실행기 `ssh01_context`와 수집기 `ROOT_CONTEXT`를 환경별 설정으로 분리. 값은 7장 5단계 실측 후 확정 → GNS3 전용 설정안 → 팀장 승인. 분리 방식·실행 이력 기록은 D와 협의 |
| R6 | 같은 구간 안(DMZ의 웹 ↔ DNS)은 OPNsense가 통제하지 못함 | 웹이 뚫리면 같은 DMZ의 DNS로 이동 가능 | 발표·문서에 한계로 명시하고 호스트 방화벽으로 보완. 필요하면 DMZ를 둘로 나누는 안은 v1.1에서 검토 |
| R7 | 관리 GUI 접근 경로: 관리망에 브라우저가 있는 PC가 없음(`central-mgmt`는 Server 에디션) | OPNsense 웹 설정이 불편 | 초기 설정은 OPNsense 콘솔 메뉴, GUI는 구축 기간에만 호스트(`192.168.10.1`)에서 WAN 주소 443 접근을 출발지 1개로 허용하는 임시 규칙 → Kali 시험 전 삭제. 팀장 승인 필요 |
| R8 | 호스트 RAM 여유 부족 | VM이 느려지거나 시작 실패 | 4장. 시험 중에는 다른 프로그램 사용을 제한하고, Kali는 시험 때만 켠다 |
| R9 | C 드라이브 여유 87GB로 감소 | 복제·백업 시 공간 부족 | 신규·복제·백업 모두 E 드라이브 |
| R10 | 사용자 PC VM과 팀장 PC VM 상태가 다름(수집기 유무) | GNS3 환경에서 SSH-01 E2E 재현 기준 혼동 | GNS3 환경은 사용자 PC 복제본 기준(수집기 없음). 수집기 설치는 팀장 절차로 따로(R5와 함께 결정) |
| R11 | Rocky·Ubuntu Desktop 기본 서비스(cups·avahi)가 DMZ에 생김 | SVC-01 결과 변화 | v0.3 6장대로 B·C와 의도 여부 정리 |

## 7. 구축·전환 순서 (기존 SSH-01 E2E 무영향)

핵심: **원본 VM 3대와 팀장 PC VM은 끝까지 바꾸지 않는다.** GNS3 작업은 새 VM과 복제본에서만 한다.

| 단계 | 일정 | 내용 | VM·운영 환경 변경 | 승인 | 검증·증거 | 복구 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 11/19 | 이 문서, 점검 결과 보고 | 없음 | - | 본 문서 0장 | - |
| 1 | 11/19~20 | 사용자 PC에 GNS3(올인원, 로컬 서버만)·Wireshark 설치, VMware 연동 확인 | 호스트 프로그램 설치, 사용자 정의 VMnet 생성 | 팀장 | GNS3 VMware 설정에서 VM 인식 화면 | 프로그램 제거 |
| 2 | 11/20 | 원본 3대 ZIP 백업(E)·SHA-256, **전체 복제**(현재 상태 → E, 이름 `-g`) | 원본은 읽기만(꺼진 상태에서 복제) | 팀장 | 해시, 복제본 목록 | 복제본 삭제 |
| 3 | 11/20 | OPNsense 신규 설치(E), 인터페이스 5개·별칭·1단계 규칙 | 신규 VM만 | 팀장 | 인터페이스 화면, 규칙 화면, 설치 직후 스냅샷 `00-initial-setup` | 스냅샷 복귀·VM 삭제 |
| 4 | 11/20 | GNS3 프로젝트에 OPNsense·스위치·복제본 연결, 복제본 IP 변경(netplan·nmcli), 중앙 `~/.ssh/config` HostName·`known_hosts`(지문 대조 후) | 복제본만 | 팀장 | 구간별 `ping`·`ip route`, Wireshark 캡처 | 복제본 스냅샷 복귀 |
| 5 | 11/20 | `central-mgmt-g` → DMZ SSH 재검증(HANDOFF 2-4 출발지·키 지문, 2-5 `sshd -T`, `sudo -l`), 허용·차단 시험(L1 허용, D4·E3 차단) | 없음 | - | SSH 성공·차단 캡처, OPNsense 방화벽 로그 | - |
| 6 | 11/21~ | `rocky-int` 신규 설치, 진단 대상 등록(계정·키·sudoers v0) | 신규 VM | 팀장 | README 5장 절차 재사용 | 스냅샷 복귀 |
| 7 | 11/21~25 | C 서비스(DNS·DB·FTP)·팀장 웹 구축 지원, 규칙 L4·L5·I1·E1·E2 활성화, D1(WEB→DB)은 승인 후 | 복제본·신규 VM | 팀장 (D1은 별도) | 서비스별 허용·차단 시험 | 규칙 비활성화, 스냅샷 |
| 8 | 11/22~25 | Suricata IDS, syslog(S1), Kali 외부 시험 | OPNsense, `central-mgmt-g`, Kali 신규 | 팀장 | 경보 화면, 수신 로그 | 기능 끄기, 스냅샷 |

- **진행 현황 (11/20):** 1단계 11/19 완료, 2단계 11/20 완료(9장). 위 표의 일정은 최초 계획이며, 3단계 이후 일정은 3단계 실행안 승인에 따라 다시 정한다.
- 각 단계 시작 전 대상 VM이 꺼진 상태에서 스냅샷을 만든다. 이름은 `NN-<내용>-YYMMDD`(예: `03-gns3-ip-changed-261120`).
- 기존 E2E가 필요할 때는 GNS3 노드를 모두 끄고 원본 VM(VMnet8)을 켜면 그대로 재현된다.
- sudoers·계정·키는 이행 중에 바꾸지 않는다. 복제본에서 바뀌는 것은 IP와 SSH 접속 설정뿐이다.

**5단계 SSH-01 문맥 실측 항목 (B 요청, R5)** — `central-mgmt-g`에서 대상 복제본마다 실행

| 확인 | 명령 (대상에서) | 기대 |
| --- | --- | --- |
| 대상이 보는 출발지 | `echo $SSH_CONNECTION`의 첫 번째 값 | `10.40.0.10` (OPNsense가 구간 사이 NAT를 하지 않음) |
| DNS 역조회 | `sudo sshd -T \| grep -i usedns` | `usedns no` (yes면 `host=`에 역방향 DNS 이름이 들어가야 함) |
| 문맥 적용 결과 | `sudo sshd -T -C user=root,host=<출발지 IP>,addr=<출발지 IP> \| grep -i permitrootlogin` | 원본 환경과 같은 값 |

- `sshd -T -C …`는 현재 scan sudo 허용 범위 밖이므로 `user1`로 확인한다(11/12 2-5와 같은 방식).
- 대상에 `Match Address`/`Host` 같은 접속 위치 조건이 새로 생기면 B에 미리 공유한다. B 판정은 문맥 주소 외의 주소에서 나올 수 있는 값까지 계산하므로 문맥을 여러 개 둘 필요는 없다. "관리망에서만 root 허용" 같은 예외는 현재 기준(no만 pass)에서는 `vulnerable`이며, 예외 인정은 정책 변경(팀장 승인)이다.

## 8. 협업 연결

| 담당 | A가 제공 | A가 받아야 할 것 |
| --- | --- | --- |
| B·D | GNS3 환경 IP·별칭표, 중앙 → 대상 SSH 재검증 결과 | GNS3용 `targets.json`·`ssh01_context` 처리 방식(R5) |
| C | 구간·포트 허용 규칙, 서버 접속 환경 | 서비스별 확정 포트(특히 FTP 패시브 범위), 로그 기준 |
| E | 단계별 스냅샷 이름·복구 방법(7장) | 조치 시험 시 사용할 스냅샷 기준 |
| 팀장 | 단계별 승인 요청, 진행 현황 | 1~3단계 승인, R2 대체안·R5·R7 결정 |

## 9. 2단계 실행 기록 (2026-11-20)

비민감 운영 기록이다. 인증정보가 들어 있는 원본 백업 ZIP·복제본은 호스트 PC의 접근 제한 로컬 드라이브에만 있고, 이 저장소에는 해시 목록·로그·캡처만 둔다. 백업·복제본의 실제 저장 경로는 적지 않는다(README 7-1 원칙).

### 9-1. 사전 점검 (09:40~10:02, 조회만)

| 항목 | `central-mgmt` | `ubuntu-a` | `rocky-b` |
| --- | --- | --- | --- |
| 시스템 상태 | `running`, 실패 서비스 없음 | 같음 | 같음 |
| 중앙→대상 SSH | - | scan 접속, 출발지 `192.168.10.10` | 같음 |
| 파일시스템 | `clean` | `clean`, 이번 부팅에 저널 복구·I/O 오류 메시지 없음 | - |
| 기존 진단 환경 | 회수 폴더 보존 | C 배치 폴더 `2fac2a02` 보존 | 같음 |
| 스냅샷 / NIC | 2개 / e1000·VMnet8 | 3개 / e1000·VMnet8 | 2개 / vmxnet3·VMnet8 |

중단 기준(파일시스템 이상, 실패 서비스, SSH 불가)에 해당하는 항목 없음. 팀원 4명 모두 작업 시간에 진행 중인 SSH/E2E 없음을 확인했다.

### 9-2. 단계별 결과

| 단계 | 시각 | 결과 |
| --- | --- | --- |
| S1 원본 정상 종료 | 10:59:49~11:00:28 | 3대 모두 게스트 정상 종료(VMware 로그 `PM Soft Off`, 강제 차단 기록 없음). `rocky-b`는 VMware soft 종료 요청, `central-mgmt`(11:00:16)·`ubuntu-a`(11:00:28)는 게스트 안에서 종료. 절차서 순서(대상 먼저, 중앙 마지막)와 달리 `central-mgmt`가 `ubuntu-a`보다 먼저 꺼짐(영향 없음). `vmrun list` 0. 종료 직후 남아 있던 잠금 폴더 2개(`rocky-b`·`ubuntu-a`)는 약 5초 뒤 사라짐 |
| S2 파일별 SHA-256 | 11:01~11:02 | 파일 54/55/45개, 스냅샷 수 = `.vmsn` 수(2/3/2), `.vmsd` 각 1개 |
| S3 ZIP·무결성 | 11:02~11:14 | ZIP 3개 모두 `7z t` `Everything is Ok`, ZIP 안 파일 수 = S2 파일 수 |
| S4 복원 시험 | 11:14~11:17 | `central-mgmt` ZIP을 별도 폴더에 풀어 54개 파일 SHA-256 대조 → `problems=0 extra=0`, 시험 폴더 삭제 |
| S5 Full Clone·망 분리 | 11:17~11:32 | `central-mgmt-g`·`ubuntu-a-g`·`rocky-b-g` 생성, `ethernet0.startConnected = "FALSE"`, NIC 종류는 원본과 같음, 부팅 안 함, 스냅샷 0 |
| S6 원본 재가동·재검증 | 11:32:52 재기동 명령, 이후 SSH 확인 | 작업 전후 NIC 설정·스냅샷 목록 차이 0, 중앙→대상 SSH 정상(`secureops-scan`, 출발지 `.10`) |

백업 ZIP SHA-256 (사전 점검·자동 업데이트 반영 후 상태 기준)

| ZIP | 크기 | SHA-256 |
| --- | --- | --- |
| `Central-Management-Ubuntu.zip` | 3,368,678,073 bytes | `47C51EC0C4B2160B6711CE47FE8C56704D46F22A9DC4B39281359ADD6109A52F` |
| `Target-Ubuntu.zip` | 5,303,208,076 bytes | `6F80CCDA65C1B5E794EA20416A6FF405ABA491D716D6CADD982DC1CDFC43AFFB` |
| `Target-Rocky.zip` | 7,372,541,016 bytes | `4505D3847A5F62C5B7814B5F59727A36AAA98B44445E234C2176D7C6058FCB0E` |

### 9-3. 운영 중 확인한 사항

| # | 내용 | 영향 | 처리 |
| --- | --- | --- | --- |
| O1 | **`ubuntu-a`에 VMware Tools(`open-vm-tools`) 미설치.** `dpkg -l` 상태 `un`, 설치·제거 이력 없음(HANDOFF 3-2 VMware Tools 현황과 같음). VMware 쪽 종료(`vmrun stop soft`) 요청이 실패해, 로그가 남아 있는 11/13·11/16·11/19 종료는 모두 강제 전원 차단이었다(그 이전은 로그 순환으로 확인 불가). 11/20 종료는 게스트 안에서 정상 종료 | 오늘 파일시스템 `clean`, 복구 흔적 없음 → 손상 확인 안 됨 | 패키지 설치·설정 변경 안 함. `ubuntu-a`는 **항상 게스트에서 `sudo poweroff`로 종료**한다. Tools 설치는 별도 승인 사항 |
| O2 | **자동 업데이트(`unattended-upgrade`) 실행.** `central-mgmt` 09:46~09:47(libgstreamer, sosreport, needrestart), `ubuntu-a` 09:54(전체 16개: gstreamer 관련 10개, hplip·프린터 드라이버·sane 관련 6개). 두 서버 모두 openssh·커널(`linux-image`) 변경 없음, `ubuntu-a` 재부팅 필요 표시 없음(전체 목록 재확인 `central-mgmt-stage2-autoupdate-full-261120.png`). `rocky-b`는 `dnf-automatic` 미설치 | 백업 직전 원본 패키지가 바뀜. 이후 `central-mgmt` `sshd` 리스너 재시작 기록(`needrestart` 추정), 접속 영향 없음 | 백업 기준을 업데이트 반영 상태로 기록. 자동 업데이트 끄기는 별도 승인 사항(제안) |
| O3 | **복제 경로 변수 사고.** PowerShell 변수는 대소문자를 구분하지 않아 절차서의 `$G`(복제 경로)와 `$g`(복제본 이름)가 같은 변수였다. 그 결과 S5 복제본 3개가 지정 경로가 아닌 **작성자 PC의 저장소 작업 폴더**에 생성됐다 | 원본은 읽기만 해서 영향 없음. 복제본은 untracked 상태였고 스테이징·커밋·push 없음 | 다음 단계 경로 확인 장치에서 발견(그 단계 쓰기 없음) → 지정 경로로 복사, 파일별 SHA-256 대조(16/13/13개, 차이 0) → 작업 폴더 쪽 삭제. 11:49 재확인: 스테이징 없음, ignored 없음, 추적 파일·전체 이력·디스크에 VM 파일·ZIP·키 파일 0건. 절차서에 경고 추가, 겹치지 않는 변수 이름으로 재실행 |

### 9-4. 증거

- `evidence/gns3-host/gns3-host-stage2-{before,shutdown,zip-test,clone,after}-261120.png` — 백업·복제본 경로와 VM MAC은 가림 처리
- `evidence/gns3-host/stage2-hashes-261120/` — 파일별 SHA-256 CSV 3개(파일 이름·크기·해시만), ZIP 해시, 작업 전후 NIC·스냅샷 기록(MAC 가림), S3~S5 로그(경로 치환)
- `evidence/central-mgmt/central-mgmt-stage2-{precheck,precheck-fs,autoupdate,autoupdate-full,sessions,ssh-after}-261120.png`
- `evidence/ubuntu-a/ubuntu-a-stage2-{precheck,tools-cause,autoupdate}-261120.png`

## 10. 3-A 실행 기록 (2026-11-23, OPNsense 설치·콘솔 초기 설정)

팀장 조건부 승인(11/20) 범위: 공식 배포본 확보 → SHA-256 대조 → 격리된 신규 VM 설치 → 콘솔 초기 설정. **결과: 3-A 구축 완료로 수용(11/23).** NIC 연결과 구간별 통신 검증은 3-C 범위이며 아직 하지 않았다.

### 10-1. 결과

| 항목 | 결과 |
| --- | --- |
| 설치 파일 | OPNsense 26.7 `dvd-amd64` ISO(bz2, 494,298,945 bytes). SHA-256 `95cafedda6d5b22ce832e249dc2309110fbee19f813ad78cf28bb3d387186bfb` — 공식 체크섬 파일·공식 릴리스 노트 두 곳과 일치 |
| VM `opnsense-g` | FreeBSD 14 64-bit, vCPU 2, RAM 4GB, 디스크 32GB, 복제본과 같은 접근 제한 E 드라이브 폴더. 클립보드·공유폴더·USB·사운드 끔 |
| NIC | vmxnet3 5개, **모두 `startConnected = "FALSE"`**(링크 `no carrier`) |
| 인터페이스·IP | WAN `vmx0` `192.168.10.100/24` GW `.2`(값만, 미연결) / LAN `vmx1` `10.40.0.1/24` / OPT1 `vmx2` `10.20.0.1/24` / OPT2 `vmx3` `10.30.0.1/24` / OPT3 `vmx4` `10.10.0.1/24`. IPv6 없음, DHCP 서버 없음(67·547 리스너 0) |
| NIC 대응 | MAC 대조 결과 **LAN `vmx1` = VMware 어댑터 5**(ethernet4, PCI 슬롯 순서 때문), 나머지는 vmx0=1, vmx2=2, vmx3=3, vmx4=4. 3-C 연결 때 반영 |
| 스냅샷 | `00-initial-setup-261123`(전원 끈 상태) |
| 사전·사후 비교 | VMnet1·VMnet8 호스트 어댑터, VMware 망 설정 파일 해시, 원본·복제본 VMX NIC 줄 차이 0. Windows IP 포워딩 켜진 어댑터 0 |

### 10-2. 운영 중 확인한 사항

| # | 내용 | 영향 | 처리 |
| --- | --- | --- | --- |
| O4 | **원본 대상 2대 강제 종료(09:44).** OPNsense 첫 기동 직후 일시정지하자 VMware가 그 탭을 닫고 화면을 `Target-Rocky` 탭으로 자동 전환 → 이어진 전원 메뉴 클릭이 `rocky-b`(전원 끄기)·`ubuntu-a`(게스트 종료 → Tools 없어 강제 종료)에 적용됨(UI 로그 `MenuButtonClicked`). 10:02 재기동 | Windows 이벤트 오류 없음, vmrun 호출 없음. 재기동 후 failed unit 0, 파일시스템 오류 0, C 16개 해시 일치, 원본 NIC 설정 같음 | 원본이 켜진 동안 GNS3 노드를 켜지 않음(팀장 지시). GNS3 노드는 다른 VMware 창에서 조작, 원본 종료는 콘솔 `sudo poweroff`만, 일시정지 사용 안 함 |
| O5 | `ubuntu-a` 11/23 09:35 자동 업데이트 `python3-jwt` 1개 | openssh·커널·Python 변화 없음, C 진단 코드 무관 | 기록만. 자동 업데이트 비활성화는 보류 유지 |

### 10-3. 증거

- `evidence/gns3-host/gns3-host-stage3a-vm-settings-nic{1..5}-261123.png` — NIC 5개 연결 안 함
- `evidence/gns3-host/gns3-host-stage3a-console-{menu,assign,ip,check}-261123.png` — 설치 직후, 할당, IP, 버전·링크·DHCP(check는 MAC 가림)
- `evidence/central-mgmt/central-mgmt-scan-sudo-recheck-261123.png` — `secureops-scan` sudo 목록 재확인(C/D 계약용)
- `evidence/central-mgmt/central-mgmt-targets-reboot-check-261123.png` — O4 재기동 후 상태

## 변경 이력

| 버전 | 일자 | 내용 |
| --- | --- | --- |
| v1.0 | 2026-11-23 | 10장 3-A 실행 기록(OPNsense 26.7 설치·초기 설정, NIC 대응, O4 강제 종료 원인, O5 자동 업데이트, 증거) |
| v1.0 | 2026-11-20 | 2단계 완료·결과 수용 반영(상단 상태, 승인 현황, 7장 진행 현황), 3단계 전 복제본 격리 조건, 9장 2단계 실행 기록(사전 점검, 단계별 결과, ZIP SHA-256, 운영 확인 사항 O1~O3, 증거) |
| v1.0 | 2026-11-19 | 1단계 결과 접수·2단계 조건부 승인 반영(승인 현황 표) |
| v1.0 | 2026-11-19 | 팀장 회신 반영: 승인 현황 표(1단계 승인, 2·3단계 단계별 승인, VMnet 대체안 즉시 전환 금지, GUI WAN 개방 불승인, SSH-01 문맥 B·D 협의) |
| v1.0 | 2026-11-19 | 최초: 사용자 PC 점검 결과, GNS3 VM 미사용·복제본 사용 결정 제안, 토폴로지, VM·IP·서비스 목록, 자원, OPNsense 인터페이스·규칙 초안, Suricata IDS, 위험 11건, 단계별 구축·전환 순서 |
