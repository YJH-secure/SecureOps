# SecureOps Infrastructure

### Linux 진단 환경 (VMware) 구축 및 검증

**담당:** 김민우 (A · 서버·네트워크 인프라)  
**관련 문서:** [시스템 아키텍처 설계서](../docs/architecture/system-architecture.md) · [프로젝트 README](../README.md)  
**상태:** 2026-11-11 VM 3대 재구축 완료 — 서버·네트워크 구성, 전용 계정, SSH 키 인증, sudoers 초안 v0, `01-ssh-security-configured` 스냅샷, 검증 증거 확보 완료 / VM 폴더 백업 검증(구성·7-Zip·원본 비교) 및 복원 시험 완료 (7-1) / 2026-11-12 `ubuntu-a` `user1` 비밀번호 변경·설치 미디어 제거, `01-ssh-security-configured-passwd` 스냅샷과 신규 백업·복원 시험 완료 (7-3) / sudo 권한 팀장 검토·확정 예정 — 적용 현황은 1장, 검증 상태는 6장, 재구축 경위는 11장 참고

## 1. 개요

이 폴더는 SecureOps의 진단 기능이 실행되는 **가상 서버와 네트워크 환경**을 정의한다. VM 파일 자체는 용량과 보안 문제로 GitHub에 올리지 않으며, 대신 **같은 환경을 다시 만들 수 있도록** 구성값, 설정 파일, 구축 절차, 검증 증거를 관리한다.

| 기준표 항목 | 이 폴더에서 다루는 내용 |
| --- | --- |
| 1장 담당 역할 | VM 구성/버전표, 서버 연결 증거, 스냅샷 증거 |
| 6장 통합 테스트 | T-01~T-04를 위한 접속 경로, 조치 전 스냅샷, OS 버전 정보 |
| 7장 확인 목록 | 실제 VM 버전·네트워크가 문서와 일치하는지 확인 |

### 적용 현황

이 문서의 내용은 **실제 서버에 적용 완료된 설정**과 **추후 적용·검증 예정인 설정**으로 구분한다.

**적용 완료** — 실제 서버에 설정됨

| 구분 | 내용 | 관련 장 |
| --- | --- | --- |
| 서버 | 3대 OS 설치 (Ubuntu 24.04.5 LTS Server/Desktop, Rocky Linux 9.8 Desktop) | 2장 |
| 서버 식별자 | `central-mgmt`, `ubuntu-a`, `rocky-b` 확정 | 2장 |
| 호스트명 | central-management-ubuntu, Target-Ubuntu, Target-Rocky 설정 (재구축 후 `central-mgmt`는 소문자) | 2장 |
| 네트워크 | VMnet8 NAT, `192.168.10.0/24` 고정 IP, 게이트웨이·DNS `192.168.10.2` | 3장 |
| 시간대 | 3대 모두 `Asia/Seoul` | 5-3 |
| SSH 서버 | 진단 대상 A/B에서 OpenSSH 서버 실행 | 5-4 |
| 비밀번호 정책 | 서버·계정별 서로 다른 16자 이상 비밀번호 | 5-5 |
| 계정 분리 | 진단 대상 A/B에 `secureops-scan`, `secureops-fix` 생성 | 5-5 |
| sudo 권한 | sudoers 초안 v0 적용 — scan은 읽기 보조 명령, fix는 승인된 SSH 설정 적용 명령만 허용 | 5-6 |
| 관리 계정 | Rocky `user1`을 `wheel` 그룹에 추가해 3대 모두 `user1` sudo 사용 | 5-6 |
| SSH 키 인증 | Ed25519 키 계정별 분리 생성, 공개키 등록, 4개 조합 키 접속 동작 확인 | 5-5 |
| 스냅샷 | `00-initial-setup` (초기 환경 복구용), `01-ssh-security-configured` (보안 설정 완료 상태, 재구축 후 2026-11-11 생성) | 7장 |
| 백업 | `01-ssh-security-configured` 이후 VM 폴더 3대를 별도 드라이브에 zip으로 백업, SHA-256 기록, 무결성 검사와 복원 시험 완료 (2026-11-11) | 7-1 |
| `ubuntu-a` 자격증명 조치 | `user1` 비밀번호 변경, `autoinst.iso`·`autoinst.flp` 장치 제거·원본 삭제, `01-ssh-security-configured-passwd` 스냅샷(일반 복구 기준), 신규 백업·복원 시험 (2026-11-12, 팀장 승인) | 7-3 |

**추후 적용·검증 예정** — 아직 서버에 적용되지 않음

| 구분 | 내용 | 적용 시점 |
| --- | --- | --- |
| SSH 설정 | root 직접 SSH 로그인 제한 등 `sshd_config` 변경 | 진단·조치 정책 확정 후 |
| sudo 권한 확정 | sudoers 초안 v0 팀장 검토 및 확정·조정 | 팀장 검토 후 |
| 조치 권한 확장 | PAM·FILE-01·방화벽 등 SSH-01 외 항목의 조치 명령 | 조치 기능·정책 확정 후 |
| 승인 파일 경로 | `/etc/secureops/approved/` 생성 및 승인 파일 관리 절차 | 조치 기능 개발 시 |
| 스냅샷 | `02-vuln-baseline` 이후 단계 | 진단 항목 확정 후 |
| 설정 파일 | `network/`, `setup/` 스크립트 작성 | 구축 진행에 따라 |

## 2. 서버 구성

2026-11-11 재구축 기준이다. 재구축 전 커널 값은 아래 "커널 버전 변동"에, 재구축 경위는 11장에 적는다.

| 구분 | 서버 식별자 | 호스트명 | OS | 에디션 | IP | 커널 |
| --- | --- | --- | --- | --- | --- | --- |
| 중앙 관리 서버 | `central-mgmt` | central-management-ubuntu | Ubuntu 24.04.5 LTS | Server | `192.168.10.10` | 6.8.0-149-generic |
| 진단 대상 A | `ubuntu-a` | Target-Ubuntu | Ubuntu 24.04.5 LTS | Desktop | `192.168.10.20` | 7.0.0-42-generic |
| 진단 대상 B | `rocky-b` | Target-Rocky | Rocky Linux 9.8 (Blue Onyx) | Desktop | `192.168.10.30` | 5.14.0-687.66.1.el9_8.x86_64 |

| 서버 식별자 | 네트워크 인터페이스 |
| --- | --- |
| `central-mgmt` | `ens33` |
| `ubuntu-a` | `ens33` |
| `rocky-b` | `ens160` |

| 구분 | vCPU | RAM | 디스크 | 역할 |
| --- | --- | --- | --- | --- |
| 중앙 관리 서버 | 2 | 4096MB | 40GB | 진단 실행, SSH 연결 관리, 결과 통합·평가, 승인·조치 제어 |
| 진단 대상 A | 2 | 4096MB | 30GB | 1차 Linux 취약점 진단 및 재검증 |
| 진단 대상 B | 2 | 2048MB | 30GB (NVMe) | 다른 배포판의 점검 및 조치 호환성 검증 |

- 가상화: VMware Workstation
- 서버 식별자는 아키텍처 설계서 6장의 논리 식별자를 따르며, IP나 호스트명이 바뀌어도 유지한다.

> **`central-mgmt` 호스트명:** 재구축 후 정적 호스트명이 소문자 `central-management-ubuntu`로 설정되었다 (`central-mgmt-hostname-261111.png`). 재구축 전에는 `Central-Management-Ubuntu`였다. 진단 결과와 연동은 서버 식별자(`central-mgmt`)와 IP를 기준으로 하므로 동작에는 영향이 없다. 대소문자를 맞출지는 10장에서 협의한다.

> **Desktop 대상 주의:** 진단 대상 2대는 Desktop 에디션이라 Server보다 기본 서비스·패키지가 많다. SVC-01 등 서비스 관련 점검 결과에 차이가 생길 수 있다.

> **커널 차이:** 같은 Ubuntu 24.04.5라도 Server는 기본 커널(6.8), Desktop은 HWE 커널이 설치된다(재구축 전 `ubuntu-a`는 7.0). 서버 간 진단 결과가 다를 때 확인할 요소로 기록한다.

> **커널 버전 변동:** 커널은 설치 매체와 패키지 업데이트 시점에 따라 바뀐다. 재구축 전후 비교: `central-mgmt` 6.8.0-147 → 6.8.0-139 → 6.8.0-149, `ubuntu-a` 7.0.0-42 (같음), `rocky-b` 5.14.0-687.65.1 → 5.14.0-687.66.1. `central-mgmt`는 2026-11-11 오전 증거(`central-mgmt-kernel-261111.png`) 촬영 뒤, 백업(12:15 종료) 전에 커널이 6.8.0-149로 업데이트되고 재부팅되었다 (`central-mgmt-kernel-update-261111.png`, 복원 시험에서도 149 확인). 업데이트 원인(수동·자동)은 확인하지 않았다. 진단 결과에 커널 버전을 쓸 때는 이 표가 아니라 진단 시점에 `uname -r`로 수집한 값을 기준으로 한다.

## 3. 네트워크 구성

| 항목 | 값 |
| --- | --- |
| 네트워크 | VMnet8 (NAT) 단일 구성 |
| 대역 | `192.168.10.0/24` (서브넷 마스크 `255.255.255.0`) |
| 게이트웨이 / DNS | `192.168.10.2` (VMware NAT 장치) |
| IP 할당 | 수동 지정 (VMnet8 DHCP 미사용) |
| 관리 접속 | 중앙 관리 서버 → 진단 대상 A/B, SSH TCP 22 |

| 주소 | 용도 |
| --- | --- |
| `192.168.10.1` | 호스트 PC의 VMnet8 가상 어댑터 (게이트웨이로 사용하지 않음) |
| `192.168.10.2` | VMware NAT 게이트웨이 및 DNS |
| `192.168.10.10` | 중앙 관리 서버 (`central-mgmt`) |
| `192.168.10.20` | 진단 대상 A (`ubuntu-a`) |
| `192.168.10.30` | 진단 대상 B (`rocky-b`) |

**NAT 단일 구성 근거:** VM 간 통신과 패키지 설치가 모두 가능하고, 외부에서 VM으로 직접 접근할 수 없어 실습 환경으로 격리된다. 진단 트래픽을 인터넷과 완전히 분리해야 하는 경우 Host-only(VMnet1) 어댑터를 추가 검토한다.

## 4. 배포판별 차이 (진단 담당 참고)

| 구분 | Ubuntu 24.04 | Rocky Linux 9.8 | 관련 항목 |
| --- | --- | --- | --- |
| 패키지 관리 | `apt` | `dnf` | SVC-01 |
| SSH 서비스명 | `ssh` | `sshd` | SSH-01, SSH-02 |
| PAM 설정 | `/etc/pam.d/common-*` | `/etc/pam.d/system-auth`, `password-auth` (**authselect 관리**) | ACC-01, ACC-02 |
| 방화벽 | `ufw` (기본 비활성) | `firewalld` (기본 활성) | FW-01 |
| 보안 모듈 | AppArmor | SELinux | FILE-01, SVC-01 |
| 인증 로그 | `/var/log/auth.log` | `/var/log/secure` | LOG-01 |
| 네트워크 설정 | netplan | NetworkManager (`nmcli`) | A |

> Rocky의 PAM 파일은 `authselect`가 생성·관리하므로 직접 수정하면 덮어써질 수 있다. 조치 전 관리 방식과 복구 절차를 먼저 확인한다.

> **OpenSSH 버전:** Ubuntu는 9.6, Rocky는 9.9로 표시되지만, 배포판은 버전 번호를 유지한 채 보안 패치를 적용(백포트)한다. 버전 번호만으로 취약 여부를 판정하지 않는다.

## 5. 구축 절차

### 5-1. VMnet8 설정 (호스트 PC)

VMware → **Edit → Virtual Network Editor → VMnet8**
- Subnet IP: `192.168.10.0`, Subnet mask: `255.255.255.0`
- NAT Settings의 Gateway IP가 `192.168.10.2`인지 확인
- "Use local DHCP service" 해제

### 5-2. 고정 IP 설정

**Ubuntu** — `/etc/netplan/` 아래 yaml 수정 후 `sudo netplan apply` (진단 대상 A 예시, 인터페이스 이름은 `ip a`로 확인)

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.10.20/24]
      routes:
        - to: default
          via: 192.168.10.2
      nameservers:
        addresses: [192.168.10.2, 8.8.8.8]
```

**Rocky** — `nmcli`로 설정 (연결 이름은 `nmcli con show`로 확인)

```bash
sudo nmcli con mod ens160 ipv4.method manual ipv4.addresses 192.168.10.30/24 \
  ipv4.gateway 192.168.10.2 ipv4.dns "192.168.10.2 8.8.8.8"
sudo nmcli con up ens160
```

### 5-3. 기본 설정 (3대 공통)

```bash
# 패키지 최신화
sudo apt update && sudo apt upgrade        # Ubuntu
sudo dnf upgrade                           # Rocky

# 시간대 (JSON checked_at의 +09:00 기준)
sudo timedatectl set-timezone Asia/Seoul
```

### 5-4. OpenSSH 서버 (진단 대상)

```bash
# 진단 대상 A (Ubuntu Desktop은 기본 미설치)
sudo apt install openssh-server
sudo systemctl enable --now ssh

# 진단 대상 B (Rocky linux 기본 설치 여부 확인)
rpm -q openssh-server
sudo systemctl enable --now sshd
```

중앙 관리 서버는 접속하는 쪽이므로 `openssh-client`만 있으면 된다 (`ssh -V`로 확인).

### 5-5. 계정 및 SSH 키 인증

**SSH 인증 및 권한 원칙 (확정)**
- 중앙 관리 서버(`central-mgmt`)에서 진단 대상(`ubuntu-a`, `rocky-b`)으로 접속할 때 **SSH 공개키 인증(Ed25519)**을 사용한다. — **적용 완료**
- 진단·조치는 전용 계정(`secureops-scan`, `secureops-fix`)으로 분리해 수행한다. — **적용 완료**
- 전체 관리자 권한 대신 **최소 권한 원칙**을 적용한다. — **sudoers 초안 v0 적용**, 팀장 검토 후 확정 (5-6)
- root 직접 SSH 로그인은 제한한다. — **적용 예정** (정책 확정 후)

**계정 구성**

| 계정 | 용도 | 위치 | 현재 상태 (적용 완료) | 추후 적용 예정 |
| --- | --- | --- | --- | --- |
| `user1` | 서버 관리용 | 3대 공통 | 관리자(sudo) | — |
| `secureops-scan` | 취약점 진단용 | 진단 대상 A/B | 계정·SSH 키 등록, 읽기 보조 sudo 명령 (초안 v0) | 팀장 검토 후 확정 |
| `secureops-fix` | 보안 조치용 | 진단 대상 A/B | 계정·SSH 키 등록, 승인된 SSH 설정 적용 sudo 명령 (초안 v0) | SSH-01 외 조치 명령 추가 |
| `root` | 시스템 관리자 | 3대 공통 | 기본 설정 유지 | 직접 SSH 로그인 제한 |

**적용 시점**

| 작업 | 상태 |
| --- | --- |
| 전용 계정 생성, SSH 키 생성·등록, 키 접속 확인 | 적용 완료 |
| root 직접 SSH 로그인 제한 등 `sshd_config` 변경 | 진단·조치 기능 및 정책 확정 후 적용 |
| `secureops-scan`, `secureops-fix`의 sudo 권한 | 초안 v0 적용 (2026-11-06), 팀장 검토 후 확정 |

**비밀번호 정책**
- 서버별로 서로 다른 비밀번호를 사용하고, 같은 서버의 `user1`과 `root`도 각각 다르게 설정한다.
- 16자 이상의 강력한 비밀번호를 사용한다.
- 비밀번호는 이 저장소, 문서, 팀 채팅방에 기록·공유하지 않는다.
- `secureops-scan`, `secureops-fix`는 비밀번호 없이 SSH 키로만 접속한다.

**1) 전용 계정 생성** — 진단 대상 A/B에서 `user1`로 실행

```bash
sudo useradd -m -s /bin/bash secureops-scan
sudo useradd -m -s /bin/bash secureops-fix
```

**2) SSH 키 생성** — 중앙 관리 서버에서 실행 (계정별로 키를 분리)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_scan -C "secureops-scan"
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_fix  -C "secureops-fix"
```

**3) 공개키 등록** — 전용 계정은 비밀번호가 없어 `ssh-copy-id`를 쓸 수 없으므로, `user1`을 통해 등록한다.

```bash
# 중앙 관리 서버에서 공개키 전송 (진단 대상 B는 192.168.10.30)
scp ~/.ssh/id_ed25519_scan.pub ~/.ssh/id_ed25519_fix.pub user1@192.168.10.20:/tmp/
```

```bash
# 진단 대상 A/B에서 user1로 실행
for u in scan fix; do
  sudo install -d -m 700 -o secureops-$u -g secureops-$u /home/secureops-$u/.ssh
  sudo install -m 600 -o secureops-$u -g secureops-$u /tmp/id_ed25519_$u.pub /home/secureops-$u/.ssh/authorized_keys
done
rm /tmp/id_ed25519_*.pub
sudo restorecon -R /home/secureops-*/.ssh   # Rocky(SELinux)만 해당
```

**4) 접속 확인** — 중앙 관리 서버에서 실행

```bash
ssh -i ~/.ssh/id_ed25519_scan secureops-scan@192.168.10.20
ssh -i ~/.ssh/id_ed25519_fix  secureops-fix@192.168.10.20
```

> 개인키(`~/.ssh/id_ed25519_scan`, `~/.ssh/id_ed25519_fix`)는 중앙 관리 서버 밖으로 복사하지 않으며 이 저장소에 커밋하지 않는다.

**5) 재구축 시 키 재생성 (2026-11-11)**

VM을 다시 설치하면 서버의 **호스트 키**와 `central-mgmt`의 **사용자 키**가 모두 새로 만들어진다.

| 구분 | 변경 내용 | 조치 |
| --- | --- | --- |
| 호스트 키 (3대) | OS 재설치로 SSH 호스트 키가 새로 생성됨 | 이전에 접속한 PC·서버의 `known_hosts`에서 해당 IP 항목을 지운 뒤, 처음 접속할 때 지문을 확인하고 등록 |
| 사용자 키 (`central-mgmt`) | `id_ed25519_scan`, `id_ed25519_fix`를 위 2)로 새로 생성 | 위 3)으로 진단 대상 A/B에 공개키를 다시 등록 (Rocky는 `restorecon` 포함) |

```bash
# 이전에 접속했던 PC·서버에서 실행 — 바뀐 호스트 키의 이전 항목 삭제
ssh-keygen -R 192.168.10.10
ssh-keygen -R 192.168.10.20
ssh-keygen -R 192.168.10.30
```

Windows PowerShell에서도 같은 명령(`ssh-keygen -R <IP>`)을 쓴다. 별칭(`ubuntu-a` 등)으로 접속해 저장된 항목이 있으면 별칭도 같은 방법으로 지운다.

### 5-6. 계정 권한 및 sudo 설정 현황 (sudoers 초안 v0)

2026-11-06 팀장 요청에 따라 **sudoers 초안 v0**을 진단 대상 A/B에 적용했다. 기준표 v1.1의 8개 점검 항목 중 **일반 권한으로 불가능했던 확인만** 정확한 명령·인자 단위로 허용하며, 팀장 검토 후 확정·조정한다.

**설계 원칙**
- 일반 권한으로 가능한 확인(ACC-01·02, FILE-01의 `stat`/ACL 등)은 sudo를 부여하지 않는다.
- 명령은 전체 경로와 인자를 고정하며 `*` 와일드카드를 사용하지 않는다 (임의 인자 추가 방지).
- 셸 탈출이 가능한 명령(`journalctl`, `less`, `vi` 등)은 허용하지 않는다.
- `/etc/shadow` 내용은 FILE-01에 필요하지 않으므로(소유자·권한만 확인) 허용하지 않는다.
- `secureops-fix`는 설정 **내용**을 직접 작성할 수 없고, 관리자(`user1`)가 승인해 `/etc/secureops/approved/`에 둔 파일만 설치·제거할 수 있다. 현재는 SSH-01 조치 경로만 열려 있다.

| 계정 | 그룹 | sudo 허용 명령 (초안 v0) | 설정 파일 |
| --- | --- | --- | --- |
| `secureops-scan` | 본인 그룹만 | `sshd -T`, `ss -lntup`, 방화벽 조회, `nft list ruleset`, 인증 로그 `tail -n 200`, (Rocky) `cat /etc/ssh/sshd_config` | `/etc/sudoers.d/secureops-scan` |
| `secureops-fix` | 본인 그룹만 | `sshd -t`, 승인된 SSH drop-in 설치·제거, SSH 서비스 reload | `/etc/sudoers.d/secureops-fix` |

2026-11-11 재구축 후 같은 허용 명령으로 다시 적용했다. 재구축본은 `Cmnd_Alias` 없이 한 줄로 작성했으며, 허용 명령과 인자는 재구축 전(2026-11-06)과 같다. 권한은 추가하거나 줄이지 않았다.

**진단 대상 A (Ubuntu) — 적용 내용**

```text
# /etc/sudoers.d/secureops-scan
secureops-scan ALL=(root) NOPASSWD: /usr/sbin/sshd -T, /usr/bin/ss -lntup, /usr/sbin/ufw status verbose, /usr/sbin/nft list ruleset, /usr/bin/tail -n 200 /var/log/auth.log

# /etc/sudoers.d/secureops-fix
secureops-fix ALL=(root) NOPASSWD: /usr/sbin/sshd -t, /usr/bin/install -m 0600 -o root -g root /etc/secureops/approved/01-secureops.conf /etc/ssh/sshd_config.d/01-secureops.conf, /usr/bin/rm -f /etc/ssh/sshd_config.d/01-secureops.conf, /usr/bin/systemctl reload ssh
```

**진단 대상 B (Rocky) — 적용 내용**

```text
# /etc/sudoers.d/secureops-scan
secureops-scan ALL=(root) NOPASSWD: /usr/sbin/sshd -T, /usr/sbin/ss -lntup, /usr/bin/firewall-cmd --state, /usr/bin/firewall-cmd --list-all, /usr/sbin/nft list ruleset, /usr/bin/tail -n 200 /var/log/secure, /usr/bin/cat /etc/ssh/sshd_config

# /etc/sudoers.d/secureops-fix
secureops-fix ALL=(root) NOPASSWD: /usr/sbin/sshd -t, /usr/bin/install -m 0600 -o root -g root /etc/secureops/approved/01-secureops.conf /etc/ssh/sshd_config.d/01-secureops.conf, /usr/bin/rm -f /etc/ssh/sshd_config.d/01-secureops.conf, /usr/bin/systemctl reload sshd
```

> **재구축 전과 대조:** 2026-11-11 `sudo -l -U` 출력(`ubuntu-a-sudo-261111.png`, `rocky-b-sudo-261111.png`)이 재구축 전 허용 명령과 같음을 확인했다. Rocky `scan`은 `cat /etc/ssh/sshd_config`의 나열 위치만 다르며, sudoers는 명령 단위로 비교하므로 동작은 같다. 각 명령의 **인자 순서**는 그대로 유지해야 한다 (예: `install -m 0600 -o root -g root`).

**적용 방법** — `visudo -cf`로 문법 검사 후 설치 (두 서버 `user1`로)

```bash
sudo visudo -cf /tmp/secureops-scan && sudo visudo -cf /tmp/secureops-fix && \
sudo install -m 0440 -o root -g root /tmp/secureops-scan /etc/sudoers.d/secureops-scan && \
sudo install -m 0440 -o root -g root /tmp/secureops-fix /etc/sudoers.d/secureops-fix && \
rm /tmp/secureops-scan /tmp/secureops-fix && sudo visudo -c
sudo restorecon -v /etc/sudoers.d/secureops-*   # Rocky만
```

> 파일 권한 `0440`, 소유자 `root:root`, Rocky SELinux 문맥 `etc_t` 확인 완료. Rocky의 `user1`은 설치 시 관리자 미지정으로 `wheel` 그룹에 추가해 sudo를 사용하도록 맞췄다.

**확인 명령**

```bash
# 진단 대상에서 user1로 — 허용 목록 확인
sudo -l -U secureops-scan
sudo -l -U secureops-fix

# 중앙 관리 서버에서 — 허용 명령은 동작, 그 외는 차단
for h in ubuntu-a rocky-b; do
  echo "===== $h ====="
  echo "[허용] sshd -T:"; ssh $h 'sudo -n /usr/sbin/sshd -T | grep -i permitrootlogin'
  echo "[차단] shadow:";  ssh $h 'sudo -n cat /etc/shadow 2>&1 | head -1'
  echo "[차단] id:";      ssh $h-fix 'sudo -n id 2>&1 | head -1'
  echo "[허용] fix sshd -t:"; ssh $h-fix 'sudo -n /usr/sbin/sshd -t && echo OK'
done
```

**확인 결과 (재구축 후 2026-11-11, `central-mgmt-sudo-test-261111.png`)** — 두 서버 동일, 재구축 전(2026-11-06)과 같은 결과

| 테스트 | 결과 |
| --- | --- |
| `secureops-scan`: `sudo sshd -T` | 허용 — `permitrootlogin without-password` 출력 |
| `secureops-scan`: `sudo cat /etc/shadow` | 차단 — "암호가 필요합니다" |
| `secureops-fix`: `sudo id` | 차단 — "암호가 필요합니다" |
| `secureops-fix`: `sudo sshd -t` | 허용 — OK |

> SSH-01 참고: 두 서버 모두 `PermitRootLogin`이 배포판 기본값 `without-password`(`prohibit-password`)로, root의 비밀번호 로그인은 막혀 있으나 키 로그인은 허용되는 상태다. 이를 pass/vulnerable 중 무엇으로 볼지는 SSH-01 정책에서 정한다.

> 미준비: `/etc/secureops/approved/` 디렉터리와 승인 파일은 아직 만들지 않았다. 따라서 `secureops-fix`의 설치 명령은 승인 파일이 준비되기 전까지 실제로 동작하지 않는다.

### 5-7. 공통 SSH 모듈 연동 정보

`common/ssh_client.py`(양지혁 담당) 연동을 위한 접속 정보이다. **개인키 파일, 개인키 내용, 비밀번호는 이 저장소에 올리지 않는다.**

**1) 인증 방식**

| 항목 | 내용 |
| --- | --- |
| 방식 | OpenSSH 공개키 인증 (Ed25519) |
| 비밀번호 인증 | 전용 계정은 비밀번호가 없어 키로만 접속 가능 |
| 키 구성 | 계정별 분리 — `secureops-scan`용 키, `secureops-fix`용 키 |
| 키 비밀번호(passphrase) | 없음 (자동 진단용) |
| OpenSSH 기본 키와의 차이 | 키 파일명이 기본값(`id_ed25519`)이 아니므로, 중앙 관리 서버의 `~/.ssh/config`에서 대상별 키를 지정한다. 이 설정이 있으면 `ssh ubuntu-a`처럼 별칭만으로 접속되며, SSH agent 사용 시에는 `ssh-add`로 두 키를 등록한다. |

**2) 개인키 경로**

실제 경로는 환경마다 다를 수 있으므로 아래는 예시이며, 구체적인 경로는 중앙 관리 서버의 `~/.ssh/config`로 관리한다 (Git에 올리지 않음).

| 용도 | 경로 예시 (중앙 관리 서버 `user1`) |
| --- | --- |
| 진단용 | `~/.ssh/id_ed25519_scan` |
| 조치용 | `~/.ssh/id_ed25519_fix` |

```bash
# 실제 키 파일 확인
ls -l ~/.ssh/
# 별칭별로 실제 사용되는 키·계정·주소 확인
ssh -G ubuntu-a | grep -Ei "^(hostname|user|port|identityfile) "
```

`~/.ssh/config` 예시 (경로만 포함하며 비밀정보 없음):

```text
Host ubuntu-a
    HostName 192.168.10.20
    User secureops-scan
    IdentityFile ~/.ssh/id_ed25519_scan
    IdentitiesOnly yes

Host rocky-b
    HostName 192.168.10.30
    User secureops-scan
    IdentityFile ~/.ssh/id_ed25519_scan
    IdentitiesOnly yes

Host ubuntu-a-fix
    HostName 192.168.10.20
    User secureops-fix
    IdentityFile ~/.ssh/id_ed25519_fix
    IdentitiesOnly yes

Host rocky-b-fix
    HostName 192.168.10.30
    User secureops-fix
    IdentityFile ~/.ssh/id_ed25519_fix
    IdentitiesOnly yes
```

**3) 진단 대상 접속 정보**

| 서버 식별자 | IP | 포트 | 진단 계정 | 조치 계정 | SSH 별칭 (진단 / 조치) |
| --- | --- | --- | --- | --- | --- |
| `ubuntu-a` | `192.168.10.20` | 22 | `secureops-scan` | `secureops-fix` | `ubuntu-a` / `ubuntu-a-fix` |
| `rocky-b` | `192.168.10.30` | 22 | `secureops-scan` | `secureops-fix` | `rocky-b` / `rocky-b-fix` |

**4) 진단 계정 권한 범위**

- 아래 표의 Ubuntu·Rocky 열은 **일반 사용자 권한** 기준 결과이고, "sudo 초안 v0" 열은 5-6의 sudoers로 새로 가능해진 확인이다.
- "확인 방법" 열이 **테스트**인 항목은 실제 확인한 결과이고(2026-11-05 최초 확인, 재구축 후 2026-11-11 재확인 — 결과 동일), **예상**인 항목은 배포판 기본 권한 기준이며 추후 확인한다.

| 점검 대상 | Ubuntu (`ubuntu-a`) | Rocky (`rocky-b`) | sudo 초안 v0 | 확인 방법 | 관련 항목 |
| --- | --- | --- | --- | --- | --- |
| `/etc/passwd` 읽기 | 가능 | 가능 | 불필요 | 테스트 | ACC-01, FILE-01 |
| PAM 설정 읽기 (`common-auth` / `system-auth`) | 가능 | 가능 | 불필요 | 테스트 | ACC-01, ACC-02 |
| `/etc/security/pwquality.conf` 읽기 | 가능 | 가능 | 불필요 | 테스트 | ACC-01 |
| `/etc/ssh/sshd_config` 읽기 | 가능 | **불가** | Rocky `sudo cat` 허용 | 테스트 | SSH-01, SSH-02 |
| `/etc/shadow` 읽기 | **불가** | **불가** | 허용 안 함 | 테스트 | FILE-01 (권한 확인은 `stat`으로 가능) |
| 인증 로그 (`/var/log/auth.log` / `/var/log/secure`) | **불가** | **불가** | `sudo tail -n 200` 허용 | 테스트 | LOG-01 |
| `sshd -T` (유효 설정 확인) | **불가** (root 필요) | **불가** (root 필요) | 허용 (2026-11-06 동작 확인) | 테스트 | SSH-01, SSH-02 |
| `stat`으로 파일 소유자·권한 확인 | 가능 | 가능 | 불필요 | 예상 | FILE-01 |
| `systemctl list-units`, `ss -lntu` | 가능 (`ss -p` 프로세스 정보는 제한) | 가능 (동일) | `sudo ss -lntup` 허용 | 예상 | SVC-01 |
| 방화벽 규칙 조회 | **불가** (root 필요) | 확인 필요 | Ubuntu `ufw status verbose`, Rocky `firewall-cmd --state`/`--list-all`, 공통 `nft list ruleset` 허용 | 예상 | FW-01 |

> 진단 담당 참고: 일반 권한으로 확인할 수 없는 항목은 sudo 초안 v0의 허용 명령을 사용한다. 허용 목록 밖의 확인이 필요하면 직접 우회하지 말고 권한 추가를 요청하며, 권한 부족으로 실패한 경우 기준표 원칙에 따라 임의로 양호 처리하지 않고 `error`로 기록한다.

```bash
# 중앙 관리 서버에서 실행 — 진단 계정의 파일 읽기 권한 확인
for h in ubuntu-a rocky-b; do
  echo "=== $h ==="
  ssh $h 'for f in /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/security/pwquality.conf /var/log/auth.log /var/log/secure; do [ -e "$f" ] && { [ -r "$f" ] && echo "읽기 가능: $f" || echo "읽기 불가: $f"; }; done'
done
```

**5) SSH 접속 테스트 (재구축 후 신규 VM, 2026-11-11)**

모두 `central-mgmt`의 `user1`로 실행했다.

| 테스트 | 명령 | 결과 | 증거 |
| --- | --- | --- | --- |
| 키 직접 접속 (4개 조합) | `ssh -i ~/.ssh/id_ed25519_<scan\|fix> -o BatchMode=yes secureops-<scan\|fix>@<IP> 'whoami; hostname'` | 4개 모두 비밀번호 없이 접속 성공. `192.168.10.20` → `Target-Ubuntu`, `192.168.10.30` → `Target-Rocky`, `whoami`가 접속 계정과 일치 | `central-mgmt-sshkey-261111.png` |
| `~/.ssh/config` 별칭 접속 (4개) | `ssh <ubuntu-a\|rocky-b\|ubuntu-a-fix\|rocky-b-fix> 'whoami; hostname'` | `ubuntu-a`·`rocky-b` → `secureops-scan`, `-fix` 별칭 → `secureops-fix`, 호스트명 일치 | `central-mgmt-ssh-alias-261111.png` |
| sudo 허용·차단 | 5-6의 확인 명령 | 허용 2개 동작, 차단 2개 거부 (5-6 확인 결과 표) | `central-mgmt-sudo-test-261111.png` |
| 진단 계정 읽기 권한 | 위 4)의 명령 | 4) 표와 같음 — `/etc/ssh/sshd_config`는 Ubuntu 읽기 가능, Rocky 불가 / `/etc/shadow`·인증 로그는 두 서버 불가 | `central-mgmt-scan-read-test-261111.png` |
| SSH 출발지·인증 키 (2026-11-12) | 4개 별칭에서 `SSH_CONNECTION` 출력, 대상 인증 로그 `sudo -n tail -n 200` 중 `Accepted publickey` | 출발지 모두 `192.168.10.10`, 로그의 키 지문이 scan·fix 키와 일치 (HANDOFF 2-4) | `central-mgmt-ssh-source-261112.png`, `central-mgmt-ssh-authlog-261112.png` |

재구축 전(2026-11-05~06)에 같은 테스트를 한 결과는 `*-261105.png`, `*-261106.png`로 남겨 둔다.

## 6. 검증 체크리스트

모든 항목은 **실제 테스트와 증거 캡처를 마친 뒤** 완료(`[v]`)로 표시한다. 1장 적용 현황의 "적용 완료"는 설정이 적용된 상태를 뜻하며, 이 체크리스트의 완료는 증거까지 확보된 상태를 뜻한다.

증거는 서버별 폴더에 `evidence/<서버 식별자>/<서버 식별자>-<항목>-YYMMDD.png` 형식으로 저장한다. 중앙 관리 서버에서 실행해 진단 대상을 함께 확인한 캡처(VM 간 통신, SSH 키 접속, 읽기 권한 테스트)는 `central-mgmt/`에 둔다. 아래 증거 열의 `<id>`는 `central-mgmt`, `ubuntu-a`, `rocky-b`를 뜻한다.

아래 표는 **2026-11-11 재구축 후 신규 VM** 기준이다. 재구축 전 증거(`*-261105.png`, `*-261106.png`)는 이력으로 남겨 두며, 같은 폴더에 있다.

| 상태 | 확인 항목 | 명령어 | 정상 기준 | 증거 (2026-11-11) |
| --- | --- | --- | --- | --- |
| [v] | OS 버전 | `cat /etc/os-release` | 2장 버전표와 일치 | `<id>-os-261111.png` (3대) |
| [v] | 커널 버전 | `uname -r` | 2장 커널과 일치 | `<id>-kernel-261111.png` (3대), `central-mgmt-kernel-update-261111.png` (업데이트 후 149) |
| [v] | 호스트명 | `hostnamectl --static` | 2장 호스트명과 일치 | `<id>-hostname-261111.png` (3대) |
| [v] | VM 사양 | VMware Virtual Machine Settings | 2장 vCPU·RAM·디스크와 일치 | `central-mgmt-vm-spec-261111.png`, `ubuntu-a-spec-261111.png`, `rocky-b-spec-261111.png` |
| [v] | IP 할당 | `ip -4 a` | 2장 IP와 일치 | `<id>-ip-261111.png` (3대) |
| [v] | 기본 경로 | `ip route` | `default via 192.168.10.2` | `<id>-route-261111.png` (3대) |
| [v] | 시간대 | `timedatectl` | `Asia/Seoul` (3대 모두) | `<id>-timedate-261111.png` (3대) |
| [v] | 외부 통신 | `ping -c 3 8.8.8.8` | 응답 수신 | `<id>-outerping-261111.png` (3대) |
| [v] | VM 간 통신 | `ping -c 3 192.168.10.20`, `ping -c 3 192.168.10.30` | 중앙 관리 서버에서 응답 | `central-mgmt-innerping-261111.png` |
| [v] | SSH 키 접속 | 5-7 5)의 키 직접 접속 명령 | `secureops-scan`, `secureops-fix` 모두 비밀번호 없이 로그인 성공 | `central-mgmt-sshkey-261111.png` |
| [v] | 패키지 관리 | `sudo apt update` / `sudo dnf check-update` | 오류 없이 완료 | `<id>-pkg-261111.png` (3대) |
| [v] | scan 계정 권한 | `sudo -l -U secureops-scan` (진단 대상에서 `user1`로) | 5-6 초안 v0의 허용 명령만 표시 | `<id>-sudo-261111.png` (진단 대상 2대) |
| [v] | fix 계정 권한 | `sudo -l -U secureops-fix` (진단 대상에서 `user1`로) | 5-6 초안 v0의 허용 명령만 표시 | `<id>-sudo-261111.png` (진단 대상 2대) |
| [v] | sudo 허용·차단 | 5-6의 확인 명령 (중앙 관리 서버) | 허용 명령은 동작, 그 외는 거부 | `central-mgmt-sudo-test-261111.png` |
| [v] | SSH 별칭 접속 | 4개 별칭으로 `whoami; hostname` | 각 계정으로 비밀번호 없이 접속 | `central-mgmt-ssh-alias-261111.png` |
| [v] | SSH 출발지·인증 키 | 4개 별칭으로 `SSH_CONNECTION` 확인, 대상 인증 로그의 `Accepted publickey` (HANDOFF 2-4) | 출발지 `192.168.10.10`, 로그의 키 지문이 scan·fix 키 지문과 일치 | `central-mgmt-ssh-source-261112.png`, `central-mgmt-ssh-authlog-261112.png` (2026-11-12) |
| [v] | 진단 계정 읽기 권한 | 5-7의 읽기 권한 확인 명령 | 결과를 5-7 표에 반영 | `central-mgmt-scan-read-test-261111.png` |
| [v] | 스냅샷 | Snapshot Manager | `00-initial-setup`, `01-ssh-security-configured` 확인 | `<id>-snapshot-261111.png` (3대) |
| [v] | 스냅샷 Description | Snapshot Manager | `01` Description에 날짜·작업자·작업 내용 기록 | `<id>-snapshot-desc-261111.png` (3대) |
| [v] | sudoers 파일 권한 | `sudo ls -l /etc/sudoers.d/secureops-*; sudo visudo -c` (Rocky는 `ls -lZ` 추가) | `0440 root:root`, 모든 파일 해석 성공, Rocky `etc_t` | `<id>-sudoers-perm-261111.png` (진단 대상 2대) |
| [v] | 백업 해시 | `Get-FileHash -Algorithm SHA256` (호스트 PC) | 7-1 표에 파일명·크기·SHA-256 기록 | 7-1 표 (명령 출력 기준) |
| [v] | 백업 내부 구성 | ZIP 내부 목록, `.vmx`·`.vmsd`·디스크 연결 관계 | 필수 파일 포함, 참조 파일 누락 없음 | 7-1 (검사 스크립트 출력 기준) |
| [v] | 백업 무결성 | `7z t <파일>.zip` | `Everything is Ok` | 7-1 |
| [v] | 원본과 백업 비교 | 원본 VM 폴더와 ZIP의 파일 이름·크기·SHA-256 | 스냅샷 00·01 파일 일치 | 7-1 |
| [v] | 복원 시험 | 압축 해제 → `.vmx` 열기 → 스냅샷 확인 → 부팅 → SSH | 00·01 표시, 부팅, SSH·sudo 정상 | 7-2 (`vmrun` 출력 기준, 3대) |
| [v] | `ubuntu-a` 비밀번호 변경 (2026-11-12) | `passwd`, `sudo -k; sudo -v`, `/etc/shadow` 3번째 필드만 출력 | 변경일 `20769`, sudo·콘솔·scan/fix SSH 정상 | `ubuntu-a-passwd-change-261112.png`, `central-mgmt-ubuntu-a-ssh-after-passwd-261112.png` |
| [v] | `ubuntu-a` 설치 미디어 제거 (2026-11-12) | `.vmx`·`vmware.log` 확인, 게스트 `lsblk` | autoinst 장치 없음, 재부팅·Go To 정상 | `ubuntu-a-media-{before,after}-261112.png`, `ubuntu-a-revert01-boot-261112.png`, `ubuntu-a-revert-passwd-261112.png` |
| [v] | `ubuntu-a` 신규 스냅샷 (2026-11-12) | Snapshot Manager, `vmrun listSnapshots` | `01-ssh-security-configured-passwd` 생성 | `ubuntu-a-snapshot-261112.png` |
| [v] | SSH 별칭·SSH-01 문맥 (2026-11-12) | `ssh -G`, `sshd -T`(`usedns`), `Match` 검색, `sshd -T -C …` (대상은 `user1`) | 별칭 2-1과 일치, `usedns no`, `Match` 없음 (HANDOFF 2-5) | `central-mgmt-ssh-g-261112.png`, `<id>-ssh01-context-261112.png` (진단 대상 2대) |
| [v] | C 요청 권한 재측정 (2026-11-12) | scan으로 `sudo -l`, `getfacl`, journal, firewalld 조회 | `sudo -l` v0과 같음, 분류는 HANDOFF 4-1·4-3 | `central-mgmt-c-permission-check-{1,2,3}-261112.png` |
| [v] | `ubuntu-a` 신규 백업·복원 (2026-11-12) | SHA-256, `7z t`, 원본 비교, 복원 후 부팅·SSH | 7-3 4)·5) 표와 같음 | `ubuntu-a-restore-test-261112.png`, `central-mgmt-ubuntu-a-ssh-restore-261112.png` |

> 신규 VM 증거는 `*-261111.png` **43장**이다 (`central-mgmt` 17장, `ubuntu-a` 13장, `rocky-b` 13장). 재구축 전 증거(`*-261105.png`, `*-261106.png`)는 삭제된 VM의 기록이며 신규 VM의 근거로 쓰지 않는다.
>
> **저장소 보안 검사 범위 (2026-11-11):** `feature/kmw-infrastructure` 최신 커밋의 텍스트 파일을 개인키 헤더·토큰·비밀번호 패턴으로 검사했고, 키·백업·VM 파일(`id_ed25519*`, `.pem`, `.key`, `.env`, `known_hosts`, `.zip`, `.vmdk`, `.vmx`) 0건이다. 신규 스크린샷 43장은 직접 판독해 비밀번호·키·토큰이 없음을 확인했다. 이전 커밋 이력과 재구축 전 스크린샷은 이번 검사 범위에 포함하지 않았다.
>
> **2026-11-12 추가 증거 19장** (`*-261112.png`, `central-mgmt` 10장, `ubuntu-a` 8장, `rocky-b` 1장): IP, 계정명, 공개키 지문, 명령 결과, 스냅샷 화면만 담겨 있으며 비밀번호·해시·개인키·토큰이 없음을 직접 판독해 확인했다. `/etc/shadow`는 마지막 변경일 필드만 출력했다.

중앙 관리 서버에서 진단 대상 2대의 정보와 SSH 연결을 한 번에 확인할 수 있다.

```bash
for ip in 192.168.10.20 192.168.10.30; do echo "=== $ip ==="; ssh -i ~/.ssh/id_ed25519_scan secureops-scan@$ip 'hostname; grep PRETTY_NAME /etc/os-release; hostname -I; systemctl get-default'; done
```

## 7. 스냅샷 규칙

스냅샷은 VM마다 따로 저장되므로 이름에 서버 식별자를 넣지 않고, **같은 단계는 3대 모두 같은 이름**을 사용한다.

| 이름 | 대상 | 생성 시점 | 상태 |
| --- | --- | --- | --- |
| `00-initial-setup` | 3대 공통 | 기본 설정, 비밀번호 설정, 네트워크 연결 확인 완료 후 — 초기 환경 복구용으로 유지 | **확정** |
| `01-ssh-security-configured` | 3대 공통 | 전용 계정·SSH 키 인증·호스트명 설정, sudoers 초안 v0 적용 및 권한 검증 완료 후 (재구축 후 2026-11-11 생성) | **확정** |
| `01-ssh-security-configured-passwd` | `ubuntu-a`만 | `user1` 비밀번호 변경과 설치 미디어 제거 후 (2026-11-12 생성) — `ubuntu-a` 일반 복구 기준 | **확정** (7-3) |
| `02-mgmt-ready` | 중앙 관리 서버 | Python 3.12, Git 등 개발 도구 설치 후 | 제안 |
| `02-vuln-baseline` | 진단 대상 A/B | 진단 담당과 협의한 취약 설정 적용 후 | 제안 |
| `03-pre-remediation-YYMMDD` | 진단 대상 A/B | 관리자 승인 후 조치 직전 (T-03) | 제안 |
| `04-post-remediation-YYMMDD` | 진단 대상 A/B | 조치·재진단 완료 후 (선택) | 제안 |

> **`01-ssh-security-configured` 재생성 (2026-11-06)** : 최초 생성본(2026-11-05)은 `rocky-b`의 `user1`이 sudoers(`wheel` 그룹)에 적용되지 않은 상태로 생성되었다. `user1`을 `wheel` 그룹에 추가한 뒤, 3대가 같은 시점의 상태를 갖도록 기존 `01`을 삭제하고 같은 이름으로 3대 모두 다시 생성했다. `00-initial-setup`은 그대로 유지한다.
>
> **재구축 후 스냅샷 (2026-11-11)** : 이 두 스냅샷은 2026-11-08 VM과 함께 삭제되었고(11장), 재구축한 VM에서 `00-initial-setup`, `01-ssh-security-configured`를 다시 만들었다. 2026-11-11 생성본의 `01` 생성 시각은 아래와 같다 (`<id>-snapshot-261111.png`).
>
> | 서버 식별자 | `01-ssh-security-configured` 생성 시각 |
> | --- | --- |
> | `central-mgmt` | 2026-11-11 10:47:52 |
> | `ubuntu-a` | 2026-11-11 10:47:55 |
> | `rocky-b` | 2026-11-11 10:47:58 |

- 반복될 수 있는 단계(03, 04)에만 날짜를 붙이고, 같은 날 두 번 생성 시 `-2`를 붙인다.
- Description에 날짜, 작업자, 작업 내용을 기록한다. 예: `261105 김민우 / 기본 설정, 비밀번호 설정, 연결 확인 완료`
- 기준점 스냅샷(00, 01, 02)은 `sudo poweroff`로 정상 종료한 뒤 생성한다.
- 스냅샷은 VM 폴더 안에 저장되므로 백업이 아니다. 중요한 시점에는 VM 폴더 전체를 외부 저장소에 복사한다. 현황은 7-1을 참고한다.
- 복구는 Snapshot Manager → Go To로 하며, 복구 후 6장 체크리스트를 다시 확인한다.

### 7-1. VM 백업 현황 (2026-11-11)

`01-ssh-security-configured` 스냅샷을 만든 뒤, 3대를 종료한 상태에서 VM 폴더를 각각 zip으로 압축해 호스트 PC의 별도 드라이브에 보관했다. 크기와 SHA-256은 호스트 PC PowerShell(`Get-ChildItem`, `Get-FileHash -Algorithm SHA256`)로 확인한 값이다.

| 파일명 | 서버 식별자 | OS | 백업 시점 (파일 수정 시각) | 크기 | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `Central-Management-Ubuntu.zip` | `central-mgmt` | Ubuntu 24.04.5 LTS Server | 2026-11-11 12:18 | 2,878,201,934 bytes (2.68 GiB) | `613396AF67D11DCA39C0C0FC5B13C1BE787785E3DC1FEA81E6ED11795164D3C5` |
| `Target-Ubuntu.zip` → 2026-11-12 `Target-Ubuntu-261111-legacy-oldhash.zip`으로 이름 변경·읽기 전용 (7-3) | `ubuntu-a` | Ubuntu 24.04.5 LTS Desktop | 2026-11-11 11:15 | 4,599,817,605 bytes (4.28 GiB) | `33B1CF778E53A18C0C5C14C5A653B37FD78D1D4326E23564C33543F9D93DDCE1` |
| `Target-Rocky.zip` | `rocky-b` | Rocky Linux 9.8 (Blue Onyx) Desktop | 2026-11-11 11:30 | 7,105,211,739 bytes (6.62 GiB) | `34A52B02D0E8D41B610995ED3213B26797E115A654A617D065278726279C25E0` |

**백업 검증 결과 (2026-11-11, 호스트 PC에서 검사 스크립트로 확인)**

| 항목 | `central-mgmt` | `ubuntu-a` | `rocky-b` |
| --- | --- | --- | --- |
| SHA-256 | 위 표와 같음 | 같음 | 같음 |
| 7-Zip `7z t` | Everything is Ok (55개) | Everything is Ok (47개) | Everything is Ok (45개) |
| 필수 파일 (`.vmx`, `.vmsd`, `.vmsn` 2개, `.nvram`, `.vmxf`) | 있음 | 있음 | 있음 |
| 스냅샷 (`.vmsd`) | `00-initial-setup` → `01-ssh-security-configured`, 현재 위치는 01 다음 | 같음 | 같음 |
| 디스크 연결 (기본 → `-000001`(01) → `-000002`(현재)) | 참조 38건, 누락 0 | 참조 29건, 누락 0 | 참조 29건, 누락 0 |
| `.vmx` 사양 | 2 vCPU, 4GB, SCSI, VMnet8 | 2 vCPU, 4GB, SCSI, VMnet8 | 2 vCPU, 2GB, NVMe, VMnet8 |
| 실행·일시정지 흔적 (`.vmem`, `.vmss`) | 없음 | 없음 | 없음 |
| 잠금 파일 (`.vmx.lck`) | **1개 포함** (아래 참고) | 없음 | 없음 |
| 원본 폴더 비교 | 스냅샷 00·01 파일 일치 | 일치 | 일치 |

- **원본 비교 방법:** 100MB 이하 파일은 SHA-256까지, 그보다 큰 기본 디스크 파일은 크기로 비교했다. ZIP 안 파일의 손상 여부는 `7z t`(CRC)로 따로 확인했다.
- **원본과 다른 파일:** 현재 상태 디스크(`-000002*`), `.vmx`, `.nvram`, 로그, `scoreboard`는 원본과 다르다. 백업 뒤에도 원본 VM을 켜서 사용했기 때문이며 정상이다. `central-mgmt`의 `.vmsd`는 17:12에 스냅샷 Description을 입력해 달라졌다.
- **`central-mgmt`의 `.vmx.lck`:** `vmware.log` 끝에 `VMX exit (0)`(2026-11-11 12:15:04 KST, 정상 종료)이 있고 압축은 그 뒤(12:18)에 끝났다. VMware 프로세스가 없는 상태에서도 원본 폴더에 잠금 파일이 남아 있는 것을 확인했다. 따라서 정상 종료 뒤 남은 잠금 파일이 함께 압축된 것으로 판단한다. 복원 시 이 폴더를 지우고 정상 부팅됨을 확인했다(7-2). **원인 보충 (2026-11-12):** VM을 꺼도 Workstation에 탭으로 열려 있으면 잠금이 유지되고, 탭을 닫거나 라이브러리에서 Remove하면 사라지는 것을 작업자가 확인했다. 백업 절차에 반영했다(7-3 7)).
- **`ubuntu-a`의 `autoinst.iso`·`autoinst.flp`:** VMware 간편 설치가 만든 파일이 VM 폴더와 ZIP에 남아 있다. `autoinst.iso`의 `PRESEED.CFG`에 `user1` 계정 이름과 **비밀번호 해시**(SHA-256-crypt)가 들어 있다. 평문 비밀번호, SSH 키, 토큰은 없다. 2026-11-12 팀장 승인에 따라 `user1` 비밀번호를 바꾸고 원본 VM 폴더의 두 파일을 삭제했다(7-3). **이 표의 ZIP에는 그대로 남아 있다.**

- 받은 쪽은 내려받은 뒤 `Get-FileHash <파일> -Algorithm SHA256` 결과를 위 표와 대조한다.
- **백업 zip은 비밀정보로 취급한다.** VM 디스크에는 `/etc/shadow` 해시, SSH 호스트 개인키가 들어 있고, `central-mgmt`에는 passphrase가 없는 `id_ed25519_scan`·`id_ed25519_fix` 개인키가 들어 있다. 공유는 지정한 팀원 계정에만 하고, 이 저장소나 외부 AI 서비스에 올리지 않는다. 백업 파일의 저장 경로와 공유 링크는 이 문서에 적지 않는다.
- 다른 PC에서 복원할 때 확인할 것: VMnet8을 5-1과 같이 설정, 원본 VM과 동시에 켜지 않기(IP 충돌), 처음 켤 때 "I Moved It" 선택, CD/DVD가 작성자 PC의 ISO를 가리키면 연결 해제, `central-mgmt`는 압축 해제 후 `.vmx.lck` 폴더 삭제.

### 7-2. 복원 시험 (2026-11-11, 작성자 PC)

ZIP 3개를 원본과 다른 폴더에 풀어 VMware에서 열고, 원본 VM은 끈 상태에서 복원본만 실행했다. VM 안의 확인은 콘솔 로그인 없이 `vmrun`(VMware Tools 게스트 명령)으로 실행했다.

| 확인 | `central-mgmt` | `ubuntu-a` | `rocky-b` |
| --- | --- | --- | --- |
| VMware 인식·실행 | 정상 | 정상 | 정상 |
| 스냅샷 00·01 표시 (`vmrun listSnapshots`) | 정상 | 정상 | 정상 |
| 현재 상태 부팅 | 정상 (`.lck` 삭제 후) | 정상 | 정상 |
| 호스트명 / OS | central-management-ubuntu / Ubuntu 24.04.5 | Target-Ubuntu / Ubuntu 24.04.5 | Target-Rocky / Rocky 9.8 |
| 커널 | 6.8.0-149-generic | 7.0.0-42-generic | 5.14.0-687.66.1.el9_8 |
| 디스크 | 40G, LVM 루트 19G | 30G, `/` 30G | NVMe 30G, LVM 루트 27G + 스왑 2G |
| IP | 192.168.10.10 | 192.168.10.20 | 192.168.10.30 |
| 복원 `central-mgmt` → 대상 SSH | `secureops-scan`·`secureops-fix` × 2대 모두 성공 | — | — |
| sudo 허용·차단 | `sshd -T` 허용, `cat /etc/shadow` 차단 (2대) | — | — |
| 확인 방법 | `vmrun` | VMware Tools가 없어 복원 `central-mgmt`에서 SSH로 확인 | `vmrun` |

- **네트워크 분리:** 시험하는 동안 실행 중인 VM은 복원본 3대뿐이었다(`vmrun list`). 따라서 원본과 IP 충돌은 없었다. 복원본은 LAN segment `restore-test`에 연결했다(작업자 확인). 세그먼트를 만든 기록은 VMware 사용자 설정(`preferences.ini`의 `namedPVNs`)에서 확인했다. 복원본 `.vmx`는 시험 후 삭제해 각 VM의 네트워크 설정 자체는 증거로 남기지 못했다.
- 호스트 키와 사용자 키가 백업 안에 그대로 보존되어, 복원 `central-mgmt`에서 `BatchMode=yes`로 경고 없이 접속되었다.
- 스냅샷으로 되돌리기(Go To)는 이 시험에서 하지 않았다. 2026-11-12 `ubuntu-a` 원본에서 `01` → `01-…-passwd` Go To를 시험했다(7-3 2)).
- 복원본은 시험 후 VMware 라이브러리에서 제거하고 폴더를 삭제했다(개인키·`autoinst.iso` 포함).

### 7-3. `ubuntu-a` 자격증명 조치 및 신규 복구 기준 (2026-11-12)

팀장 승인(2026-11-12)에 따라 **`ubuntu-a`에만** 적용했다. sudoers, SSH 설정, `secureops-scan`·`secureops-fix` 계정, 다른 VM은 바꾸지 않았다.

**1) `user1` 비밀번호 변경**

| 확인 | 결과 | 증거 |
| --- | --- | --- |
| 변경 | 다른 서버·계정과 겹치지 않는 새 무작위 비밀번호 적용. `/etc/shadow`의 마지막 변경일 `20769` (= 2026-11-12) | `ubuntu-a-passwd-change-261112.png` |
| sudo | `sudo -k` 뒤 새 비밀번호로 `sudo -v` 성공 | 같음 |
| 콘솔 로그인 | 로그아웃 뒤 새 비밀번호로 재로그인 성공 (작업자 확인) | — |
| 기존 SSH | `central-mgmt`에서 `ubuntu-a`(scan)·`ubuntu-a-fix`(fix) 키 접속 유지 | `central-mgmt-ubuntu-a-ssh-after-passwd-261112.png` |

비밀번호와 해시는 저장소·채팅·외부 서비스에 기록하지 않았다.

**2) 설치 미디어(`autoinst.iso`·`autoinst.flp`) 참조 확인과 해제**

| 단계 | 결과 | 근거 |
| --- | --- | --- |
| 참조 확인 | 현재 `.vmx`와 스냅샷 `00`·`01`(`.vmsn` 안의 설정)이 모두 `sata0:0 = autoinst.iso`, `floppy0 = autoinst.flp`를 참조. 다른 VM은 참조 없음 | 호스트에서 `.vmx`·`.vmsd`·`.vmsn` 설정 줄만 조회 (ISO 내용은 열지 않음) |
| 실제 연결 상태 | 09:19 부팅 시 `CDROM: Connecting sata0:0 to 'autoinst.iso'`, 플로피 이미지 열림 → 게스트에 `sr0`(103.3M)·`fd0`으로 보임 (마운트는 안 됨) | `vmware.log`, `ubuntu-a-media-before-261112.png` |
| 연결 해제 | VM 종료 후 autoinst CD·Floppy 장치 **제거**, 설치 ISO(`sata0:1`)는 `startConnected = FALSE` | `.vmx` 재확인 |
| 재부팅 | autoinst 연결 기록 없음, 게스트에는 빈 `sr0`(1024M)만 있음, sudo·SSH 정상 | `ubuntu-a-media-after-261112.png`, `central-mgmt-ubuntu-a-ssh-after-media-261112.png` |
| 격리 후 기존 스냅샷 시험 | 두 파일을 VM 폴더 밖으로 옮긴 뒤 `01`로 Go To → 부팅. 아래 메시지와 함께 해당 장치만 끊긴 채 로그인 화면까지 정상 부팅 | `ubuntu-a-revert01-boot-261112.png`, `vmware.log` |
| 새 기준으로 복귀 | `01-ssh-security-configured-passwd`로 Go To → 부팅. autoinst 경고 없음, sudo·SSH 정상 | `ubuntu-a-revert-passwd-261112.png`, `central-mgmt-ubuntu-a-ssh-after-revert-261112.png` |
| 원본 삭제 | 위 시험 통과 후 2026-11-12 10:15 영구 삭제. VM 폴더에 `autoinst*` 0개 | 호스트 확인 |

`01`로 되돌렸을 때 `vmware.log`에 남은 메시지:

```text
[msg.floppyImage.inaccessibleFile] Floppy "autoinst.flp" is inaccessible.
[msg.device.startdisconnected] Virtual device 'floppy0' will start disconnected.
[msg.cdromImage.cantOpen] Cannot connect file "autoinst.iso" as a CD-ROM image: Could not find the file
[msg.device.startdisconnected] Virtual device 'sata0:0' will start disconnected.
```

- 장치를 제거해도 `.vmx`에는 `sata0:0.fileName`, `floppy0.fileName` 줄이 남는다. 장치가 비활성(`present` 없음 / `FALSE`)이라 파일을 읽지 않으며, 위 재부팅 시험으로 확인했다.
- 원본에서만 삭제했다. **기존 백업 ZIP(2026-11-11)에는 `autoinst.iso`가 그대로 있다.**

**3) 신규 스냅샷 — 일반 복구 기준**

| 이름 | 대상 | 생성 | 상태 |
| --- | --- | --- | --- |
| `01-ssh-security-configured-passwd` | `ubuntu-a`만 | 2026-11-12 10:03:41, VM 종료 상태 | 팀장 승인, **`ubuntu-a` 일반 복구 기준** |

- 스냅샷 트리: `00-initial-setup` → `01-ssh-security-configured` → `01-ssh-security-configured-passwd` (`ubuntu-a-snapshot-261112.png`)
- 이 스냅샷에 저장된 설정에는 autoinst 장치가 없다(`.vmsn` 확인).

**4) 신규 백업과 검증**

| 파일명 | 백업 시점 | 크기 | SHA-256 |
| --- | --- | --- | --- |
| `Target-Ubuntu-261112.zip` | 2026-11-12 10:24 | 4,469,751,437 bytes (4.16 GiB) | `6D184A80E78BE2A548A84A56A2EC89DAF767117E9527007962DD1533F18064EF` |

| 항목 | 결과 |
| --- | --- |
| 7-Zip `7z t` | Everything is Ok (55개) |
| 필수 파일 (`.vmx`, `.vmsd`, `.vmxf`, `.nvram`, `.vmsn` 3개) | 있음 |
| 스냅샷 (`.vmsd`) | `00` → `01` → `01-…-passwd`, 현재 위치는 passwd 다음 |
| 디스크 연결 (기본 → `-000001` → `-000002` → `-000003`(현재)) | 참조 35건, 누락 0 |
| 제외 확인 | `autoinst*` 0, `.lck` 0, `.vmem`·`.vmss` 0 |
| 원본 폴더 비교 | `.lck`를 뺀 55개 파일 이름·크기·SHA-256 모두 일치 |

- 압축 직전 원본 폴더에 `Target-Ubuntu.vmx.lck`가 있었다(VM은 `VMX exit (0)`으로 종료됨). Workstation에 VM 탭이 열려 있는 동안 유지되는 잠금이라 압축에서 제외했다(`-xr!*.lck`).

**5) 복원 시험 (2026-11-12)**

ZIP을 원본과 다른 폴더에 풀어 VMware에서 열고, **원본 `ubuntu-a`는 끈 상태**에서 복원본만 VMnet8에 연결해 실행했다(`vmrun list`로 확인).

| 확인 | 결과 |
| --- | --- |
| 스냅샷 표시 (`vmrun listSnapshots`) | 3개 모두 표시 |
| 처음 켤 때 | "I Copied It"으로 진행되어 MAC이 새로 생성됨. 고정 IP는 그대로 적용 |
| IP / 장치 | `ens33 192.168.10.20/24`, 빈 `sr0`만 있음 |
| 자격증명 | 새 비밀번호로 콘솔 로그인, `sudo -v` 성공 |
| `central-mgmt` → 복원본 SSH | scan·fix 모두 성공. `BatchMode`에서 호스트 키 경고 없음 (호스트 키 보존) |
| 증거 | `ubuntu-a-restore-test-261112.png`, `central-mgmt-ubuntu-a-ssh-restore-261112.png` |

복원본은 시험 후 라이브러리에서 제거하고 폴더를 삭제했다(2026-11-12 11:09).

**6) 과거 자료 취급 (팀장 지시)**

- 기존 스냅샷 `00-initial-setup`, `01-ssh-security-configured`는 **삭제하지 않고 유지**한다. 과거 자료 삭제 여부는 이후 별도 승인으로 정한다.
- 기존 백업 ZIP(2026-11-11)은 보존하되 접근을 제한한다. 파일명을 `Target-Ubuntu-261111-legacy-oldhash.zip`으로 바꾸고 읽기 전용으로 설정했다(SHA-256은 7-1 표와 같음, 2026-11-12 재확인).
- 기존 스냅샷과 기존 백업에는 노출된 **과거 비밀번호 해시**가 남아 있으므로 **일반 복구에 쓰지 않는다.**
- 불가피하게 이전 상태로 복구할 때는 **네트워크를 격리한 상태에서** 자격증명을 다시 설정하고 검증한 뒤에만 VMnet8 접속을 복구한다.
- **신규 백업(`Target-Ubuntu-261112.zip`)에도 `00`·`01` 스냅샷 디스크가 포함된다.** 따라서 신규 백업에서 과거 해시가 완전히 제거되었다고 보지 않는다. 바뀐 것은 현재 상태(`01-…-passwd` 이후)의 자격증명이다.

**7) 백업 절차 보완 (다음 백업부터)**

1. 게스트에서 `sudo poweroff`로 종료한다.
2. Workstation에서 해당 VM 탭을 닫는다(또는 라이브러리에서 Remove). 탭이 열려 있으면 `.vmx.lck`가 남는다.
3. VM 폴더에 `.lck`, `.vmem`, `.vmss`가 없는지 확인한 뒤 압축한다.
4. 기존 백업과 다른 파일명(`<VM>-YYMMDD.zip`)으로 만들고, SHA-256·`7z t`·원본 비교·복원 시험을 한다.

## 8. 디렉터리 구조

```text
infrastructure/
├── README.md                     # 인프라 구성·구축 절차·검증 기준 문서 (이 문서)
├── HANDOFF.md                    # 진단 실행 환경 인수인계 (SSH 접속, 실행 환경, 명령 경로·권한)
├── network/                      # 서버별 고정 IP 설정 파일
│   ├── netplan-central-mgmt.yaml # 중앙 관리 서버 netplan 설정 (192.168.10.10)
│   ├── netplan-ubuntu-a.yaml     # 진단 대상 A netplan 설정 (192.168.10.20)
│   └── nmcli-rocky-b.sh          # 진단 대상 B nmcli 설정 명령 (192.168.10.30)
├── setup/                        # 기본 설정 자동화 스크립트 (비밀번호 설정 제외)
│   ├── ubuntu-ssh-setup.sh       # Ubuntu: 패키지 업데이트, 시간대, OpenSSH 서버 설치·실행
│   ├── rocky-ssh-setup.sh        # Rocky: 패키지 업데이트, 시간대, sshd 실행
│   └── ssh-key-setup.sh          # 전용 계정(secureops-scan/fix) 생성, Ed25519 키 생성 및 공개키 등록
└── evidence/                     # 검증 캡처 (<서버 식별자>-<항목>-YYMMDD.png)
    ├── central-mgmt/             # 중앙 관리 서버 확인 + 진단 대상 원격 확인(VM 간 통신, SSH 키, 읽기 권한)
    ├── ubuntu-a/                 # 진단 대상 A 확인 캡처
    └── rocky-b/                  # 진단 대상 B 확인 캡처
```

설정 파일과 스크립트는 구축을 진행하며 순차적으로 추가한다.

## 9. VM 공유 방법

VM 자체가 필요한 경우 VMware **File → Export to OVF**로 `.ova` 파일을 만들거나, 7-1의 VM 폴더 zip 백업을 공유 저장소로 전달한다. 공유 대상은 지정한 팀원 계정으로 제한한다. VM에 설정된 비밀번호는 5-5의 비밀번호 정책에 따라 공유하지 않으며, 접근 방식은 팀에서 별도로 정한다.

## 10. 팀 협의 필요 사항

- [x] 중앙 관리 서버의 서버 식별자 및 호스트명 (`central-mgmt` / Central-Management-Ubuntu)
- [ ] 재구축 후 `central-mgmt` 호스트명이 소문자(`central-management-ubuntu`)로 설정됨 — 이전 표기로 되돌릴지 여부 (2장)
- [x] 진단 대상 호스트명을 서버 식별자(`ubuntu-a`, `rocky-b`)와 맞출지 여부 (호스트명은 Target-Ubuntu, Target-Rocky 유지)
- [x] 전용 계정·SSH 키 등록 이후 스냅샷 이름 (`01-ssh-security-configured`)
- [ ] 스냅샷 `02` 이후 단계 이름 확정
- [ ] JSON 필드명 `target_id` / `server_id` 통일 (D · 조효민)
- [ ] sudoers 초안 v0 검토 및 확정 (과도·부족 권한 확인)
- [ ] SSH-01 외 조치 항목의 `secureops-fix` 권한 및 `/etc/secureops/approved/` 승인 파일 관리 절차
- [ ] SSH-01의 `PermitRootLogin without-password`(배포판 기본값) 판정 기준
- [ ] root 직접 SSH 로그인 제한 등 `sshd_config` 변경 적용 시점
- [ ] 계정별 SSH 키 분리 방식 (`id_ed25519_scan`, `id_ed25519_fix`) 확정
- [ ] `02-vuln-baseline`에 적용할 취약 설정 목록 (B · 최종욱, C · 김서후)
- [ ] 진단 대상 Desktop의 자동 업데이트 사용 여부 (재검증 일관성) — 2026-11-11 `central-mgmt` 커널이 증거 촬영 뒤 6.8.0-139 → 149로 바뀐 사례 있음 (2장)
- [x] `ubuntu-a` 원본의 `autoinst.iso`·`autoinst.flp` 연결 해제·삭제 여부 — 2026-11-12 조건부 승인, 참조 확인·해제·재부팅·스냅샷 시험 후 원본 삭제 (7-3)
- [x] `ubuntu-a` `user1` 비밀번호 변경 여부 — 2026-11-12 승인·적용, 신규 스냅샷 `01-ssh-security-configured-passwd`를 일반 복구 기준으로 지정 (7-3)
- [ ] 과거 해시가 남은 기존 스냅샷(`00`, `01`)과 기존 백업 ZIP의 삭제 여부 — 현재는 유지·접근 제한, 이후 별도 승인 (7-3 6))

## 11. 재구축 이력

### 11-1. 경위

| 일자 | 내용 |
| --- | --- |
| 2026-11-05~06 | VM 3대 최초 구축, 스냅샷 `00-initial-setup`·`01-ssh-security-configured` 생성, 검증 증거 확보 (`*-261105.png`, `*-261106.png`) |
| 2026-11-08 | 계획 변경(서버 6대 구성) 논의 중 VM 3대와 스냅샷이 삭제됨 |
| 2026-11-08~10 | 복구 검토: VMDK와 스냅샷이 모두 삭제되어 복구할 수 없음. 별도 드라이브의 백업은 `00-initial-setup` 이전 설정 오류로 폐기했던 것이고, 디스크가 3대 모두 60GB로 사양과 달라 사용하지 않음 |
| 2026-11-11 | 팀장 결정으로 6대 구축은 보류하고, 핵심 3대를 기존 사양(2장)으로 재구축. 스냅샷 재생성(7장), VM 폴더 백업(7-1), 검증 증거 재확보 (`*-261111.png`) |

- 재구축 전 증거(`*-261105.png`, `*-261106.png`)는 **삭제된 VM의 기록**으로만 보존한다. 신규 VM의 검증 근거로 쓰지 않는다.
- 재구축 전 문서 내용은 v0.1(11-2 변경 이력)과 Git 이력에서 확인한다.
- 재구축으로 호스트 키와 사용자 키가 모두 바뀌었다 (5-5의 5)).

### 11-2. 재구축 중 문제 해결

| 서버 | 증상 | 원인 | 조치 |
| --- | --- | --- | --- |
| `central-mgmt` | DNS 조회 실패 | 설치 시 Name servers 입력 누락 | netplan에 `nameservers: addresses: [192.168.10.2]` 추가 후 `sudo netplan try` |
| `rocky-b` | 호스트명이 `localhost.localdomain` | 설치 시 호스트명 미적용 | `sudo hostnamectl set-hostname Target-Rocky` |
| 공통 | Windows에서 SSH 접속 시 호스트 키 변경 경고 | 재설치로 호스트 키 변경 | `ssh-keygen -R <IP>` 후 지문 확인하고 재접속 |
| `ubuntu-a` | sudoers fix 명령 인자 순서 불일치 | 재구성 시 `install` 옵션 순서가 달라짐 | 이전과 같은 `-m 0600 -o root -g root`로 수정 (sudoers는 인자를 순서까지 비교) |

## 12. 변경 이력

| 버전 | 일자 | 변경 사항 |
| --- | --- | --- |
| v0.1 | 2026-11-05 | 서버 구성(실제 OS 버전·에디션·커널), 네트워크, 구축 절차, 비밀번호 정책, SSH 키 인증 및 계정 구성(user1, secureops-scan, secureops-fix), 검증 체크리스트, 스냅샷 규칙 초안 작성 (아키텍처 설계서 v0.2 기준), sudoers 초안 v0 적용 내용 추가(2026-11-06), 공통 SSH 모듈 연동 정보 추가, 검토 반영 (`central-mgmt` 확정, 적용 완료·예정 구분, `01-ssh-security-configured` 스냅샷 및 계정 권한 현황 추가, `01` 스냅샷 재생성 반영(2026-11-06)) |
| v0.2 | 2026-11-11 | VM 3대 재구축 반영: 2장 서버 구성(호스트명·커널·인터페이스) 갱신, 5-5 호스트 키·사용자 키 재생성 안내, 5-6 sudoers 재적용 내용과 재검증 결과, 5-7 신규 VM SSH 접속 테스트, 6장 체크리스트를 261111 증거 기준으로 갱신(백업 검증 항목 추가), 7장 스냅샷 재생성, 7-1 VM 백업 현황(SHA-256), 11장 재구축 이력 추가, 신규 증거를 `infrastructure/evidence/`로 정리 |
| v0.3 | 2026-11-11 | 백업 최종 검증 반영: 7-1 ZIP 구성·7-Zip·디스크 연결·원본 비교 결과, `.vmx.lck` 원인, `autoinst.iso` 민감정보, 7-2 복원 시험 추가, 6장 체크리스트(백업·복원·sudoers 권한·Description) 완료 처리, 신규 증거 43장과 보안 검사 범위 기재, `central-mgmt` 커널 6.8.0-149 정정, 10장 협의 사항 추가 |
| v0.4 | 2026-11-12 | 5-7 5)와 6장 체크리스트에 SSH 출발지 IP·실제 인증 키 확인 추가(상세는 HANDOFF 2-4), 증거 2장(`*-261112.png`) 추가 |
| v0.5 | 2026-11-12 | 7-3 추가: `ubuntu-a` `user1` 비밀번호 변경, 설치 미디어 참조 확인·제거·원본 삭제, `01-ssh-security-configured-passwd` 스냅샷(일반 복구 기준), 신규 백업 SHA-256·검증·복원 시험, 과거 자료 취급 원칙, 백업 절차 보완(`.lck`). 7장·7-1·7-2·6장·10장 갱신, 증거 11장 추가 |
| v0.6 | 2026-11-12 | 6장 체크리스트에 SSH 별칭·SSH-01 평가 문맥, C 요청 권한 재측정 추가(상세는 HANDOFF 2-5·4장), 증거 6장 추가 |

---

본 환경은 허가된 실습 목적의 격리된 VM에서만 사용한다.
