# FILE-01 정책 조사·승인 요청 초안

작성일: 2026-11-06. 이 문서는 제안이며 정책 승인이나 자동 조치 지시가 아닙니다.
정책 JSON 승인 상태와 공통 결과 JSON v1.1은 변경하지 않았습니다.

## 1. 실제 관측과 후보 기준

| OS / 파일 | 현재 확보한 실제 관측 | 팀 정책 후보 또는 기존 승인 범위 |
|---|---|---|
| Ubuntu 24.04.5 passwd | 사용자 제공 v6.2 결과 화면의 실측값. UID 0, GID 0, 0644, regular, 기본 ACL | UID 0, 0644 부분집합. 그룹 최종 승인 대기 |
| Ubuntu 24.04.5 shadow | 사용자 제공 v6.2 결과 화면의 실측값. UID 0, GID 42, 0640, regular, 기본 ACL | UID 0, root 또는 대상 VM의 shadow 그룹, 0640 부분집합. 최종 승인 전 |
| Rocky 9.8 passwd | 사용자 제공 v6.2 실제 JSON: UID 0, GID 0, 0644, regular, 기본 ACL | UID 0, 0644 부분집합. 그룹 최종 승인 대기 |
| Rocky 9.8 shadow | 사용자 제공 v6.2 실제 JSON: UID 0, GID 0, 0000, regular, 기본 ACL | UID 0, GID 0, 0000. 프로젝트 강화 후보, 최종 승인 전 |

기본 권한은 8진수 숫자 대소가 아닌 허용 비트 집합으로 비교하며 특수 비트도 검사합니다.
허용 상한 충족만으로 인증 기능이나 모든 보안 조건의 충족을 의미하지 않습니다.
필수 읽기 권한의 하한, passwd 내 비인가 UID 0 계정 분석은 별도 범위 합의가 필요합니다.
파일 내용·해시는 수집하지 않습니다.

## 2. 공식 자료와 적용상의 차이

- [Ubuntu 24.04 shadow(5)](https://manpages.ubuntu.com/manpages/noble/man5/shadow.5.html)는
  일반 사용자에게 shadow 읽기를 허용하지 않아야 한다는 원칙을 설명합니다.
  이 문서만으로 root:shadow 0640이 모든 배포에서 확정 권장값이라고 단정하지 않습니다.
- [Red Hat 공식 기술문서](https://access.redhat.com/solutions/7139954)는 RHEL에서
  shadow의 설치 시 0000이 pwconv 이후 0400으로 바뀌는 사례를 설명합니다.
  Rocky의 직접 실측·공식 권장값과 동일시하지 않습니다. 0400을 일괄 취약으로
  처리할지에는 프로젝트 0000 강화 정책의 승인 및 운영 기능 검토가 필요합니다.
- [KISA 공식 상세가이드 게시물](https://krcert.or.kr/kr/bbs/view.do?bbsId=B0000127&menuNo=205021&nttId=71928)은
  확인했으나 이번 도구에서 해당 첨부 본문을 확보하지 못했습니다.
  따라서 정확한 적용 판본·항목 번호·passwd/shadow 수치의 원문 대조는 미완료입니다.
  팀이 참고한 U-16 등을 최신 판본과 동일하다고 가정하지 않습니다.
  팀장님께 적용 판본과 해당 조항 확인을 요청합니다.

## 3. ACL 판정 초안

[Linux acl(5)](https://www.man7.org/linux/man-pages/man5/acl.5.html)에 따라
named user, owning group 및 named group 권한에는 mask를 적용합니다.
소유자와 other에는 mask를 적용하지 않습니다. 확장 ACL에서는 mode의 그룹 비트가
ACL mask를 반영하므로 group::만을 mode 그룹 비트와 단순 비교하지 않습니다.

제안: 대상별 승인 UID/GID와 허용 유효 권한을 명시적으로 승인받습니다.
승인된 기준 위반이 확인되면 vulnerable, 승인 목록 미확정은 needs_review,
필수 메타데이터·ACL 조회/파싱 오류 또는 mode와 ACL 불일치는 error로 기록합니다.
ACL이 존재한다는 이유만으로 취약 판정을 하지 않습니다.
이는 DAC 기반 권한 검사이며 SELinux·모든 계정의 보조 그룹·전체 경로 접근 가능성까지
포괄한 실효 접근성 증명은 아닙니다.

## 4. 링크 판정 초안

[Linux symlink(7)](https://man7.org/linux/man-pages/man7/symlink.7.html)는
링크와 대상이 별도 객체이며 대상이 없을 수도 있음을 설명합니다.
현재 구현은 lstat/readlink 기반 읽기 전용 검사, 기본 /etc 범위, 최대 8단계,
순환·깨진 링크·깊이 초과 error, 범위 이탈 needs_review입니다.
허용된 실제 대상의 소유자·권한·ACL과 안정성을 추가 검사하며 파일 내용은 읽지 않습니다.
명시적으로 승인된 대상 목록이 없으면 링크를 양호로 판정하지 않습니다.
제안: /etc 범위, 최대 깊이 8, 허용 대상 경로와 예외 처리 방식을 승인받습니다.
임시 테스트에 사용한 외부 루트는 테스트 주입값이며 운영 허용 범위가 아닙니다.
경로 기반 스냅샷 검사는 파일 변경을 일부 탐지하지만 모든 동시 교체 공격을 방지하는
원자적 접근 보장을 의미하지 않습니다.

## 5. Rocky shadow 그룹 구분

파일의 숫자 GID 수집과 이름 shadow의 존재 여부는 별개입니다.
Rocky에서 이름 shadow가 없더라도 GID 0 기준 검사에 그 이름은 필요하지 않습니다.
새 수정에서는 이름 없음(KeyError)을 absent, NSS/OS 조회 실패를 error로 구분합니다.
승인된 대체 조건 GID 0이 충족되면 불필요한 이름 조회 실패로 오판하지 않습니다.
필수 이름 조회가 실패해 대조할 수 없으면 error,
정상 조회 결과에 해당 이름이 없고 대안도 확인되지 않으면 정책 검토 needs_review입니다.
숫자 GID 자체가 누락되면 정책 미확정 여부와 관계없이 error입니다.

## 6. 팀장 승인·자료 요청

OS별 actual 메타데이터와 적용 KISA 판본·조항, passwd 그룹 및 최소 필요 읽기,
shadow 후보 허용값, ACL 승인 주체/유효 권한, 링크 범위/깊이/허용 대상,
위 예외 상태 분류를 검토해 주세요. 승인 전 JSON 후보 상태를 유지합니다.
