# 새 수정본 VM 확인 및 원본 evidence 보관

이번 새 수정본은 그룹 조회 상태 구분을 추가했습니다. 이전 98개 결과를 덮어쓰지 말고
Ubuntu와 Rocky 각각 새 폴더에 압축을 풀어 실행하세요.

## 1. 새 코드 실행

압축 해제한 프로젝트 루트(checks, docs, tests가 함께 보이는 곳)에서:

```bash
bash checks/system/verify_vm.sh
```

완료 화면에 단위 테스트 105개, 임시 시나리오 13/13, JSON14개가 나오는지 확인하고
마지막 Evidence folder 경로를 기록하세요. 실제 진단의 상태값은 그대로 보존하세요.
오류가 있으면 양호로 바꾸거나 sudo로 재실행하지 말고 원인부터 확인하세요.

## 2. 실제 수치 및 그룹 조회 상태

다음은 조회만 수행합니다. shadow 내용은 출력하지 않습니다.
각 OS에서 출력 화면을 보관하세요.

```bash
cat /etc/os-release
python3 --version
stat -c '%n uid=%u gid=%g mode=%a type=%F' /etc/passwd /etc/shadow
getent group shadow
printf 'group lookup exit=%s\n' "$?"
getfacl -n -p /etc/passwd /etc/shadow
```

getent 종료 코드만으로 NSS 장애와 그룹 미존재를 완벽하게 구분할 수는 없습니다.
원본 오류와 새 FILE-01 JSON의 group_lookup_state, 숫자 GID, OS별 정책을 함께 비교합니다.
권한 부족은 숨기거나 임의 설정 변경으로 해결하지 않고 error 증거로 보관합니다.

## 3. 발표용 원본

이전/새 실행 각각 다음 파일을 그대로 보관하세요.

- unit-tests.txt: 전체 회귀 테스트 이름과 통과 기록
- file01-result.json: 실제 FILE-01 결과
- file01-fixture-evidence.json: MOCK 승인 정책의 임시 ACL·링크 13개 결과
- verification-summary.json: 단계별 성공/실패와 실제 상태
- 실행 종료 화면 스크린샷 및 위 메타데이터 조회 스크린샷

file01-result.json은 텍스트 편집기에서 열고 details.files의 actual을 확인하면 됩니다.
원본은 별도로 보존하고, 공개용 사본의 식별정보를 검토하세요. 원본을 합성 예시로 대체하지 않습니다.
현재 AI는 사용자 VM에 직접 접속하지 않았으며 이 새 버전을 실행한 것으로 보고하지 않습니다.
