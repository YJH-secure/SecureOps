# Draft PR 제출 전 재검증

2026-11-11 09:36:35–09:36:48 KST에 현재 소스로 Python 프로세스를 새로 실행했다.
과거 실행 기록은 덮어쓰지 않았다. 이 디렉터리는 별도 제출 전 실행 기록이다.

- 브랜치: `feature/c-d-v12-zip-integration-jhm`
- 기준 `origin/main`: `f7e4f16d94e68e408087de2cf34a9337a4f63ddf` (PR #19 병합 포함)
- 기존 PR #19 HEAD: `8ae2ca1ba09f45c6b0f4a6c49a6a1572f0caca95`
- C 출처: 담당자 제공 ZIP. **공식 C Git 커밋 검증이 아니다.**
- ZIP SHA-256: `636bca49f28eca129ad973fd0479d7d8b87acc7513ec7fa41b2b4485781999c8`
- 추출 소스 57개 해시가 기존 ZIP 검사 명세와 일치했다. ZIP 원본과 C 소스는 제출하지 않는다.
- Windows 11 / Python 3.14.2 / jsonschema 4.25.1.

| 실행 | 발견 | 통과 | 건너뜀 | 실패 | 오류 | 실제 로그 |
|---|---:|---:|---:|---:|---:|---|
| C ZIP → D 신규 통합 | 9 | 9 | 0 | 0 | 0 | [01](01-c-zip-nine.log) |
| 외부 소스 없는 전체 | 158 | 136 | 22 | 0 | 0 | [02](02-default-full.log) |
| 외부 소스 제공 전체 | 158 | 158 | 0 | 0 | 0 | [03](03-all-offline.log) |

158개는 기존 D 149개와 신규 C ZIP 통합 9개의 합이다.
기본 환경의 건너뜀은 고정 B/C 3개, 최신 B 10개, C ZIP 9개 소스 부재로 발생한다.
CVSS 52개와 v1.1 84개는 변경 없이 전체 실행에 포함됐다.
C 자체 163개 단위 테스트나 실제 SSH/VM 실행 결과를 의미하지 않는다.

정확한 명령·시간·환경·소스 커밋은 [results.json](results.json)에 기록했다.
[rerun.py](rerun.py)는 기존 증거를 덮어쓰지 않으며 결과 파일이 이미 있으면 중단한다.

```powershell
python -B -X utf8 docs/evidence/c-v12-zip-mock-20261110/submission-20261111/rerun.py --c-source-root <EXTRACTED_ROOT> --zip-file <ZIP>
```

실제 C 판정 및 어댑터를 호출하고 수집 입력만 합성했다. FILE은 vulnerable/pending,
SVC와 FW는 needs_review/not_applicable, LOG는 error/not_applicable로 수신됐다.
점수와 등급은 모두 null이다. scored 9.8 Critical은 별도의 기존 D MOCK이며 C 결과로 표시하지 않는다.
진단 error JSON 수신, 실행 실패/잘못된 JSON/CVSS 거부, v1.1 기본값,
v1.2 명시 선택, 집계·저장·재조회 및 중첩 details 원본 보존을 확인했다.

기존 tracked 파일과 과거 C ZIP 증거·신규 테스트의 실행 전후 해시가 일치했다.
테스트 결과와 저장 JSON은 합성 관측이며 실제 서버·계정·인증정보를 포함하지 않는다.
원본 ZIP은 해시와 파일 해시 목록으로만 식별한다.

남은 사항은 공식 C 커밋 제공 후 재검증, 운영 정책 승인 확인, 실제 scored 메트릭 근거 제공,
LOG 설정 탐색의 별도 입력 경계 확인이다. 실제 SSH/VM은 미실행이다.
자세한 선행 결과와 제한은 [기존 검증 보고서](../c-to-d-v12-report.md)를 보존했다.
그 보고서의 미제출 문구는 당시 시점의 기록이다. 이번 Draft PR 제출 상태와 구분한다.

과거 검증 명세의 파일 SHA-256은 당시 로컬 원본 바이트 기준이다. Git의 CRLF/LF 정규화로
체크아웃 바이트의 해시는 달라질 수 있다. 원본 명세를 다시 쓰지 않았으며 ZIP 해시에는 영향이 없다.
