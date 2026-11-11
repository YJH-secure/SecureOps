# C JSON v1.2 공식 코드 커밋 기준 로컬 검증

기반 main은 PR #22 Squash 병합 커밋
6bf80bb114458994bec7d640b4fe4ec53b97bb10이다.
검증한 공식 C 코드 커밋은 d21816689f7a795a64657148067994a28201772e다.

GitHub의 해당 커밋 트리와 Git blob 해시가 일치하는 54개 실행·검증 입력 파일을
로컬에 구성했다. C 코드·테스트·정책·스키마·샘플 및 D core 코드가 포함된다.
임의 커밋 표식만 붙인 로컬 소스를 공식 코드 실행으로 보고하지 않았다.

실행 환경은 Windows Python 3.12.14다.
검증에 사용한 D core는 기반 main 6bf80bb의 코드이며 동일한 소스가 C 브랜치에
상속돼 있다. C PR에서 D 운영 코드를 수정하지 않았다.

| 검증 | 결과 |
| --- | --- |
| C 단위·회귀 | 163개 통과 |
| 같은 MOCK 입력의 v1.1 원본 보존 및 v1.2 5종 상태 | 5/5 통과 |
| 잘못된 JSON·CVSS·실행 및 전달 조건 거부 | 28/28 통과 |
| D 로컬 MOCK 수신·검증·집계·저장·재조회 | 5/5 통과 |

## 명령과 원본 로그

```bash
python -B -m unittest discover -s checks/system/tests -v
python -B -m checks.system.verify_json_scenarios \
  --code-commit d21816689f7a795a64657148067994a28201772e \
  --output-dir verification-runs/official-d218166
```

unit-tests-d218166.txt는 단위·회귀 출력이다. scenarios-d218166.txt는 시나리오
출력이며 로컬 사용자 경로를 제거했다. scenario-evidence-d218166.json에는
실제 v1.1·v1.2 JSON, D가 저장·재조회한 보고서와 조건별 성공 여부가 있다.
rejections-d218166.json에는 28개 거부 조건과 검사 결과를 기록했다.

pass, error, needs_review, not_applicable은 CVSS not_applicable로,
vulnerable은 pending으로 출력됐다. 점수·Vector·등급·version·source는 null이다.
기존 evidence·recommendation·details와 상태가 보존됐다.
기존 severity를 바꾼 추가 입력에서도 CVSS 결과가 동일했다.

not_applicable은 제외 승인을 fixture 안에서만 가정한 계약 예시다.
FW·LOG는 수집 단계의 error·needs_review를 사용하며, 미구현 운영 판정이나
실제 FILE 제외 정책 평가를 구현 완료로 표시하지 않았다.

## 이전 ZIP과의 차이

참고 ZIP은 SecureOps_JSON_v12_5status_Demo.zip이며 SHA-256은
d802c42a3e801bec1699696fe69f3148caf740aca60269dc5bf4f7b077bf411f다.

검증된 어댑터·CLI·정책·테스트 입력을 재사용했다.
독립 ZIP의 시나리오 runner와 입력 생성 함수를 저장소 모듈인
verify_json_scenarios.py·scenario_inputs.py로 옮겼다.
기대 결과 JSON은 checks/system/scenarios 아래로 이동했다.
기본 D 경로는 동봉 사본 대신 저장소 core를 사용하며 외부 D checkout도 선택할 수 있다.
커밋 표식과 별도 실제 파일 해시 대조 절차를 문서화했다.
원래 ZIP을 수정하거나 그 실행 결과를 이번 공식 실행 결과로 복사하지 않았다.
zip-comparison.json에 코드·정책·테스트 비교 결과와 파일 해시를 기록했다.

## 완료 범위와 후속 검증

이번 결과는 공식 C 코드 커밋과 상속된 D 코드를 사용한 에이전트의 로컬 MOCK
실행이다. 효민 담당자가 별도 확인한 최종 C·D 커밋 조합의 재검증은 후속 확인이다.
공식 PR과 C 커밋을 공유하고 담당자 재실행 결과를 추가로 기록한다.

실제 Ubuntu·Rocky에서 이번 공식 커밋을 재실행하거나 SSH를 연결하지 않았다.
운영 정책 승인·sudoers 적용·실제 SSH·D 실서버 검증과 구분한다.
이 검증 자료 후속 커밋은 문서·로그·합성 증거만 추가하며 코드·정책·테스트를
변경하지 않는다. main 병합은 팀장의 최종 리뷰·승인 후 진행한다.
