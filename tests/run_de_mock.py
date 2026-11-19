"""프로젝트 루트에서 python -B tests/run_de_mock.py로 실행한다.

PR #8의 고정 커밋에서 D 원본을 임시 폴더에 추출하고 E 단위 테스트와
D↔E 통합 테스트를 함께 실행한다. D 커밋은 로컬 Git에 있어야 한다.
원격 다운로드나 브랜치 변경은 수행하지 않는다. Python 3.12 기준.
"""

import argparse
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


D_COMMIT = "994d20c1d7a914ba8a77ab9e89ea7080c16e171e"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--d-ref", default=D_COMMIT, help="D source ref; use origin/main for latest fetched main")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", args.d_ref + "^{commit}"],
        cwd=repo, capture_output=True, text=True, check=False,
    )
    if resolved.returncode:
        raise SystemExit("D source ref is unavailable in local Git")
    commit = resolved.stdout.strip()
    archive = subprocess.run(
        ["git", "archive", "--format=tar", commit, "core"], cwd=repo,
        capture_output=True, check=False,
    )
    if archive.returncode:
        raise SystemExit(f"D 기준 커밋 {commit}의 core 소스를 로컬 Git에서 읽지 못했습니다")

    # 소스와 보고서 모두 임시 디렉터리에서 사용하고 실행 후 정리한다.
    with TemporaryDirectory(prefix="secureops-d-source-") as directory:
        with tarfile.open(fileobj=BytesIO(archive.stdout)) as source:
            source.extractall(directory, filter="data")
        environment = dict(os.environ, SECUREOPS_D_SOURCE=directory)
        print(f"D 기준 커밋: {commit}", flush=True)
        # 각 테스트를 별도 프로세스에서 실행해 다른 D 버전의 import가 섞이지 않게 한다.
        for pattern in ("test_remediation.py", "test_remediation_core_integration.py"):
            result = subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"],
                cwd=repo, env=environment, check=False,
            )
            if result.returncode:
                return result.returncode
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
