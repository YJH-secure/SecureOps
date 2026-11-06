"""전용 비공개 디렉터리의 append-only 보고서 저장소.

동일 파일시스템의 하드링크를 지원해야 한다. 저장소 디렉터리는 신뢰된
관리자만 변경할 수 있어야 하며 Windows에서는 별도 NTFS ACL 설정이 필요하다.
민감정보 탐지는 보조 수단이며 모든 개인정보의 자동 식별을 보장하지 않는다.
"""

from copy import deepcopy
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile

from core.main import DiagnosisAggregator


def _check_sensitive(value):
    secret_key = re.compile(r"^(?:password|passwd|token|access_token|refresh_token|api_key|"
                            r"secret|private_key|cookie|authorization)$", re.I)
    secret_text = re.compile(
        r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|"
        r"\bBearer\s+\S+|\b(?:password|token|api[_-]?key|secret|cookie)\s*[:=]\s*\S+",
        re.I,
    )
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON 객체의 키는 문자열이어야 합니다.")
            if secret_key.fullmatch(key):
                raise ValueError("민감정보 의심 필드가 있어 저장·조회를 거부합니다.")
            _check_sensitive(item)
    elif isinstance(value, list):
        for item in value:
            _check_sensitive(item)
    elif isinstance(value, str):
        if secret_text.search(value):
            raise ValueError("민감정보 의심 내용이 있어 저장·조회를 거부합니다.")
    elif value is not None and type(value) not in (bool, int, float):
        raise TypeError("JSON으로 보존할 수 없는 값입니다.")


class ReportStore:
    def __init__(self, root):
        path = Path(root).absolute()
        if path.is_symlink() or path.resolve() != path:
            raise ValueError("저장소 경로에 심볼릭 링크를 사용할 수 없습니다.")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.is_dir():
            raise ValueError("저장소는 디렉터리여야 합니다.")
        self.root = path

    @staticmethod
    def _id(value):
        if not isinstance(value, str):
            raise TypeError("ID는 문자열이어야 합니다.")
        if not value:
            raise ValueError("ID는 비어 있을 수 없습니다.")
        return value

    def _path(self, scan_id):
        digest = sha256(self._id(scan_id).encode("utf-8")).hexdigest()
        return self.root / f"{digest}.json"

    @staticmethod
    def _validate(report):
        DiagnosisAggregator._validate_report(report)
        _check_sensitive(report)
        return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)

    def save(self, report):
        """검증된 보고서를 배타적으로 추가하고 최종 경로를 반환한다."""
        data = deepcopy(report)
        payload = self._validate(data)
        destination = self._path(data["scan_id"])
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.root,
                prefix=".pending-", suffix=".tmp", delete=False,
            ) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            # replace/rename과 달리 기존 이름이 있으면 원자적으로 실패한다.
            os.link(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return destination

    def _read(self, path):
        if path.is_symlink() or not path.is_file():
            raise ValueError("보고서는 일반 파일이어야 합니다.")
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as error:
            raise ValueError("저장된 보고서 JSON이 손상되었습니다.") from None
        self._validate(report)
        if path != self._path(report["scan_id"]):
            raise ValueError("저장 파일명과 scan_id가 일치하지 않습니다.")
        return report

    def load(self, target_id, scan_id):
        self._id(target_id)
        path = self._path(scan_id)
        if not path.exists() and not path.is_symlink():
            raise FileNotFoundError("해당 보고서가 없습니다.")
        report = self._read(path)
        if report["target_id"] != target_id or report["scan_id"] != scan_id:
            raise ValueError("요청한 서버·실행 ID와 보고서가 일치하지 않습니다.")
        return report

    def history(self, target_id):
        """동일 서버의 보고서를 완료 시각 순으로 반환한다. 손상 파일은 숨기지 않는다."""
        self._id(target_id)
        reports = []
        for path in self.root.glob("*.json"):
            report = self._read(path)
            if report["target_id"] == target_id:
                reports.append(report)
        return sorted(reports, key=lambda report: (
            datetime.fromisoformat(report["scanned_at"].upper().replace("Z", "+00:00")),
            report["scan_id"],
        ))

    def match_results(self, target_id, before_scan_id, after_scan_id):
        """동일 서버의 두 회차를 check_id로 연결한다. 판정·조치를 수행하지 않는다."""
        if before_scan_id == after_scan_id:
            raise ValueError("서로 다른 scan_id가 필요합니다.")
        before = {r["check_id"]: r for r in self.load(target_id, before_scan_id)["results"]}
        after = {r["check_id"]: r for r in self.load(target_id, after_scan_id)["results"]}
        return {check_id: {"before": before.get(check_id), "after": after.get(check_id)}
                for check_id in sorted(before.keys() | after.keys())}
