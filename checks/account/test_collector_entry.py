"""
수집기 출력 입구(judge_collector_output) Mock 테스트

실제 서버 명령을 실행하지 않습니다.
가짜 대상 서버에서 수집기(b_collector.main)를 돌린 실제 출력 bytes를 입구 함수에 넣어 확인합니다.
  1) 정상 : 결과 3개 = 점검별 judge_payload 직접 호출 결과
  2) 신뢰성 오류(decode·structure·context·os) : CollectorTrustError, 결과 없음
  3) 호출 실수 : ValueError
  4) 신뢰된 상태의 개별 항목 실패 : STOP 아님, status=error 결과 유지

실행: python -m unittest test_collector_entry -v
"""

import copy
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import acc_password_check as acc01
import b_collector as collector
import central_adapter as adapter
from collector_entry import CHECK_IDS, CollectorTrustError, judge_collector_output
from test_account_checks import ERROR, ROCKY_SYSTEM_AUTH_FAILLOCK, rocky_fs, ubuntu_fs
from test_b_collector import CONTEXT, target

TRUSTED = {"host": CONTEXT["host"], "addr": CONTEXT["addr"], "os_id": "ubuntu", "os_version": "24.04"}


# 가짜 대상 서버에서 수집기를 실제로 돌려 stdout bytes를 얻습니다.
def collector_stdout(**target_kw):
    out = io.StringIO()
    with target(**target_kw):
        assert collector.main([], out=out) == 0
    return out.getvalue().encode("utf-8")


# 출력 JSON을 고친 뒤 다시 1줄 bytes로
def modified(raw, change):
    document = json.loads(raw)
    change(document)
    return (json.dumps(document, ensure_ascii=False) + "\n").encode("utf-8")


# 실제 명령이 실행되면 실패하도록 막고 호출
def judge(raw, trusted=None, **kw):
    with mock.patch("subprocess.run", side_effect=AssertionError("no real command")):
        return judge_collector_output(raw, trusted or TRUSTED, **kw)


class EntryBase(unittest.TestCase):
    raw = None

    @classmethod
    def setUpClass(cls):
        cls.raw = collector_stdout()

    def assertStop(self, raw, stage, reason, trusted=None):
        with self.assertRaises(CollectorTrustError) as caught:
            judge(raw, trusted)
        self.assertEqual((caught.exception.stage, caught.exception.reason), (stage, reason))
        self.assertIn(caught.exception.stage, CollectorTrustError.STAGES)


# ==================================================
# 1. 정상
# ==================================================
class NormalTest(EntryBase):
    def test_three_results_equal_direct_judge(self):
        results = judge(self.raw)
        self.assertEqual(list(results), list(CHECK_IDS))
        document = json.loads(self.raw)
        ssh_context = {"host": TRUSTED["host"], "addr": TRUSTED["addr"]}
        for check_id in CHECK_IDS:
            expected = adapter.judge_payload(check_id, document["payloads"][check_id], ssh_context)
            self.assertEqual(results[check_id], expected)
            self.assertIn("cvss", results[check_id])                     # v1.2 기본

    def test_result_version_1_1(self):
        results = judge(self.raw, result_version="1.1")
        self.assertTrue(all("severity" in r for r in results.values()))

    def test_policy_paths(self):
        with open(acc01.POLICY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        data["policies"][0]["criteria"]["interactive_accounts"] = ["user1"]
        handle, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            json.dump(data, f)
        try:
            raw = collector_stdout()                                     # 실제 정책이라 chage 없음
            results = judge(raw, policy_paths={"ACC-01": path})
            self.assertEqual(results["ACC-01"]["details"]["accounts"], ["user1"])
        finally:
            os.remove(path)

    def test_rocky_target(self):
        raw = collector_stdout(acc_fs=rocky_fs(ROCKY_SYSTEM_AUTH_FAILLOCK))
        results = judge(raw, dict(TRUSTED, os_id="rocky", os_version="9.6"))
        self.assertEqual(list(results), list(CHECK_IDS))


# ==================================================
# 2. 신뢰성 오류 (STOP)
# ==================================================
class DecodeTest(EntryBase):
    def test_decode_errors(self):
        cases = [
            (b"\xff\xfe" + self.raw, "stdout_not_utf8"),
            (b"", "not_single_line_json"),
            (b"\n", "not_single_line_json"),
            (self.raw + self.raw, "not_single_line_json"),                # 2줄
            (json.dumps(json.loads(self.raw), indent=2).encode(), "not_single_line_json"),
            (b"{not json}\n", "invalid_json"),
            (self.raw[:-20] + b"\n", "invalid_json"),                     # 잘린 출력
        ]
        for raw, reason in cases:
            with self.subTest(reason=reason, size=len(raw)):
                self.assertStop(raw, "decode", reason)


class StructureTest(EntryBase):
    def test_duplicate_keys(self):
        text = self.raw.decode("utf-8").rstrip("\n")
        top = text[:-1] + ', "payloads": {}}\n'                            # 최상위 payloads 두 번
        nested = text.replace('"host":', '"host": "x", "host":', 1) + "\n"  # context_used.host 두 번
        for raw in (top.encode(), nested.encode()):
            with self.subTest(raw=raw[:40]):
                self.assertStop(raw, "structure", "duplicate_key")

    def test_structure_errors(self):
        cases = {
            "top_level_fields": [lambda d: d.pop("payloads"), lambda d: d.update(_note="x"),
                                 lambda d: d.pop("context_used")],
            "collector_name": [lambda d: d["collector"].update(name="other"),
                               lambda d: d.update(collector="secureops-b-read")],
            "context_used_fields": [lambda d: d["context_used"].pop("addr"),
                                    lambda d: d["context_used"].update(user="root")],
            "payload_checks": [lambda d: d["payloads"].pop("ACC-02"),
                               lambda d: d["payloads"].update({"SSH-01": {}})],
            "payload_type": [lambda d: d["payloads"].update({"ACC-01": []})],
        }
        for reason, changes in cases.items():
            for index, change in enumerate(changes):
                with self.subTest(reason=reason, case=index):
                    self.assertStop(modified(self.raw, change), "structure", reason)

    def test_not_object(self):
        self.assertStop(b'["a"]\n', "structure", "top_level_fields")


class ContextTest(EntryBase):
    def test_context_mismatch(self):
        cases = [
            (lambda d: d["context_used"].update(host="192.0.2.11"), "host_mismatch"),
            (lambda d: d["context_used"].update(addr="192.0.2.11"), "addr_mismatch"),
        ]
        for change, reason in cases:
            with self.subTest(reason=reason):
                self.assertStop(modified(self.raw, change), "context", reason)

    def test_trusted_context_differs(self):
        self.assertStop(self.raw, "context", "host_mismatch", dict(TRUSTED, host="10.40.0.10"))


class OsTest(EntryBase):
    def test_os_mismatch(self):
        self.assertStop(self.raw, "os", "os_id_mismatch", dict(TRUSTED, os_id="rocky"))
        self.assertStop(self.raw, "os", "os_version_mismatch", dict(TRUSTED, os_version="22.04"))

    def test_os_release_unreadable(self):
        for check_id in ("ACC-01", "ACC-02"):
            for record in ({"state": "error"}, {"state": "missing"}, None,
                           {"state": "ok", "text": "ID=ubuntu\n", "exit_code": 1}):
                with self.subTest(check_id=check_id, record=record):
                    def change(d, cid=check_id, rec=record):
                        d["payloads"][cid]["os_release"] = rec
                    self.assertStop(modified(self.raw, change), "os", "os_release_unreadable")

    def test_acc_os_release_disagree(self):
        def change(d):
            d["payloads"]["ACC-02"]["os_release"] = {"state": "ok", "text": 'ID=ubuntu\nVERSION_ID="22.04"\n'}
        self.assertStop(modified(self.raw, change), "os", "os_version_mismatch")

    def test_target_os_unreadable_on_server(self):
        raw = collector_stdout(acc_fs=ubuntu_fs(**{"/etc/os-release": ERROR}))
        self.assertStop(raw, "os", "os_release_unreadable")


# ==================================================
# 3. 호출 실수 (ValueError)
# ==================================================
class CallerMistakeTest(EntryBase):
    def test_bad_arguments(self):
        bad_calls = [
            (self.raw.decode("utf-8"), TRUSTED, {}),                      # bytes 아님
            (self.raw, None, {}),
            (self.raw, {"host": "h", "addr": "a", "os_id": "ubuntu"}, {}),            # 키 누락
            (self.raw, dict(TRUSTED, extra="x"), {}),                                 # 키 추가
            (self.raw, dict(TRUSTED, host="a,b"), {}),
            (self.raw, dict(TRUSTED, os_version=""), {}),
            (self.raw, dict(TRUSTED, os_version=24.04), {}),
            (self.raw, TRUSTED, {"result_version": "2.0"}),
            (self.raw, TRUSTED, {"policy_paths": {"SSH-01": "x.json"}}),
            (self.raw, TRUSTED, {"policy_paths": {"ACC-01": ""}}),
            (self.raw, TRUSTED, {"policy_paths": ["x.json"]}),
        ]
        for index, (raw, trusted, kw) in enumerate(bad_calls):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    judge_collector_output(raw, trusted, **kw)

    def test_options_are_keyword_only(self):
        with self.assertRaises(TypeError):
            judge_collector_output(self.raw, TRUSTED, None, "1.1")

    def test_trust_error_is_not_value_error(self):
        # D가 두 종류를 구분해 처리할 수 있어야 함
        self.assertFalse(issubclass(CollectorTrustError, ValueError))


# ==================================================
# 4. 신뢰된 상태의 개별 항목 실패 -> STOP 아님
# ==================================================
class ItemFailureTest(EntryBase):
    def test_item_failures_stay_as_results(self):
        def change(d):
            user = list(d["payloads"]["SSH-02"]["sshd_T_C"])[0]
            d["payloads"]["SSH-02"]["sshd_T_C"][user] = {"state": "timeout"}
            d["payloads"]["ACC-02"]["files"]["/etc/pam.d/common-auth"] = {"state": "error"}
        results = judge(modified(self.raw, change))
        self.assertEqual(results["SSH-02"]["status"], "error")
        self.assertEqual(results["ACC-02"]["status"], "error")
        self.assertIn("common-auth", results["ACC-02"]["evidence"])         # 실패 근거 보존
        self.assertIsNone(results["ACC-02"]["cvss"]["base_score"])           # CVSS null 보존

    def test_input_is_not_modified(self):
        raw = bytes(self.raw)
        before = copy.deepcopy(raw)
        judge(raw)
        self.assertEqual(raw, before)


if __name__ == "__main__":
    unittest.main()
