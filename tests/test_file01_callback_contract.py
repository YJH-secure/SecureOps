"""E callback 내용 바인딩. D 운영 callback 통합 테스트가 아니다."""
from copy import deepcopy
import unittest

from remediation.file01 import PATH, validate_callback_context
from remediation.engine import build_plan
import test_file01_integration as fixtures


class File01CallbackContractTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.File01IntegrationTests("test_F01_normal_action_and_normal_restoration")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.result = self.case.execute()
        self.request, self.state = deepcopy(self.case.calls[0])

    def test_phase_modes_and_immutable_original(self):
        for phase, mode in (("before", "0666"), ("after", "0644"),
                            ("post_restore", "0666"), ("post_rollback", "0666")):
            state = deepcopy(self.state)
            state["file01_context"]["phase"] = phase
            state["files"][PATH]["mode"] = mode
            validate_callback_context(self.request, state)
            self.assertEqual(state["file01_context"]["original_snapshot"]["mode"], "0666")
            state["files"][PATH]["mode"] = "0600"
            with self.assertRaises(ValueError): validate_callback_context(self.request, state)
        self.assertEqual(self.case.calls[1][1]["file01_context"]["phase"], "post_restore")

    def test_subcheck_and_goal_rejected(self):
        for key, value in (("permission_subcheck_id", "owner"), ("target_mode", "0777")):
            state = deepcopy(self.state)
            state["file01_context"][key] = value
            with self.assertRaises(ValueError): validate_callback_context(self.request, state)

    def test_snapshot_digest_recomputed_against_trusted_fixture(self):
        for change in ("digest", "original", "expected"):
            state = deepcopy(self.state)
            context = state["file01_context"]
            if change == "digest": context["snapshot_digest"] = "0" * 64
            elif change == "original": context["original_snapshot"]["mode"] = "0644"
            else: context["expected_identity"]["inode"] = 999
            with self.assertRaises(ValueError): validate_callback_context(self.request, state)

    def test_before_report_digest_and_plan_binding(self):
        for key in ("before_report_digest", "before_scan_id", "plan_id"):
            state = deepcopy(self.state)
            state["file01_context"][key] = "other"
            with self.assertRaises(ValueError): validate_callback_context(self.request, state)
        state = deepcopy(self.state)
        state["file01_context"]["before_report"]["results"][0]["evidence"] = "modified"
        with self.assertRaises(ValueError): validate_callback_context(self.request, state)

    def test_boolean_does_not_replace_approval_binding(self):
        for key, value in (("approval_id", "other"), ("plan_id", "other"),
                           ("approved", 1), ("verification", "self_asserted"),
                           ("expires_at", "2000-01-01T00:00:00Z")):
            state = deepcopy(self.state)
            state["file01_context"]["approval_evidence"][key] = value
            with self.assertRaises(ValueError): validate_callback_context(self.request, state)

    def test_request_target_and_before_are_bound(self):
        for key in ("target_id", "before_scan_id", "check_id", "schema_version"):
            request = dict(self.request, **{key: "other"})
            with self.assertRaises(ValueError): validate_callback_context(request, self.state)

    def test_internal_context_tamper_stops_dispatch(self):
        backend = self.case.backend
        backend._file01_context["snapshot_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            backend.request_recheck(self.case.plan, lambda *_: self.fail("must not dispatch"))

    def test_plan_is_unchanged_by_callback_context(self):
        self.assertEqual(self.case.plan, build_plan(self.case.before, "FILE-01"))
        self.assertEqual(self.case.plan.source_digest,
                         self.state["file01_context"]["before_report_digest"])
