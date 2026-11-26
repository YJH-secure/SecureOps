"""SSH-01 정책 분리와 PR #23 원본의 계획·MOCK 동작 동일성 검증."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
import inspect
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

from remediation import Approval, MockBackend, Plan, Remediator, build_plan
from remediation.handlers import SSH01MockHandler
from remediation.mock import MockFailure
from remediation.policies import REMEDIATION_POLICIES


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "b0ef73a1613ebc40fdd596edcbaf0413d32309b8"


def baseline_module(filename):
    """고정 SHA의 원본을 읽어 기준선 모듈을 만든다."""
    source = subprocess.check_output(
        ["git", "show", f"{BASE_SHA}:remediation/{filename}.py"], cwd=ROOT,
    ).decode("utf-8")
    name = f"remediation._phase1_baseline_{filename}"
    module = ModuleType(name)
    module.__package__ = "remediation"
    sys.modules[name] = module
    exec(compile(source, f"{BASE_SHA}:remediation/{filename}.py", "exec"), module.__dict__)
    return module


def report(version="1.1"):
    path = ROOT / f"tests/fixtures/sample-result-v{version}-MOCK.json"
    return json.loads(path.read_text(encoding="utf-8"))


def backend(incoming, **changes):
    options = dict(target_id=incoming["target_id"], os=incoming["os"], files={},
                   access_verified=True, snapshot_verified=True, include_verified=True)
    options.update(changes)
    return MockBackend(**options)


class PolicyHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_engine = baseline_module("engine")
        cls.old_mock = baseline_module("mock")

    def test_registry_preserves_original_ssh01_and_adds_approved_file01(self):
        self.assertEqual(set(REMEDIATION_POLICIES), {"SSH-01", "FILE-01"})
        policy = REMEDIATION_POLICIES["SSH-01"]
        self.assertEqual(policy.check_id, "SSH-01")
        self.assertEqual(policy.policy_version, "ssh-01-proposal-v1")
        self.assertEqual(policy.supported_os, {"ubuntu-24.04", "ubuntu-24.04.5"})
        self.assertEqual(policy.actions, (("ssh_dropin", "/etc/ssh/sshd_config.d/01-secureops.conf",
                                           "PermitRootLogin no\n"),))
        self.assertIs(policy.handler, SSH01MockHandler)
        self.assertFalse(hasattr(Remediator, "run_all"))

    def test_registry_and_policy_are_immutable(self):
        with self.assertRaises(TypeError):
            REMEDIATION_POLICIES["SSH-02"] = REMEDIATION_POLICIES["SSH-01"]
        with self.assertRaises(FrozenInstanceError):
            REMEDIATION_POLICIES["SSH-01"].policy_version = "changed"

    def test_plan_fields_and_hash_equal_baseline(self):
        # 2 versions × (2 supported OS × 5 statuses + unsupported OS + absent ID + unknown ID).
        for version in ("1.1", "1.2"):
            incoming = report(version)
            for os_name in ("ubuntu-24.04", "ubuntu-24.04.5"):
                for status in ("vulnerable", "pass", "error", "needs_review", "not_applicable"):
                    case = deepcopy(incoming)
                    case["os"] = os_name
                    item = next(row for row in case["results"] if row["check_id"] == "SSH-01")
                    item["status"] = status
                    if version == "1.2" and status != "vulnerable":
                        item["cvss"].update(assessment_status="not_applicable", version=None,
                                            vector=None, base_score=None, rating=None)
                    with self.subTest(version=version, os=os_name, status=status):
                        self.assert_same_plan(case, "SSH-01")
            case = deepcopy(incoming)
            case["os"] = "rocky-9.8"
            self.assert_same_plan(case, "SSH-01")
            case = deepcopy(incoming)
            next(row for row in case["results"] if row["check_id"] == "SSH-01")["check_id"] = "OTHER-MOCK"
            self.assert_same_plan(case, "SSH-01")
            self.assert_same_plan(incoming, "UNKNOWN-MOCK")

    def assert_same_plan(self, incoming, check_id):
        original = deepcopy(incoming)
        old = self.old_engine.build_plan(incoming, check_id)
        new = build_plan(incoming, check_id)
        self.assertEqual(asdict(new), asdict(old))
        for field in ("actions", "policy_version", "source_digest", "plan_id"):
            self.assertEqual(getattr(new, field), getattr(old, field))
        self.assertEqual(incoming, original)

    def test_hash_identity_with_unscored_and_zero_cvss(self):
        incoming = report("1.2")
        incoming["results"][0]["cvss"].update(
            assessment_status="not_applicable", rationale="MOCK: compliance only",
        )
        self.assert_same_plan(incoming, "SSH-01")
        incoming = report("1.2")
        incoming["results"][-1]["cvss"].update(
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            base_score=0.0, rating="none", rationale="MOCK: zero-impact calculator fixture",
        )
        self.assert_same_plan(incoming, "SSH-01")

    def test_other_checks_and_untrusted_file01_remain_excluded(self):
        incoming = report()
        engine = Remediator(allowed_targets={incoming["target_id"]}, allowed_checks={"SSH-01"})
        current = backend(incoming)
        for check_id in ("SSH-02", "ACC-01", "ACC-02", "FILE-01", "SVC-01", "FW-01", "LOG-01"):
            with self.subTest(check_id=check_id):
                plan = build_plan(incoming, check_id)
                self.assertEqual(plan.skip_reason, "file01_requires_v12" if check_id == "FILE-01"
                                 else "check_policy_not_allowed")
                result = engine.run(incoming, plan, backend=current, dry_run=False)
                self.assertEqual(result["outcome"], "skipped")
                self.assertEqual(result["backup"], "not_attempted")
        self.assertEqual(current.events, [])

    def test_public_api_signatures_equal_baseline(self):
        for current, old in ((build_plan, self.old_engine.build_plan), (Plan, self.old_engine.Plan),
                             (Approval, self.old_engine.Approval), (Remediator, self.old_engine.Remediator),
                             (Remediator.run, self.old_engine.Remediator.run),
                             (MockBackend, self.old_mock.MockBackend)):
            self.assertEqual(str(inspect.signature(current)), str(inspect.signature(old)))
        for name in ("preflight", "backup", "apply", "validate", "recheck", "request_recheck",
                     "restore", "verify_restore", "verify_service"):
            self.assertEqual(str(inspect.signature(getattr(MockBackend, name))),
                             str(inspect.signature(getattr(self.old_mock.MockBackend, name))))

    def test_preflight_failure_codes_equal_baseline(self):
        incoming = report()
        plan = build_plan(incoming, "SSH-01")
        for changes in ({"include_verified": False}, {"match_present": True},
                        {"access_verified": False}, {"snapshot_verified": False},
                        {"files": {plan.actions[0][1]: {"type": "symlink", "acl": "none"}}},
                        {"files": {plan.actions[0][1]: {"type": "regular", "acl": "none"}}}):
            with self.subTest(changes=changes):
                current = backend(incoming, **changes)
                old = self.old_mock.MockBackend(**self.options(current))
                with self.assertRaises(MockFailure) as new_error:
                    current.preflight(plan)
                with self.assertRaises(self.old_mock.MockFailure) as old_error:
                    old.preflight(plan)
                self.assertEqual(str(new_error.exception), str(old_error.exception))
                self.assertEqual(current.events, old.events)

    @staticmethod
    def options(current):
        return {key: deepcopy(getattr(current, key)) for key in (
            "target_id", "os", "files", "root_login", "fail_at", "access_verified",
            "snapshot_verified", "include_verified", "match_present")}

    def test_backend_routes_plan_to_registered_handler(self):
        incoming = report()
        plan = build_plan(incoming, "SSH-01")
        current = backend(incoming)
        for name in ("preflight", "snapshot", "apply", "validate", "recheck"):
            with self.subTest(method=name):
                with patch.object(SSH01MockHandler, name, wraps=getattr(SSH01MockHandler, name)) as delegated:
                    if name == "snapshot":
                        current.backup(plan)
                    else:
                        getattr(current, name)(plan)
                    self.assertEqual(delegated.call_count, 1)

    def test_apply_and_snapshot_restore_equal_baseline(self):
        incoming = report()
        plan = build_plan(incoming, "SSH-01")
        current = backend(incoming, files={"/mock/unrelated": {"content": "keep"}})
        old = self.old_mock.MockBackend(**self.options(current))
        snapshots = []
        for instance in (current, old):
            instance.preflight(plan)
            token = instance.backup(plan)
            snapshots.append(deepcopy(instance._backups[token]))
            instance.apply(plan)
            instance.validate(plan)
            self.assertEqual(instance.files[plan.actions[0][1]]["content"], "PermitRootLogin no\n")
            instance.restore(token)
            instance.verify_restore(token)
            instance.verify_service()
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(current.files, old.files)
        self.assertEqual(current.root_login, old.root_login)
        self.assertEqual(current.service_running, old.service_running)
        self.assertEqual(current.events, old.events)

    def test_partial_apply_failure_still_requires_and_allows_restore(self):
        incoming = report()
        plan = build_plan(incoming, "SSH-01")
        current = backend(incoming, fail_at={"apply"})
        token = current.backup(plan)
        with self.assertRaisesRegex(MockFailure, "mock_apply_failure"):
            current.apply(plan)
        self.assertEqual(current.root_login, "no")
        self.assertFalse(current.service_running)
        current.restore(token)
        current.verify_restore(token)
        current.verify_service()
        self.assertEqual(current.files, {})
        self.assertEqual(current.root_login, "yes")

    def test_handler_validation_detects_corrupted_state(self):
        incoming = report()
        plan = build_plan(incoming, "SSH-01")
        current = backend(incoming)
        current.apply(plan)
        current.files[plan.actions[0][1]]["content"] = "unexpected"
        with self.assertRaisesRegex(MockFailure, "mock_ssh_setting_invalid"):
            SSH01MockHandler.validate(current, plan)

    def test_recheck_uses_original_effective_state_and_preserves_cvss(self):
        incoming = report()
        plan = build_plan(incoming, "SSH-01")
        for root_login in ("yes", "no"):
            for version in ("1.1", "1.2"):
                with self.subTest(root_login=root_login, version=version):
                    current = backend(incoming, root_login=root_login)
                    old = self.old_mock.MockBackend(**self.options(current))
                    self.assertEqual(current.recheck(plan, schema_version=version),
                                     old.recheck(plan, schema_version=version))
                    self.assertEqual(SSH01MockHandler.recheck(current, plan, schema_version=version)["status"],
                                     "pass" if root_login == "no" else "vulnerable")


if __name__ == "__main__":
    unittest.main()
