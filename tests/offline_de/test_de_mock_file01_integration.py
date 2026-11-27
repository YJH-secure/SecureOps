"""New Q09 integration tests; real frozen E sender, D callback and C Bridge.

Fault injection is synthetic. No real chmod/chown, process or network operation.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from core import file01_mock_callback as callback
from core.main import DiagnosisAggregator
from core.storage import ReportStore
from file01_pilot.c_mock_bridge import diagnose
from remediation import Approval, MockBackend, Remediator, build_plan
from remediation.file01 import PATH, initial_snapshot
from remediation.history import ExecutionHistoryStore
from remediation.recheck import MockRecheckAdapter
from orchestration.de_mock import execute_mock_remediation, persist_mock_execution_history


class Q09File01Tests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(prefix='secureops-q09-')
        self.addCleanup(directory.cleanup)
        self.store = ReportStore(Path(directory.name) / 'reports')
        self.history = ExecutionHistoryStore(Path(directory.name) / 'executions')
        self.before = DiagnosisAggregator.from_results(
            [], [diagnose(initial_snapshot())['c_result']], target_id='file01-MOCK',
            os='ubuntu-24.04', schema_version='1.2').get_report()
        self.before_path = self.store.save(self.before)
        self.before_bytes = self.before_path.read_bytes()
        self.plan = build_plan(self.before, 'FILE-01')
        self.approval = Approval('q09-approval-MOCK', 'admin-MOCK', self.plan.target_id,
            self.plan.scan_id, self.plan.plan_id, '2099-01-01T00:00:00Z', True)
        self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={'FILE-01'},
            verify_approval=lambda value: value == self.approval)
        self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os,
            files={PATH: initial_snapshot()}, access_verified=True, snapshot_verified=True)
        self.calls = []
        self.results = []
        self.mutate_state = None
        self.mutate_report = None
        self.adapter = MockRecheckAdapter(self.capture, self.store)

    def tearDown(self):
        self.assertEqual(self.before_path.read_bytes(), self.before_bytes)
        self.assertEqual(self.store.load(self.plan.target_id, self.plan.scan_id), self.before)
        destination = os.environ.get('SECUREOPS_DE_OBSERVATIONS')
        if destination:
            path = Path(destination)
            path.mkdir(parents=True, exist_ok=True)
            (path / (self._testMethodName + '.json')).write_text(json.dumps(
                dict(before=self.before, callback_calls=self.calls, results=self.results),
                ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

    def capture(self, request, state):
        self.calls.append(dict(request=deepcopy(request), state=deepcopy(state)))
        if self.mutate_state:
            self.mutate_state(request, state)
        # Callback itself must never construct, save, or load a ReportStore.
        with patch.object(ReportStore, '__init__', side_effect=AssertionError('callback cannot create store')), \
             patch.object(self.store, 'save', side_effect=AssertionError('callback cannot save')), \
             patch.object(self.store, 'load', side_effect=AssertionError('callback cannot load')):
            report = callback.diagnose_file01_mock(request, state)
        if self.mutate_report:
            self.mutate_report(report)
        self.calls[-1]['report'] = deepcopy(report)
        return report

    def execute(self):
        with patch.object(self.engine, 'run', wraps=self.engine.run) as run:
            result = execute_mock_remediation(report_store=self.store, history_store=self.history,
                remediator=self.engine, target_id=self.plan.target_id, before_scan_id=self.plan.scan_id,
                check_id='FILE-01', approval=self.approval, dry_run=False,
                backend=self.backend, recheck_adapter=self.adapter)
        run.assert_called_once()
        self.assertIs(run.call_args.kwargs['post_rollback_recheck'], False)
        self.results.append(deepcopy(result))
        return result

    def phases(self):
        return [call['state']['file01_context']['phase'] for call in self.calls]

    def test_Q01_normal_restore_phase_counts_roundtrip_and_immutable_before(self):
        with patch.object(self.store, 'save', wraps=self.store.save) as save, \
             patch.object(self.store, 'load', wraps=self.store.load) as load, \
             patch.object(self.history, 'save', wraps=self.history.save) as hs, \
             patch.object(self.history, 'load', wraps=self.history.load) as hl:
            out = self.execute()
        self.assertTrue(out['integration_success'])
        self.assertEqual(out['outcome'], 'success')
        self.assertEqual(self.phases(), ['after', 'post_restore'])
        self.assertEqual((save.call_count, load.call_count, hs.call_count, hl.call_count), (2, 3, 1, 1))
        ids = {self.plan.scan_id}
        for call, attempt, mode in zip(self.calls, out['recheck_attempts'], ('0644', '0666')):
            state, report = call['state'], call['report']
            context = state['file01_context']
            self.assertEqual(context['execution_id'], out['execution_id'])
            self.assertEqual(context['original_snapshot'], initial_snapshot())
            self.assertEqual(context['expected_identity'], initial_snapshot())
            self.assertEqual(state['files'][PATH]['mode'], mode)
            self.assertNotIn(report['scan_id'], ids)
            ids.add(report['scan_id'])
            self.assertEqual(attempt['scan_id'], report['scan_id'])
            self.assertTrue(attempt['report_verified'])
            self.assertEqual(report['results'], [diagnose(state['files'][PATH])['c_result']])
            self.assertEqual(self.store.load(self.plan.target_id, report['scan_id']), report)
        self.assertEqual(self.calls[0]['report']['results'][0]['status'], 'needs_review')
        self.assertEqual(out['e_result']['normal_restore_scan_id'], self.calls[1]['report']['scan_id'])
        self.assertEqual(self.history.load(out['execution_id']), json.loads(json.dumps(out['e_result'])))

    def test_Q02_failed_apply_verified_rollback_rechecks_despite_generic_false(self):
        self.backend.fail_at = {'apply'}
        with patch.object(self.store, 'save', wraps=self.store.save) as save, \
             patch.object(self.store, 'load', wraps=self.store.load) as load:
            out = self.execute()
        self.assertEqual(self.phases(), ['post_rollback'])
        self.assertEqual((save.call_count, load.call_count), (1, 2))
        self.assertEqual(out['outcome'], 'failed')
        self.assertFalse(out['integration_success'])
        self.assertEqual(out['e_result']['rollback'], 'verified')
        self.assertTrue(out['recheck_attempts'][0]['report_verified'])
        self.assertEqual(out['e_result']['post_rollback_scan_id'], self.calls[0]['report']['scan_id'])
        self.assertTrue(out['history_verified'])

    def test_Q03_unverified_rollback_has_no_callback_or_success(self):
        self.backend.fail_at = {'apply', 'restore'}
        out = self.execute()
        self.assertEqual(self.calls, [])
        self.assertFalse(out['integration_success'])
        self.assertEqual(out['outcome'], 'failed')
        self.assertIsNone(out['e_result']['post_rollback_scan_id'])

    def test_Q04_wrong_after_mode_blocked_then_valid_rollback_rechecked(self):
        self.mutate_state = lambda request, state: state['files'][PATH].update(mode='0666')
        with patch.object(callback, 'diagnose', wraps=diagnose) as bridge, \
             patch.object(self.store, 'save', wraps=self.store.save) as save:
            out = self.execute()
        # after=0666 is invalid; post_rollback=0666 is independently valid.
        self.assertEqual(self.phases(), ['after', 'post_rollback'])
        self.assertEqual(bridge.call_count, 1)
        self.assertEqual(save.call_count, 1)
        self.assertEqual(out['recheck_attempts'][0]['failure_stage'], 'diagnose')
        self.assertTrue(out['recheck_attempts'][1]['report_verified'])
        self.assertFalse(out['integration_success'])
        self.assertEqual(out['outcome'], 'failed')

    def test_Q05_snapshot_identity_digest_plan_phase_binding_rejected(self):
        mutations = (
            lambda r, s: s['files'][PATH].update(inode=99999),
            lambda r, s: s['file01_context'].update(snapshot_digest='0'*64),
            lambda r, s: s['file01_context'].update(approved_plan_id='wrong-plan'),
            lambda r, s: s['file01_context'].update(phase='unknown'),
        )
        # Independent complete E executions; each injected callback input is
        # synthetic corruption, not evidence of a real sender failure.
        with patch.object(callback, 'diagnose', wraps=diagnose) as bridge, \
             patch.object(self.store, 'save', wraps=self.store.save) as save:
            for mutation in mutations:
                with self.subTest(mutation=mutations.index(mutation)):
                    self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os,
                        files={PATH: initial_snapshot()}, access_verified=True, snapshot_verified=True)
                    # Each independent execution gets a new in-memory E approval
                    # verifier; do not accidentally test approval reuse instead.
                    self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={'FILE-01'},
                        verify_approval=lambda value: value == self.approval)
                    self.mutate_state = mutation
                    out = self.execute()
                    self.assertFalse(out['integration_success'])
                    self.assertEqual(out['outcome'], 'failed')
            self.assertEqual((bridge.call_count, save.call_count), (0, 0))

    def test_Q06_reused_before_scan_id_rejected_before_save(self):
        self.mutate_report = lambda report: report.update(scan_id=self.plan.scan_id)
        with patch.object(self.store, 'save', wraps=self.store.save) as save:
            out = self.execute()
        self.assertEqual(save.call_count, 0)
        self.assertFalse(out['integration_success'])
        self.assertTrue(any(a['failure_stage'] == 'validate' for a in out['recheck_attempts']))

    def test_Q07_save_failure_not_success_no_retry(self):
        with patch.object(self.store, 'save', side_effect=PermissionError('synthetic')) as save:
            out = self.execute()
        self.assertFalse(out['integration_success'])
        self.assertEqual(save.call_count, len(out['recheck_attempts']))
        self.assertTrue(all(a['save_status'] == 'failed' for a in out['recheck_attempts']))
        self.assertTrue(all(not a['report_verified'] for a in out['recheck_attempts']))

    def test_Q08_load_failure_preserves_saved_id_and_original(self):
        original = self.store.load
        def fail_after(target, scan):
            if scan == self.plan.scan_id:
                return original(target, scan)
            raise PermissionError('synthetic')
        with patch.object(self.store, 'load', side_effect=fail_after):
            out = self.execute()
        self.assertFalse(out['integration_success'])
        for attempt in out['recheck_attempts']:
            self.assertEqual(attempt['save_status'], 'success')
            self.assertEqual(attempt['load_status'], 'failed')
            self.assertFalse(attempt['report_verified'])
            self.assertIsNotNone(attempt['scan_id'])
            self.assertEqual(original(self.plan.target_id, attempt['scan_id'])['scan_id'], attempt['scan_id'])

    def test_Q09_history_failure_never_replays_e_or_changes_outcome(self):
        with patch.object(self.history, 'save', side_effect=OSError('synthetic')) as save:
            out = self.execute()
        save.assert_called_once()
        self.assertEqual(out['outcome'], 'success')
        self.assertFalse(out['integration_success'])
        self.assertEqual(out['error_stage'], 'history_save')
        self.assertEqual(self.phases(), ['after', 'post_restore'])

    def test_Q10_duplicate_history_id_preserves_record_without_reexecution(self):
        first = self.execute()
        with patch.object(self.engine, 'run', wraps=self.engine.run) as run:
            again = persist_mock_execution_history(first['e_result'], history_store=self.history)
        run.assert_not_called()
        self.assertEqual(again['error_stage'], 'history_conflict')
        self.assertFalse(again['integration_success'])
        self.assertEqual(self.phases(), ['after', 'post_restore'])
        self.assertEqual(self.history.load(first['execution_id']), json.loads(json.dumps(first['e_result'])))

    def test_Q11_duplicate_phase_scan_id_rejected_without_second_save(self):
        previous = []
        def repeated(report):
            if previous:
                report['scan_id'] = previous[0]
            else:
                previous.append(report['scan_id'])
        self.mutate_report = repeated
        with patch.object(self.store, 'save', wraps=self.store.save) as save:
            out = self.execute()
        self.assertEqual(save.call_count, 1)
        self.assertEqual(self.phases(), ['after', 'post_restore'])
        self.assertTrue(out['recheck_attempts'][0]['report_verified'])
        self.assertEqual(out['recheck_attempts'][1]['failure_stage'], 'validate')
        self.assertFalse(out['integration_success'])
        self.assertEqual(out['outcome'], 'failed')

    def test_Q12_normal_restore_failure_has_no_successful_final_recheck(self):
        self.backend.fail_at = {'normal_restore'}
        out = self.execute()
        self.assertEqual(self.phases(), ['after'])
        self.assertTrue(out['recheck_attempts'][0]['report_verified'])
        self.assertEqual(out['outcome'], 'failed')
        self.assertFalse(out['integration_success'])
        self.assertIsNone(out['e_result']['normal_restore_scan_id'])

    def test_Q13_target_and_cvss_corruption_fail_validation_before_save(self):
        mutations = (
            lambda report: report.update(target_id='other-MOCK'),
            lambda report: report['results'][0]['cvss'].update(base_score=0.0),
        )
        with patch.object(self.store, 'save', wraps=self.store.save) as save:
            for index, mutation in enumerate(mutations):
                with self.subTest(index=index):
                    self.backend = MockBackend(target_id=self.plan.target_id, os=self.plan.os,
                        files={PATH: initial_snapshot()}, access_verified=True, snapshot_verified=True)
                    self.engine = Remediator(allowed_targets={self.plan.target_id}, allowed_checks={'FILE-01'},
                        verify_approval=lambda value: value == self.approval)
                    self.mutate_report = mutation
                    out = self.execute()
                    self.assertEqual(out['outcome'], 'failed')
                    self.assertFalse(out['integration_success'])
            self.assertEqual(save.call_count, 0)
