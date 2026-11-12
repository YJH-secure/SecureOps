"""Verify runner control flow with mocked stages; no Linux or system files touched."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from checks.system import verify_all
from checks.system.file_check import run
from checks.system.tests.fixtures import singlefile_policy
from checks.system.tests.test_diagnosis import observation


class VerifyAllTests(unittest.TestCase):
    def stages(self,actual):
        return dict(_preflight=Mock(),_run_unit_tests=Mock(return_value={'tests_run':1,'exit_code':0}),
                    _run_diagnosis=Mock(return_value=actual),
                    _run_fixtures=Mock(return_value={'exit_code':0,'cases':13,'matched':13}),
                    _validate_outputs=Mock(return_value={'validated_result_items':14,'schema_version':'1.1'}))

    def execute(self,stages):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'new-run'
            with patch.multiple(verify_all,**stages),patch('sys.stdout'):
                code=verify_all.execute(output)
            report=json.loads((output/'verification-summary.json').read_text(encoding='utf-8'))
            return code,report

    def pending_result(self):
        data=observation();data['file_type']='symlink'
        return run(singlefile_policy(),collector=lambda path:data,environment={'id':'MOCK'})

    def test_missing_prerequisite_does_not_claim_tests_or_touch_actual_files(self):
        stages=self.stages(self.pending_result())
        stages['_preflight'].side_effect=RuntimeError('(MOCK) dependency missing')
        code,report=self.execute(stages)
        self.assertEqual(code,1)
        stages['_run_unit_tests'].assert_not_called()
        stages['_run_diagnosis'].assert_not_called()
        self.assertEqual(report['stages']['json-schema']['status'],'not_run')

    def test_unit_failure_stops_real_file_stages(self):
        stages=self.stages(self.pending_result())
        stages['_run_unit_tests'].side_effect=RuntimeError('(MOCK) regression failed')
        code,report=self.execute(stages)
        self.assertEqual(code,1)
        stages['_run_diagnosis'].assert_not_called()
        stages['_run_fixtures'].assert_not_called()
        self.assertFalse(report['verification_success'])

    def test_successful_verification_preserves_needs_review_status(self):
        code,report=self.execute(self.stages(self.pending_result()))
        self.assertEqual(code,0)
        self.assertTrue(report['verification_success'])
        self.assertEqual(report['operational_status'],'needs_review')
        self.assertIn('does not mean',report['notice'])
        self.assertEqual(report['stages']['temporary-acl-links']['matched'],13)

    def test_live_collection_error_is_not_hidden_by_passing_schema(self):
        actual=run(singlefile_policy(),collector=Mock(side_effect=PermissionError('(MOCK) denied')),
                   environment={'id':'MOCK'})
        stages=self.stages(actual)
        code,report=self.execute(stages)
        self.assertEqual(code,1)
        self.assertEqual(report['operational_status'],'error')
        self.assertEqual(report['stages']['actual-diagnosis']['status'],'fail')
        self.assertEqual(report['stages']['json-schema']['status'],'pass')
        stages['_run_fixtures'].assert_called_once()

    @patch('checks.system.verify_all.subprocess.run',return_value=SimpleNamespace(
        returncode=0,stdout='',stderr='Ran 0 tests in 0.001s\nOK'))
    def test_empty_unit_suite_cannot_pass(self,command):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RuntimeError):
                verify_all._run_unit_tests(Path(folder))


if __name__=='__main__':
    unittest.main()
