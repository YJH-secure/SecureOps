"""Result contract and export minimization; no live machine or D-module calls."""
import copy
import json
import unittest
from unittest.mock import Mock, patch

from checks.system.common import make_result, recommendation_for_status, STATUSES
from checks.system.file_check import run, run_from_policy
from checks.system.tests.fixtures import singlefile_policy
from checks.system.tests.test_diagnosis import observation


class ResultContractTests(unittest.TestCase):
    def test_minimum_five_fields_without_details(self):
        result = make_result('FILE-01','needs_review','high','(MOCK) pending','Review approval')
        self.assertEqual(set(result), {'check_id','status','severity','evidence','recommendation'})

    def test_summary_and_recommendation_are_required_nonempty_strings(self):
        for value in ('', '  ', None, {}, []):
            for field in ('evidence','recommendation'):
                args = dict(check_id='FILE-01',status='error',severity='high',
                            evidence='(MOCK) failure',recommendation='Review')
                args[field] = value
                with self.assertRaises(ValueError):
                    make_result(**args)

    def test_details_must_be_finite_json_object(self):
        for details in ([], 'text', {'number':float('nan')}, {'number':float('inf')}):
            with self.assertRaises(ValueError):
                make_result('FILE-01','error','high','Failure','Review',details)

    def test_all_statuses_have_followup_without_status_change(self):
        for status in STATUSES:
            result = make_result('FILE-01',status,'high','(MOCK) evidence',
                                 recommendation_for_status(status),{})
            self.assertEqual(result['status'],status)
            self.assertTrue(result['recommendation'].strip())

    def test_detailed_uid_mode_acl_are_retained_without_input_mutation(self):
        actual = observation()
        original = copy.deepcopy(actual)
        result = run(singlefile_policy(),collector=lambda path:actual,environment={'id':'MOCK'})
        self.assertEqual(actual,original)
        exported=result['details']['files'][0]['actual']
        self.assertEqual(exported['uid'],actual['uid'])
        self.assertEqual(exported['mode'],actual['mode'])
        self.assertEqual(exported['acl'],actual['acl'])
        self.assertNotIn('owner',exported)
        self.assertNotIn('group',exported)

    def test_structured_secret_keys_and_person_names_are_minimized(self):
        details={'token':'fixture-secret','nested':{'password':'fixture-password'},
                 'owner':'fixture-person','proposed_by':'fixture-author','uid':123}
        result=make_result('FILE-01','error','high','(MOCK) failure','Review',details)
        text=json.dumps(result)
        for marker in ('fixture-secret','fixture-password','fixture-person','fixture-author'):
            self.assertNotIn(marker,text)
        self.assertEqual(result['details']['uid'],123)

    def test_exception_string_redaction(self):
        values=['token=fixture-secret', 'Authorization: Bearer fixture-secret',
                '{"password": "fixture-secret"}', "{'token': 'fixture-secret'}",
                '-----BEGIN PRIVATE KEY-----\nfixture-secret\n-----END PRIVATE KEY-----']
        for value in values:
            result=make_result('FILE-01','error','high','(MOCK) failure','Review',{'detail':value})
            self.assertNotIn('fixture-secret',json.dumps(result))

    def test_partial_error_is_visible_in_summary_and_details(self):
        actual=observation(uid=123)
        actual['acl']={'state':'error','detail':'(MOCK) ACL denied'}
        result=run(singlefile_policy(),collector=lambda path:actual,environment={'id':'MOCK'})
        self.assertEqual(result['status'],'vulnerable')
        self.assertIn('오류 1건',result['evidence'])
        self.assertIn('error',[c['status'] for c in result['details']['files'][0]['checks']])

    def test_metadata_failure_still_produces_valid_result_fields(self):
        result=run(singlefile_policy(),collector=Mock(side_effect=PermissionError('(MOCK) denied')),
                   environment={'id':'MOCK'})
        self.assertEqual(result['status'],'error')
        self.assertIsInstance(result['evidence'],str)
        self.assertIsInstance(result['details'],dict)
        self.assertTrue(result['recommendation'])

    @patch('checks.system.file_check.environment_info',return_value={'id':'ubuntu','version_id':'24.04',
                                                                   'named_groups':{'shadow':42}})
    @patch('checks.system.file_check.collect_file_info')
    def test_policy_metadata_under_details_not_evidence(self,collector,env):
        collector.side_effect=lambda path:dict(observation(),path=path)
        result=run_from_policy()
        self.assertIn('policy_version',result['details'])
        self.assertNotIn('proposed_by',result['details']['policy_metadata'])
        self.assertNotIn('schema_version',result)  # D owns the scan envelope.


if __name__ == '__main__':
    unittest.main()
