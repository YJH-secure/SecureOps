"""Regression coverage for missing/invalid acquisition fields, MOCK data only."""
import copy
import unittest

from checks.system.common import load_policy
from checks.system.file_check import DEFAULT_POLICY, run, _acl_check
from checks.system.policy_rules import group_check
from checks.system.tests.fixtures import singlefile_policy
from checks.system.tests.test_diagnosis import observation


def approved_acl_policy():
    policy=singlefile_policy()
    policy['criteria']['files'][0]['acl_policy']=dict(approval_status='approved',
        users=[dict(id=0,max_bits=6),dict(id=123,max_bits=4)],
        groups=[dict(id=0,max_bits=4)],other_max_bits=4)
    return policy


def extended():
    data=observation()
    data['acl']['raw'] += 'user:123:r--\nmask::r--\n'
    return data


def diagnose(policy,data):
    return run(policy,collector=lambda path:copy.deepcopy(data),environment={'id':'MOCK'})


class MissingMetadataTests(unittest.TestCase):
    def test_missing_uid_in_approved_acl_returns_error(self):
        data=extended();del data['uid']
        result=diagnose(approved_acl_policy(),data)
        self.assertEqual(result['status'],'error')
        checks=result['details']['files'][0]['checks']
        self.assertEqual(next(c for c in checks if c['name']=='acl')['status'],'error')

    def test_invalid_uid_types_do_not_crash_or_become_acl_violation(self):
        for uid in (None,True,-1,'0',[],{}):
            data=extended();data['uid']=uid
            self.assertEqual(diagnose(approved_acl_policy(),data)['status'],'error')

    def test_missing_gid_not_treated_as_unauthorized_acl_principal(self):
        data=extended();del data['gid']
        result=diagnose(approved_acl_policy(),data)
        self.assertEqual(result['status'],'error')
        checks=result['details']['files'][0]['checks']
        self.assertNotIn('vulnerable',[c['status'] for c in checks])

    def test_invalid_gid_types_return_error(self):
        for gid in (None,True,-1,'0',[],{}):
            data=extended();data['gid']=gid
            self.assertEqual(diagnose(approved_acl_policy(),data)['status'],'error')

    def test_gid_validation_precedes_pending_group_policy(self):
        policy=load_policy(DEFAULT_POLICY.parent/'file_policy.ubuntu-24.04.json')['policies'][0]
        policy['criteria']['files']=policy['criteria']['files'][:1]
        data=observation();data['gid']=None
        result=diagnose(policy,data)
        self.assertEqual(result['status'],'error')
        check=next(c for c in result['details']['files'][0]['checks'] if c['name']=='group')
        self.assertEqual(check['status'],'error')

    def test_direct_group_check_rejects_bad_gid_even_if_policy_pending(self):
        for gid in (None,True,-1,'0'):
            status,_,_=group_check({'allowed_groups':None,'reference_gid':None},{'gid':gid},{})
            self.assertEqual(status,'error')

    def test_valid_gid_with_pending_policy_stays_review(self):
        status,_,_=group_check({'allowed_groups':None,'reference_gid':None},{'gid':0},{})
        self.assertEqual(status,'needs_review')

    def test_missing_file_type_is_error(self):
        data=observation();del data['file_type']
        self.assertEqual(diagnose(singlefile_policy(),data)['status'],'error')

    def test_unknown_file_type_is_error(self):
        for kind in (None,'',True,[],'directory','invalid'):
            data=observation();data['file_type']=kind
            self.assertEqual(diagnose(singlefile_policy(),data)['status'],'error')

    def test_known_other_and_symlink_types_remain_review(self):
        for kind in ('other','symlink'):
            data=observation();data['file_type']=kind
            self.assertEqual(diagnose(singlefile_policy(),data)['status'],'needs_review')

    def test_known_violation_survives_independent_gid_failure(self):
        data=extended();data['uid']=999;data['gid']=None
        result=diagnose(approved_acl_policy(),data)
        self.assertEqual(result['status'],'vulnerable')
        checks=result['details']['files'][0]['checks']
        self.assertEqual(next(c for c in checks if c['name']=='owner')['status'],'vulnerable')
        self.assertEqual(next(c for c in checks if c['name']=='acl')['status'],'error')
        self.assertEqual(next(c for c in checks if c['name']=='group')['status'],'error')

    def test_policy_candidate_does_not_hide_acquisition_error(self):
        policy=approved_acl_policy()
        policy['criteria']['files'][0]['approval_status']='candidate'
        data=extended();data['gid']=None
        self.assertEqual(diagnose(policy,data)['status'],'error')

    def test_partial_acl_evidence_is_preserved(self):
        data=extended();del data['uid']
        result=diagnose(approved_acl_policy(),data)
        file_result=result['details']['files'][0]
        self.assertEqual(file_result['actual']['acl']['raw'],data['acl']['raw'])
        acl=next(c for c in file_result['checks'] if c['name']=='acl')
        self.assertIn('effective_entries',acl['actual'])


if __name__ == '__main__':
    unittest.main()
