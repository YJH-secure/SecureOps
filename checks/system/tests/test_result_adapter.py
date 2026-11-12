"""Opt-in result export and contract checks using fixtures."""

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from checks.system import file_check, firewall_check, log_check, service_check
from checks.system.common import make_result
from checks.system.result_adapter import adapt_result
from checks.system.tests.test_diagnosis import observation
from checks.system.tests.test_v11 import execute, shadow_only
from checks.system.validate_result import DEFAULT_SCHEMA, validate

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None


SCHEMA_V12 = DEFAULT_SCHEMA.with_name('json-result-schema-v1.2.schema.json')
ASSESSMENTS = {
    'pass': 'not_applicable',
    'vulnerable': 'pending',
    'error': 'not_applicable',
    'not_applicable': 'not_applicable',
    'needs_review': 'not_applicable',
}
UNSCORED_FIELDS = ('version', 'vector', 'base_score', 'rating', 'source')


def legacy_result(status, check_id='FILE-01'):
    return make_result(check_id, status, 'high', 'Observed facts', 'Review evidence',
                       details={'files': [{'path': '/etc/shadow'}]})


class ResultAdapterTests(unittest.TestCase):
    def test_all_diagnosis_statuses_and_unscored_fields(self):
        for status, assessment in ASSESSMENTS.items():
            with self.subTest(status=status):
                legacy = legacy_result(status)
                exported = adapt_result(legacy, '1.2')
                cvss = exported['cvss']
                self.assertEqual(exported['status'], status)
                self.assertEqual(cvss['assessment_status'], assessment)
                self.assertEqual(set(cvss), set(UNSCORED_FIELDS) | {'assessment_status', 'rationale'})
                for field in UNSCORED_FIELDS:
                    self.assertIsNone(cvss[field])
                self.assertIn(f'v1.1 {status}', cvss['rationale'])
                self.assertEqual(set(exported), (set(legacy) - {'severity'}) | {'cvss'})

    def test_candidate_shadow_details_are_preserved(self):
        legacy = execute(shadow_only(), observation('0640', gid=777))
        exported = adapt_result(legacy, '1.2')
        self.assertEqual(exported['status'], 'needs_review')
        self.assertEqual(exported['cvss']['assessment_status'], 'not_applicable')
        for key in ('details', 'evidence', 'recommendation'):
            self.assertEqual(exported[key], legacy[key])
        self.assertEqual(exported['details']['files'][0]['path'], '/etc/shadow')
        exported['details']['files'][0]['path'] = 'changed'
        self.assertEqual(legacy['details']['files'][0]['path'], '/etc/shadow')
        self.assertEqual(legacy['severity'], 'high')
        self.assertNotIn('cvss', legacy)

    def test_reviewed_policy_only_violation(self):
        rationale = 'This fixture represents a policy-only exception.'
        exported = adapt_result(legacy_result('vulnerable'), '1.2',
                                policy_only_rationale=rationale)
        self.assertEqual(exported['status'], 'vulnerable')
        self.assertEqual(exported['cvss']['assessment_status'], 'not_applicable')
        self.assertIn(rationale, exported['cvss']['rationale'])

    def test_invalid_policy_only_classification(self):
        cases = (('needs_review', '1.2', 'a reason'), ('vulnerable', '1.1', 'a reason'),
                 ('vulnerable', '1.2', '   '))
        for status, version, rationale in cases:
            with self.subTest(status=status, version=version, rationale=rationale):
                with self.assertRaises(ValueError):
                    adapt_result(legacy_result(status), version, policy_only_rationale=rationale)

    def test_cli_v12_is_opt_in_and_valid_error_results_exit_zero(self):
        modules = ((file_check, 'FILE-01'), (service_check, 'SVC-01'),
                   (firewall_check, 'FW-01'), (log_check, 'LOG-01'))
        for module, check_id in modules:
            legacy = legacy_result('error', check_id)
            for args in ([], ['--result-version', '1.1'], ['--result-version', '1.2']):
                with self.subTest(check_id=check_id, args=args):
                    stdout = StringIO()
                    with patch.object(module, 'run_from_policy', return_value=legacy), \
                            patch('sys.argv', [module.__name__, *args]), redirect_stdout(stdout):
                        self.assertEqual(module.main(), 0)
                    output = json.loads(stdout.getvalue())
                    if args and args[-1] == '1.2':
                        self.assertEqual(output['status'], 'error')
                        self.assertEqual(output['cvss']['assessment_status'], 'not_applicable')
                        self.assertEqual(output['details'], legacy['details'])
                        self.assertNotIn('severity', output)
                    else:
                        self.assertEqual(output, legacy)


@unittest.skipUnless(Draft202012Validator, 'install the developer dependency jsonschema[format]')
class ResultSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_V12.read_text(encoding='utf-8'))

    def test_merged_v12_mock_and_adapted_items_validate(self):
        mock = Path(__file__).resolve().parents[3] / 'tests/fixtures/sample-result-v1.2-MOCK.json'
        self.assertEqual(validate(json.loads(mock.read_text(encoding='utf-8')), self.schema), [])
        for status in ASSESSMENTS:
            with self.subTest(status=status):
                self.assertEqual(validate(adapt_result(legacy_result(status), '1.2'), self.schema), [])
        reviewed = adapt_result(legacy_result('vulnerable'), '1.2',
                                policy_only_rationale='Reviewed policy-only test fixture.')
        self.assertEqual(validate(reviewed, self.schema), [])

    def test_v11_output_still_validates(self):
        schema = json.loads(DEFAULT_SCHEMA.read_text(encoding='utf-8'))
        self.assertEqual(validate(adapt_result(legacy_result('needs_review')), schema), [])

    def test_v12_schema_rejects_invalid_status_combinations_and_fields(self):
        for status in ('pass', 'error', 'needs_review', 'not_applicable'):
            with self.subTest(status=status):
                invalid = adapt_result(legacy_result(status), '1.2')
                invalid['cvss']['assessment_status'] = 'pending'
                self.assertTrue(validate(invalid, self.schema))
        invalid = adapt_result(legacy_result('vulnerable'), '1.2')
        invalid['cvss']['base_score'] = 7.5
        self.assertTrue(validate(invalid, self.schema))
        invalid = adapt_result(legacy_result('vulnerable'), '1.2')
        invalid['severity'] = 'high'
        self.assertTrue(validate(invalid, self.schema))
