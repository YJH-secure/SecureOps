"""Official expectations are independent constants, never computed by the SUT.

FIRST examples sections 3/4/5/6/7: https://www.first.org/cvss/v3-1/examples
Equations / Roundup: https://www.first.org/cvss/v3-1/specification-document
Only calculator fixtures; these CVEs are NOT detections on SecureOps targets.
"""

import itertools
import unittest

from core.cvss import METRICS, base_score, parse_vector, rating, roundup


VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
OFFICIAL_CASES = (
    ("CVE-2013-0375; FIRST examples section 3", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
    ("CVE-2014-3566; FIRST examples section 4", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVE-2012-1516; FIRST examples section 5", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
    ("CVE-2009-0783; FIRST examples section 6", "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2),
    ("CVE-2012-0384; FIRST examples section 7", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
)


class CVSSBaseTests(unittest.TestCase):
    def test_first_official_examples(self):
        for source, vector, expected in OFFICIAL_CASES:
            with self.subTest(source=source, vector=vector):
                self.assertEqual(base_score(vector), expected)

    def test_policy_mock_is_98_critical(self):
        self.assertEqual(base_score(VECTOR), 9.8)
        self.assertEqual(rating(base_score(VECTOR)), "critical")

    def test_scope_and_privilege_weights(self):
        # Synthetic formula cases, not additional official vulnerability examples.
        for privilege, unchanged, changed in (("N", 9.8, 10.0), ("L", 8.8, 9.9), ("H", 7.2, 9.1)):
            with self.subTest(privilege=privilege):
                vector = VECTOR.replace("PR:N", "PR:" + privilege)
                self.assertEqual(base_score(vector), unchanged)
                self.assertEqual(base_score(vector.replace("S:U", "S:C")), changed)

    def test_zero_impact_in_both_scopes(self):
        for scope in ("U", "C"):
            vector = VECTOR.replace("S:U", "S:" + scope).replace("C:H/I:H/A:H", "C:N/I:N/A:N")
            self.assertEqual(base_score(vector), 0.0)
            self.assertEqual(rating(base_score(vector)), "none")

    def test_first_roundup_examples_and_floating_point(self):
        for value, expected in ((4.02, 4.1), (4.0, 4.0), (.1 + .2, .3),
                                (1.200003, 1.2), (1.200006, 1.3), (9.99999, 10.0), (0, 0.0)):
            with self.subTest(value=value):
                self.assertEqual(roundup(value), expected)

    def test_roundup_rejects_nonfinite_and_non_numeric(self):
        for value in (None, True, "4.0", float("nan"), float("inf"), -1, 11, 10**1000):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                roundup(value)

    def test_rating_boundaries(self):
        for score, expected in ((0, "none"), (.1, "low"), (3.9, "low"), (4, "medium"),
                                (6.9, "medium"), (7, "high"), (8.9, "high"), (9, "critical"), (10, "critical")):
            with self.subTest(score=score):
                self.assertEqual(rating(score), expected)

    def test_rating_rejects_invalid_values(self):
        for value in (True, None, "9.8", -1, 11, float("nan"), float("inf"), 10**1000):
            with self.assertRaises(ValueError):
                rating(value)

    def test_canonical_parser(self):
        self.assertEqual(list(parse_vector(VECTOR)), list(METRICS))

    def test_invalid_duplicate_missing_and_extra_metrics(self):
        for vector in (VECTOR.replace("3.1", "3.0"), VECTOR + "/E:F", VECTOR + "/AV:N",
                       VECTOR.rsplit("/", 1)[0], VECTOR.replace("/I:H", "/C:H"),
                       VECTOR.replace("AV:N/AC:L", "AC:L/AV:N"), VECTOR.lower(),
                       VECTOR.replace("AV:N", "AV:X"), VECTOR + "\n", " " + VECTOR,
                       VECTOR.replace("AV:N", "AV:"), VECTOR.replace("PR:N", "PR:NL")):
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                base_score(vector)
        for value in (None, {}, [], True):
            with self.assertRaises(TypeError):
                parse_vector(value)

    def test_all_2592_base_combinations_have_valid_bounded_tenths(self):
        # Invariants, not a claim of 2592 independent official expected scores.
        count = 0
        for values in itertools.product(*METRICS.values()):
            vector = "CVSS:3.1/" + "/".join(f"{key}:{value}" for key, value in zip(METRICS, values))
            score = base_score(vector)
            self.assertTrue(0 <= score <= 10)
            self.assertEqual(score, round(score, 1))
            if values[-3:] == ("N", "N", "N"):
                self.assertEqual(score, 0.0)
            else:
                self.assertGreater(score, 0)
            count += 1
        self.assertEqual(count, 2592)


if __name__ == "__main__":
    unittest.main()
