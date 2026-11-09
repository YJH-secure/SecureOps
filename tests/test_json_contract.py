
import copy
import json
import unittest
from pathlib import Path

from jsonschema import (
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATH = (
    ROOT / "docs/architecture/"
    "json-result-schema-v1.1.schema.json"
)

SAMPLE_PATH = (
    ROOT / "tests/fixtures/"
    "sample-result-v1.1-MOCK.json"
)


class TestJSONContract(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(
            SCHEMA_PATH.read_text(encoding="utf-8")
        )

        Draft202012Validator.check_schema(cls.schema)

        cls.validator = Draft202012Validator(
            cls.schema,
            format_checker=FormatChecker(),
        )

        cls.original = json.loads(
            SAMPLE_PATH.read_text(encoding="utf-8")
        )

    def validate_report(self, report):
        self.validator.validate(report)

        ids = [
            item["check_id"]
            for item in report["results"]
        ]

        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate check_id detected")

    def test_valid_json(self):
        self.validate_report(self.original)

    def test_missing_recommendation(self):
        data = copy.deepcopy(self.original)
        data["results"][0].pop("recommendation")

        with self.assertRaises(ValidationError):
            self.validate_report(data)

    def test_invalid_status(self):
        data = copy.deepcopy(self.original)
        data["results"][0]["status"] = "unknown"

        with self.assertRaises(ValidationError):
            self.validate_report(data)

    def test_uppercase_severity(self):
        data = copy.deepcopy(self.original)
        data["results"][0]["severity"] = "HIGH"

        with self.assertRaises(ValidationError):
            self.validate_report(data)

    def test_invalid_timestamp(self):
        data = copy.deepcopy(self.original)
        data["scanned_at"] = "2026-11-06T10:00:00"

        with self.assertRaises(ValidationError) as result:
            self.validate_report(data)

        self.assertEqual(
            result.exception.validator,
            "format",
        )

    def test_duplicate_check_id(self):
        data = copy.deepcopy(self.original)
        data["results"].append(
            copy.deepcopy(data["results"][0])
        )

        with self.assertRaisesRegex(
            ValueError, "Duplicate check_id"
        ):
            self.validate_report(data)

    def test_missing_target_id(self):
        data = copy.deepcopy(self.original)
        data.pop("target_id")

        with self.assertRaises(ValidationError):
            self.validate_report(data)

    def test_empty_results(self):
        data = copy.deepcopy(self.original)
        data["results"] = []

        with self.assertRaises(ValidationError):
            self.validate_report(data)


if __name__ == "__main__":
    unittest.main()
