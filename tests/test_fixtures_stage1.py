from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from trivy_remediation_evidence.reader import read_source_file
from trivy_remediation_evidence.validator import (
    HAS_JSONSCHEMA,
    validate_source,
)

FIXTURES_DIR = Path("outputs/fixtures")
SCHEMAS_DIR = Path("outputs/schemas")


class TestFixturesStage1(unittest.TestCase):
    def test_case8_broken_json_reader(self) -> None:
        """Case 8 broken-json: reader detects invalid JSON and preserves raw hash."""
        broken_report_path = FIXTURES_DIR / "08" / "broken-json" / "after.json"
        self.assertTrue(broken_report_path.exists())

        res = read_source_file(broken_report_path, side="after", kind="report")
        self.assertEqual(res.parse_state, "invalid_json")
        self.assertIsNotNone(res.sha256)
        expected_hash = hashlib.sha256(broken_report_path.read_bytes()).hexdigest()
        self.assertEqual(res.sha256, expected_hash)
        self.assertEqual(len(res.reasons), 1)
        self.assertEqual(res.reasons[0].code, "INPUT_INVALID_JSON")
        self.assertEqual(res.reasons[0].refs[0].pointer, "")

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for fixture schema validation")
    def test_case1_array_order_only_validation(self) -> None:
        """Case 1 array-order-only: valid manifest and report on both sides."""
        c1_dir = FIXTURES_DIR / "01" / "array-order-only"
        self.assertTrue(c1_dir.exists())

        for side in ["before", "after"]:
            manifest_res = read_source_file(c1_dir / f"{side}.manifest.json", side=side, kind="manifest")  # type: ignore
            self.assertEqual(manifest_res.parse_state, "valid")
            reasons_m = validate_source(manifest_res, schemas_dir=SCHEMAS_DIR)
            self.assertEqual(reasons_m, [])
            self.assertEqual(manifest_res.parse_state, "valid")

            report_res = read_source_file(c1_dir / f"{side}.json", side=side, kind="report")  # type: ignore
            self.assertEqual(report_res.parse_state, "valid")
            reasons_r = validate_source(report_res, schemas_dir=SCHEMAS_DIR)
            self.assertEqual(reasons_r, [])
            self.assertEqual(report_res.parse_state, "valid")

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for fixture schema validation")
    def test_case7_manifest_missing_validation(self) -> None:
        """Case 7 manifest-missing: after manifest is missing execution."""
        path = FIXTURES_DIR / "07" / "manifest-missing" / "after.manifest.json"
        self.assertTrue(path.exists())

        res = read_source_file(path, side="after", kind="manifest")
        self.assertEqual(res.parse_state, "valid")
        reasons = validate_source(res, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(res.parse_state, "invalid_schema")
        codes = [r.code for r in reasons]
        self.assertIn("MANIFEST_REQUIRED_MISSING", codes)

        req_reasons = [r for r in reasons if r.code == "MANIFEST_REQUIRED_MISSING"]
        self.assertEqual(req_reasons[0].refs[0].pointer, "")

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for fixture schema validation")
    def test_case7_db_hash_missing_validation(self) -> None:
        """Case 7 db-hash-missing: after manifest is missing snapshotSha256 in databases."""
        path = FIXTURES_DIR / "07" / "db-hash-missing" / "after.manifest.json"
        self.assertTrue(path.exists())

        res = read_source_file(path, side="after", kind="manifest")
        self.assertEqual(res.parse_state, "valid")
        reasons = validate_source(res, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(res.parse_state, "invalid_schema")
        codes = [r.code for r in reasons]
        self.assertIn("DB_SNAPSHOT_MISSING", codes)
        self.assertNotIn("MANIFEST_REQUIRED_MISSING", codes)

        db_reasons = [r for r in reasons if r.code == "DB_SNAPSHOT_MISSING"]
        self.assertEqual(db_reasons[0].refs[0].pointer, "/databases/0")

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for fixture schema validation")
    def test_case8_execution_failed_stage1_boundary(self) -> None:
        """Case 8 execution-failed: valid JSON and schema in stage 1 (semantic failure belongs to stage 2)."""
        path = FIXTURES_DIR / "08" / "execution-failed" / "after.manifest.json"
        self.assertTrue(path.exists())

        res = read_source_file(path, side="after", kind="manifest")
        self.assertEqual(res.parse_state, "valid")
        reasons = validate_source(res, schemas_dir=SCHEMAS_DIR)
        # In stage 1, execution.success=false is schema-valid
        self.assertEqual(reasons, [])
        self.assertEqual(res.parse_state, "valid")


if __name__ == "__main__":
    unittest.main()
