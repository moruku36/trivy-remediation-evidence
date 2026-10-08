from __future__ import annotations

import copy
import unittest
from pathlib import Path

from trivy_remediation_evidence.models import SourceInput
from trivy_remediation_evidence.validator import (
    HAS_JSONSCHEMA,
    validate_source,
)

SCHEMAS_DIR = Path("outputs/schemas")


@unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is required for schema validation tests")
class TestSchemaValidator(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_manifest_dict = {
            "schemaVersion": 1,
            "reportSha256": "a" * 64,
            "scanner": {
                "name": "trivy",
                "mode": "image",
                "version": "0.0.0-synthetic",
            },
            "databases": [
                {
                    "role": "vuln",
                    "snapshotSha256": "b" * 64,
                    "schemaVersion": 2,
                    "updatedAt": "2026-10-08T00:00:00Z",
                    "repository": "example/db:2",
                    "ociDigest": "sha256:" + "c" * 64,
                }
            ],
            "effectiveConfig": {
                "completeness": "complete",
                "scanners": ["vuln"],
                "packageTypes": ["os"],
                "severity": ["HIGH"],
                "ignoreUnfixed": False,
                "ignoreStatus": [],
                "skipDirs": [],
                "skipFiles": [],
                "ignoreFiles": [],
                "vex": [],
                "regoPolicies": [],
                "configFiles": [],
                "extraOptions": {},
            },
            "target": {
                "logicalId": "app",
                "imageDigest": "sha256:" + "d" * 64,
                "platform": {
                    "os": "linux",
                    "architecture": "amd64",
                    "variant": "",
                },
                "scopes": [
                    {
                        "logicalTargetId": "root",
                        "rawTarget": "root",
                        "path": "@os",
                        "class": "os-pkgs",
                        "ecosystem": "debian",
                        "expected": True,
                        "coverage": "scanned",
                    }
                ],
            },
            "execution": {
                "success": True,
                "completed": True,
                "reportComplete": True,
                "exitCode": 0,
                "configuredExitCode": 0,
                "configuredExitOnEol": 0,
                "exitCause": "normal",
            },
        }

        self.valid_report_dict = {
            "SchemaVersion": 2,
            "ArtifactType": "container_image",
            "ArtifactName": "test-image:latest",
            "Metadata": {
                "RepoDigests": ["test-image@sha256:" + "e" * 64],
                "ImageConfig": {
                    "os": "linux",
                    "architecture": "amd64",
                },
            },
            "Results": [
                {
                    "Target": "root",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "libtest",
                            "InstalledVersion": "1.0.0",
                        }
                    ],
                }
            ],
        }

    def test_valid_manifest(self) -> None:
        source = SourceInput(
            side="before",
            kind="manifest",
            sha256="1" * 64,
            parse_state="valid",
            data=copy.deepcopy(self.valid_manifest_dict),
        )
        reasons = validate_source(source, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(reasons, [])
        self.assertEqual(source.parse_state, "valid")

    def test_valid_report(self) -> None:
        source = SourceInput(
            side="before",
            kind="report",
            sha256="2" * 64,
            parse_state="valid",
            data=copy.deepcopy(self.valid_report_dict),
        )
        reasons = validate_source(source, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(reasons, [])
        self.assertEqual(source.parse_state, "valid")

    def test_manifest_required_missing_omitted_and_null(self) -> None:
        # Case A: omitted execution
        data_omitted = copy.deepcopy(self.valid_manifest_dict)
        del data_omitted["execution"]
        src_omitted = SourceInput(
            side="after", kind="manifest", sha256="3" * 64, parse_state="valid", data=data_omitted
        )
        reasons_omitted = validate_source(src_omitted, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_omitted.parse_state, "invalid_schema")
        codes = [r.code for r in reasons_omitted]
        self.assertIn("MANIFEST_REQUIRED_MISSING", codes)
        self.assertNotIn("INPUT_SCHEMA_INVALID", codes)

        # Case B: execution is explicitly null
        data_null = copy.deepcopy(self.valid_manifest_dict)
        data_null["execution"] = None
        src_null = SourceInput(
            side="after", kind="manifest", sha256="3" * 64, parse_state="valid", data=data_null
        )
        reasons_null = validate_source(src_null, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_null.parse_state, "invalid_schema")
        codes_null = [r.code for r in reasons_null]
        self.assertIn("MANIFEST_REQUIRED_MISSING", codes_null)
        self.assertNotIn("INPUT_SCHEMA_INVALID", codes_null)

        # Case C: execution is integer 123 (type violation) -> INPUT_SCHEMA_INVALID
        data_type = copy.deepcopy(self.valid_manifest_dict)
        data_type["execution"] = 123
        src_type = SourceInput(
            side="after", kind="manifest", sha256="3" * 64, parse_state="valid", data=data_type
        )
        reasons_type = validate_source(src_type, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_type.parse_state, "invalid_schema")
        codes_type = [r.code for r in reasons_type]
        self.assertIn("INPUT_SCHEMA_INVALID", codes_type)
        self.assertNotIn("MANIFEST_REQUIRED_MISSING", codes_type)

    def test_db_snapshot_missing_omitted_null_and_empty(self) -> None:
        for missing_val in ["OMIT", None, ""]:
            with self.subTest(missing_val=missing_val):
                data = copy.deepcopy(self.valid_manifest_dict)
                if missing_val == "OMIT":
                    del data["databases"][0]["snapshotSha256"]
                else:
                    data["databases"][0]["snapshotSha256"] = missing_val

                src = SourceInput(
                    side="after", kind="manifest", sha256="4" * 64, parse_state="valid", data=data
                )
                reasons = validate_source(src, schemas_dir=SCHEMAS_DIR)
                self.assertEqual(src.parse_state, "invalid_schema")
                codes = [r.code for r in reasons]
                self.assertIn("DB_SNAPSHOT_MISSING", codes)
                self.assertNotIn("MANIFEST_REQUIRED_MISSING", codes)
                self.assertNotIn("INPUT_SCHEMA_INVALID", codes)
                db_reason = [r for r in reasons if r.code == "DB_SNAPSHOT_MISSING"][0]
                self.assertEqual(db_reason.refs[0].pointer, "/databases/0")

    def test_db_snapshot_missing_and_role_missing_both_preserved(self) -> None:
        """When both snapshotSha256 and role are missing, both reasons must be preserved."""
        data = copy.deepcopy(self.valid_manifest_dict)
        del data["databases"][0]["snapshotSha256"]
        del data["databases"][0]["role"]
        src = SourceInput(
            side="after", kind="manifest", sha256="4b" * 32, parse_state="valid", data=data
        )
        reasons = validate_source(src, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src.parse_state, "invalid_schema")
        codes = [r.code for r in reasons]
        self.assertIn("DB_SNAPSHOT_MISSING", codes)
        self.assertIn("MANIFEST_REQUIRED_MISSING", codes)
        db_r = [r for r in reasons if r.code == "DB_SNAPSHOT_MISSING"][0]
        self.assertEqual(db_r.refs[0].pointer, "/databases/0")
        req_r = [r for r in reasons if r.code == "MANIFEST_REQUIRED_MISSING"][0]
        self.assertEqual(req_r.refs[0].pointer, "/databases/0")

    def test_db_snapshot_type_violation_and_format_violation(self) -> None:
        # Type violation: integer 123
        data_int = copy.deepcopy(self.valid_manifest_dict)
        data_int["databases"][0]["snapshotSha256"] = 123
        src_int = SourceInput(
            side="after", kind="manifest", sha256="5" * 64, parse_state="valid", data=data_int
        )
        reasons_int = validate_source(src_int, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_int.parse_state, "invalid_schema")
        codes_int = [r.code for r in reasons_int]
        self.assertIn("INPUT_SCHEMA_INVALID", codes_int)
        self.assertNotIn("DB_SNAPSHOT_MISSING", codes_int)

        # Format violation: non-empty string but invalid pattern
        data_fmt = copy.deepcopy(self.valid_manifest_dict)
        data_fmt["databases"][0]["snapshotSha256"] = "invalid_hash_pattern"
        src_fmt = SourceInput(
            side="after", kind="manifest", sha256="5" * 64, parse_state="valid", data=data_fmt
        )
        reasons_fmt = validate_source(src_fmt, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_fmt.parse_state, "invalid_schema")
        codes_fmt = [r.code for r in reasons_fmt]
        self.assertIn("INPUT_SCHEMA_INVALID", codes_fmt)
        self.assertNotIn("DB_SNAPSHOT_MISSING", codes_fmt)

    def test_manifest_version_unsupported_vs_type_violation(self) -> None:
        # Valid integer, unsupported version 2
        data_unsupported = copy.deepcopy(self.valid_manifest_dict)
        data_unsupported["schemaVersion"] = 2
        src_unsupported = SourceInput(
            side="before", kind="manifest", sha256="6" * 64, parse_state="valid", data=data_unsupported
        )
        reasons_u = validate_source(src_unsupported, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_unsupported.parse_state, "invalid_schema")
        codes_u = [r.code for r in reasons_u]
        self.assertIn("MANIFEST_VERSION_UNSUPPORTED", codes_u)
        self.assertNotIn("INPUT_SCHEMA_INVALID", codes_u)

        # String type violation "1"
        data_str = copy.deepcopy(self.valid_manifest_dict)
        data_str["schemaVersion"] = "1"
        src_str = SourceInput(
            side="before", kind="manifest", sha256="6" * 64, parse_state="valid", data=data_str
        )
        reasons_s = validate_source(src_str, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_str.parse_state, "invalid_schema")
        codes_s = [r.code for r in reasons_s]
        self.assertIn("INPUT_SCHEMA_INVALID", codes_s)
        self.assertNotIn("MANIFEST_VERSION_UNSUPPORTED", codes_s)

        # Bool type violation True
        data_bool = copy.deepcopy(self.valid_manifest_dict)
        data_bool["schemaVersion"] = True
        src_bool = SourceInput(
            side="before", kind="manifest", sha256="6" * 64, parse_state="valid", data=data_bool
        )
        reasons_b = validate_source(src_bool, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_bool.parse_state, "invalid_schema")
        codes_b = [r.code for r in reasons_b]
        self.assertIn("INPUT_SCHEMA_INVALID", codes_b)
        self.assertNotIn("MANIFEST_VERSION_UNSUPPORTED", codes_b)

    def test_report_schema_unsupported_vs_type_violation(self) -> None:
        # Valid integer, unsupported version 1
        data_unsupported = copy.deepcopy(self.valid_report_dict)
        data_unsupported["SchemaVersion"] = 1
        src_unsupported = SourceInput(
            side="after", kind="report", sha256="7" * 64, parse_state="valid", data=data_unsupported
        )
        reasons_u = validate_source(src_unsupported, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_unsupported.parse_state, "invalid_schema")
        codes_u = [r.code for r in reasons_u]
        self.assertIn("UNSUPPORTED_REPORT_SCHEMA", codes_u)
        self.assertNotIn("INPUT_SCHEMA_INVALID", codes_u)

        # String type violation "2"
        data_str = copy.deepcopy(self.valid_report_dict)
        data_str["SchemaVersion"] = "2"
        src_str = SourceInput(
            side="after", kind="report", sha256="7" * 64, parse_state="valid", data=data_str
        )
        reasons_s = validate_source(src_str, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_str.parse_state, "invalid_schema")
        codes_s = [r.code for r in reasons_s]
        self.assertIn("INPUT_SCHEMA_INVALID", codes_s)
        self.assertNotIn("UNSUPPORTED_REPORT_SCHEMA", codes_s)

    def test_typed_const_profile_violations(self) -> None:
        # 1. Report ArtifactType
        # Correct string type, unsupported profile "filesystem"
        data_art = copy.deepcopy(self.valid_report_dict)
        data_art["ArtifactType"] = "filesystem"
        src_art = SourceInput(
            side="after", kind="report", sha256="8" * 64, parse_state="valid", data=data_art
        )
        reasons_art = validate_source(src_art, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(src_art.parse_state, "invalid_schema")
        codes_art = [r.code for r in reasons_art]
        self.assertIn("UNSUPPORTED_PROFILE", codes_art)
        self.assertNotIn("INPUT_SCHEMA_INVALID", codes_art)

        # ArtifactType integer 123 -> INPUT_SCHEMA_INVALID
        data_art_int = copy.deepcopy(self.valid_report_dict)
        data_art_int["ArtifactType"] = 123
        src_art_int = SourceInput(
            side="after", kind="report", sha256="8" * 64, parse_state="valid", data=data_art_int
        )
        reasons_art_int = validate_source(src_art_int, schemas_dir=SCHEMAS_DIR)
        codes_art_int = [r.code for r in reasons_art_int]
        self.assertIn("INPUT_SCHEMA_INVALID", codes_art_int)
        self.assertNotIn("UNSUPPORTED_PROFILE", codes_art_int)

        # 2. Manifest scanner.name
        # Correct string type, unsupported scanner "grype"
        data_sc_name = copy.deepcopy(self.valid_manifest_dict)
        data_sc_name["scanner"]["name"] = "grype"
        src_sc_name = SourceInput(
            side="before", kind="manifest", sha256="8" * 64, parse_state="valid", data=data_sc_name
        )
        reasons_sc_name = validate_source(src_sc_name, schemas_dir=SCHEMAS_DIR)
        codes_sc_name = [r.code for r in reasons_sc_name]
        self.assertIn("UNSUPPORTED_PROFILE", codes_sc_name)
        self.assertNotIn("INPUT_SCHEMA_INVALID", codes_sc_name)

        # 3. Manifest scanner.mode
        # Correct string type, unsupported mode "fs"
        data_sc_mode = copy.deepcopy(self.valid_manifest_dict)
        data_sc_mode["scanner"]["mode"] = "fs"
        src_sc_mode = SourceInput(
            side="before", kind="manifest", sha256="8" * 64, parse_state="valid", data=data_sc_mode
        )
        reasons_sc_mode = validate_source(src_sc_mode, schemas_dir=SCHEMAS_DIR)
        codes_sc_mode = [r.code for r in reasons_sc_mode]
        self.assertIn("UNSUPPORTED_PROFILE", codes_sc_mode)
        self.assertNotIn("INPUT_SCHEMA_INVALID", codes_sc_mode)

    def test_known_field_type_violation(self) -> None:
        data = copy.deepcopy(self.valid_report_dict)
        data["Results"] = "not_a_list"
        source = SourceInput(
            side="after",
            kind="report",
            sha256="7" * 64,
            parse_state="valid",
            data=data,
        )
        reasons = validate_source(source, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(source.parse_state, "invalid_schema")
        codes = [r.code for r in reasons]
        self.assertIn("INPUT_SCHEMA_INVALID", codes)
        self.assertEqual(reasons[0].refs[0].pointer, "/Results")

    def test_manifest_unknown_field_rejected(self) -> None:
        data = copy.deepcopy(self.valid_manifest_dict)
        data["unexpectedProperty"] = 123
        source = SourceInput(
            side="before",
            kind="manifest",
            sha256="8" * 64,
            parse_state="valid",
            data=data,
        )
        reasons = validate_source(source, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(source.parse_state, "invalid_schema")
        codes = [r.code for r in reasons]
        self.assertIn("INPUT_SCHEMA_INVALID", codes)

    def test_report_unknown_field_accepted(self) -> None:
        data = copy.deepcopy(self.valid_report_dict)
        data["UnknownTrivyTopLevelProperty"] = {"some": "data"}
        source = SourceInput(
            side="before",
            kind="report",
            sha256="9" * 64,
            parse_state="valid",
            data=data,
        )
        reasons = validate_source(source, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(reasons, [])
        self.assertEqual(source.parse_state, "valid")

    def test_no_empty_report_conversion_on_failure(self) -> None:
        data = copy.deepcopy(self.valid_report_dict)
        data["SchemaVersion"] = 99
        source = SourceInput(
            side="after",
            kind="report",
            sha256="10" * 32,
            parse_state="valid",
            data=data,
        )
        validate_source(source, schemas_dir=SCHEMAS_DIR)
        self.assertEqual(source.parse_state, "invalid_schema")
        self.assertEqual(source.data, data)
        self.assertIsNotNone(source.data.get("Results"))


if __name__ == "__main__":
    unittest.main()
