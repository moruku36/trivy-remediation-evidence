from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from trivy_remediation_evidence.manifest_gate import evaluate_manifest_gate
from trivy_remediation_evidence.models import SourceInput
from trivy_remediation_evidence.reader import read_source_file
from trivy_remediation_evidence.reasons import InputRef, Reason
from trivy_remediation_evidence.validator import HAS_JSONSCHEMA, validate_source

FIXTURES_DIR = Path("outputs/fixtures")
SCHEMAS_DIR = Path("outputs/schemas")


class TestManifestGate(unittest.TestCase):
    def load_fixture_inputs(self, fixture_rel_path: str) -> tuple[SourceInput, SourceInput, SourceInput, SourceInput]:
        path = FIXTURES_DIR / fixture_rel_path
        bm = read_source_file(path / "before.manifest.json", side="before", kind="manifest")
        am = read_source_file(path / "after.manifest.json", side="after", kind="manifest")
        br = read_source_file(path / "before.json", side="before", kind="report")
        ar = read_source_file(path / "after.json", side="after", kind="report")

        if HAS_JSONSCHEMA:
            for s in [bm, am, br, ar]:
                validate_source(s, schemas_dir=SCHEMAS_DIR)

        return bm, am, br, ar

    def load_expected_global_codes(self, fixture_rel_path: str) -> list[str]:
        expected_path = FIXTURES_DIR / fixture_rel_path / "expected.json"
        expected_data = json.loads(expected_path.read_bytes().decode("utf-8"))
        return expected_data.get("globalReasonCodes", [])

    def test_case1_array_order_only(self) -> None:
        """Case 1: Array order differences only, set comparison passes with no global reasons."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("01/array-order-only")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, [])

    def test_image_digest_difference_is_allowed(self) -> None:
        """Image digest difference between before and after is allowed."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        # Change after manifest target imageDigest to a new digest, also updated in report RepoDigests
        new_digest = "sha256:" + "f" * 64
        am.data["target"]["imageDigest"] = new_digest
        ar.data["Metadata"]["RepoDigests"].append("synthetic-app@" + new_digest)

        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertNotIn("TARGET_ID_MISMATCH", codes)
        self.assertNotIn("IMAGE_EVIDENCE_MISMATCH", codes)

    def test_case6_scope_missing(self) -> None:
        """Case 6 scope-missing: after manifest is missing a scope -> SCOPE_SET_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("06/scope-missing")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("06/scope-missing")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["SCOPE_SET_MISMATCH"])

    def test_case6_scope_excluded(self) -> None:
        """Case 6 scope-excluded: scope coverage is excluded -> SCOPE_NOT_SCANNED."""
        bm, am, br, ar = self.load_fixture_inputs("06/scope-excluded")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("06/scope-excluded")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["SCOPE_NOT_SCANNED"])

    def test_case6_result_missing(self) -> None:
        """Case 6 result-missing: scanned scope missing matching Result -> RESULT_SCOPE_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("06/result-missing")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("06/result-missing")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["RESULT_SCOPE_MISMATCH"])

    def test_case7_scanner_changed(self) -> None:
        """Case 7 scanner-changed: scanner version mismatch -> SCANNER_VERSION_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("07/scanner-changed")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("07/scanner-changed")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["SCANNER_VERSION_MISMATCH"])

    def test_case7_db_changed(self) -> None:
        """Case 7 db-changed: DB snapshotSha256 mismatch -> DB_SNAPSHOT_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("07/db-changed")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("07/db-changed")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["DB_SNAPSHOT_MISMATCH"])

    def test_case7_config_changed(self) -> None:
        """Case 7 config-changed: effectiveConfig mismatch -> CONFIG_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("07/config-changed")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("07/config-changed")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["CONFIG_MISMATCH"])

    def test_case7_ignore_changed(self) -> None:
        """Case 7 ignore-changed: ignoreFiles asset mismatch -> CONFIG_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("07/ignore-changed")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("07/ignore-changed")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["CONFIG_MISMATCH"])

    def test_case7_vex_changed(self) -> None:
        """Case 7 vex-changed: vex asset mismatch -> CONFIG_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("07/vex-changed")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("07/vex-changed")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["CONFIG_MISMATCH"])

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for manifest schema validation")
    def test_case7_manifest_missing_suppresses_derived_gate(self) -> None:
        """Case 7 manifest-missing: Stage 1 reason preserved, derived gate comparisons suppressed."""
        bm, am, br, ar = self.load_fixture_inputs("07/manifest-missing")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("07/manifest-missing")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["MANIFEST_REQUIRED_MISSING"])

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for manifest schema validation")
    def test_case7_db_hash_missing_suppresses_derived_gate(self) -> None:
        """Case 7 db-hash-missing: Stage 1 reason preserved, derived gate comparisons suppressed."""
        bm, am, br, ar = self.load_fixture_inputs("07/db-hash-missing")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("07/db-hash-missing")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["DB_SNAPSHOT_MISSING"])

    def test_derived_diagnostics_suppression_unit(self) -> None:
        """Unit test for suppression of derived gate comparisons when manifest has stage 1 error."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        # Simulate after manifest having a stage 1 schema violation
        am.parse_state = "invalid_schema"
        am.reasons = [
            Reason(code="MANIFEST_REQUIRED_MISSING", refs=(InputRef(side="after", kind="manifest", pointer=""),))
        ]
        # Introduce differences that would normally trigger gate mismatches
        am.data["scanner"]["version"] = "diff-version"
        am.data["databases"][0]["snapshotSha256"] = "1" * 64

        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        # Derived mismatches must be suppressed, only stage 1 reason preserved
        self.assertEqual(codes, ["MANIFEST_REQUIRED_MISSING"])

    def test_case8_execution_failed(self) -> None:
        """Case 8 execution-failed: execution.success=false -> EXECUTION_FAILED."""
        bm, am, br, ar = self.load_fixture_inputs("08/execution-failed")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("08/execution-failed")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["EXECUTION_FAILED"])

    def test_case8_broken_json(self) -> None:
        """Case 8 broken-json: Stage 1 invalid_json preserved."""
        bm, am, br, ar = self.load_fixture_inputs("08/broken-json")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("08/broken-json")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["INPUT_INVALID_JSON"])

    def test_case8_policy_nonzero_success(self) -> None:
        """Case 8 policy-nonzero-success: exitCode=1, findings_policy is comparable (no global reasons)."""
        bm, am, br, ar = self.load_fixture_inputs("08/policy-nonzero-success")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("08/policy-nonzero-success")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, [])

    def test_case8_unknown_nonzero(self) -> None:
        """Case 8 unknown-nonzero: exitCause=unknown -> EXECUTION_STATUS_UNKNOWN."""
        bm, am, br, ar = self.load_fixture_inputs("08/unknown-nonzero")
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        expected_codes = self.load_expected_global_codes("08/unknown-nonzero")
        self.assertEqual(codes, expected_codes)
        self.assertEqual(codes, ["EXECUTION_STATUS_UNKNOWN"])

    def test_multiple_independent_reasons_preserved(self) -> None:
        """Multiple independent gate failures must all be preserved in global reasons."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")

        # 1. Scanner version difference
        am.data["scanner"]["version"] = "9.9.9-diff"
        # 2. DB snapshot difference (distinct from original 'dddd...')
        am.data["databases"][0]["snapshotSha256"] = "1" * 64
        # 3. Execution failure
        am.data["execution"]["success"] = False
        am.data["execution"]["exitCause"] = "failure"

        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertIn("SCANNER_VERSION_MISMATCH", codes)
        self.assertIn("DB_SNAPSHOT_MISMATCH", codes)
        self.assertIn("EXECUTION_FAILED", codes)
        # Codes are sorted
        self.assertEqual(codes, sorted(codes))

    def test_report_hash_mismatch(self) -> None:
        """reportSha256 in manifest differing from actual report SHA-256 triggers REPORT_HASH_MISMATCH."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        am.data["reportSha256"] = "0" * 64
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertIn("REPORT_HASH_MISMATCH", codes)

    def test_platform_consistency_and_pointer_refs(self) -> None:
        """Mismatch in os/architecture/variant triggers IMAGE_EVIDENCE_MISMATCH with both pointers."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        # Change architecture in report
        ar.data["Metadata"]["ImageConfig"]["architecture"] = "arm64"
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertIn("IMAGE_EVIDENCE_MISMATCH", codes)

        mismatch_r = [r for r in reasons if r.code == "IMAGE_EVIDENCE_MISMATCH"][0]
        pointers = [ref.pointer for ref in mismatch_r.refs]
        self.assertIn("/target/platform/architecture", pointers)
        self.assertIn("/Metadata/ImageConfig/architecture", pointers)

    def test_db_role_vuln_required_and_duplicate_roles_rejected(self) -> None:
        """Databases must include role=vuln and must not duplicate any role."""
        # 1. Missing role=vuln
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        am.data["databases"][0]["role"] = "other"
        bm.data["databases"][0]["role"] = "other"
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertIn("DB_SNAPSHOT_MISSING", codes)

        # 2. Duplicate role in same manifest
        bm2, am2, br2, ar2 = self.load_fixture_inputs("01/array-order-only")
        dup_db = copy.deepcopy(am2.data["databases"][0])
        am2.data["databases"].append(dup_db)
        reasons2 = evaluate_manifest_gate(bm2, am2, br2, ar2)
        codes2 = [r.code for r in reasons2]
        self.assertIn("DB_SNAPSHOT_MISMATCH", codes2)

    def test_empty_scanners_profile_rejected(self) -> None:
        """Empty scanners list rejected as UNSUPPORTED_PROFILE."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        am.data["effectiveConfig"]["scanners"] = []
        bm.data["effectiveConfig"]["scanners"] = []
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertIn("UNSUPPORTED_PROFILE", codes)
        unsupp_r = [r for r in reasons if r.code == "UNSUPPORTED_PROFILE"][0]
        self.assertEqual(unsupp_r.refs[0].pointer, "/effectiveConfig/scanners")

    def test_scope_duplicates_and_bidirectional_result_mapping(self) -> None:
        """Scopes with duplicate rawTarget or logical tuple must be rejected."""
        # 1. Duplicate rawTarget across scopes in same manifest
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        extra_scope = copy.deepcopy(am.data["target"]["scopes"][0])
        extra_scope["logicalTargetId"] = "different-logical-id"
        am.data["target"]["scopes"].append(extra_scope)
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertIn("RESULT_SCOPE_MISMATCH", codes)

        # 2. Duplicate logical scope tuple in same manifest
        bm2, am2, br2, ar2 = self.load_fixture_inputs("01/array-order-only")
        dup_logical_scope = copy.deepcopy(am2.data["target"]["scopes"][0])
        dup_logical_scope["rawTarget"] = "different-raw"
        am2.data["target"]["scopes"].append(dup_logical_scope)
        reasons2 = evaluate_manifest_gate(bm2, am2, br2, ar2)
        codes2 = [r.code for r in reasons2]
        self.assertIn("SCOPE_SET_MISMATCH", codes2)

    def test_extra_options_dedicated_keys_rejected(self) -> None:
        """Dedicated known options must not be recorded in extraOptions."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")
        am.data["effectiveConfig"]["extraOptions"]["severity"] = "HIGH"
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        codes = [r.code for r in reasons]
        self.assertIn("CONFIG_MISMATCH", codes)
        all_pointers = [ref.pointer for r in reasons if r.code == "CONFIG_MISMATCH" for ref in r.refs]
        self.assertIn("/effectiveConfig/extraOptions/severity", all_pointers)

    def test_precise_causal_reason_pointers(self) -> None:
        """Reasons must reference only actual causal failing fields."""
        bm, am, br, ar = self.load_fixture_inputs("01/array-order-only")

        # 1. exitCause=failure with success=true
        am.data["execution"]["exitCause"] = "failure"
        am.data["execution"]["success"] = True
        reasons = evaluate_manifest_gate(bm, am, br, ar)
        fail_r = [r for r in reasons if r.code == "EXECUTION_FAILED"][0]
        pointers = [ref.pointer for ref in fail_r.refs]
        self.assertIn("/execution/exitCause", pointers)
        self.assertNotIn("/execution/success", pointers)

        # 2. reportComplete=false with completed=true
        bm2, am2, br2, ar2 = self.load_fixture_inputs("01/array-order-only")
        am2.data["execution"]["reportComplete"] = False
        am2.data["execution"]["completed"] = True
        reasons2 = evaluate_manifest_gate(bm2, am2, br2, ar2)
        inc_r = [r for r in reasons2 if r.code == "EXECUTION_INCOMPLETE"][0]
        pointers2 = [ref.pointer for ref in inc_r.refs]
        self.assertIn("/execution/reportComplete", pointers2)
        self.assertNotIn("/execution/completed", pointers2)

        # 3. expected=false with coverage=scanned
        bm3, am3, br3, ar3 = self.load_fixture_inputs("01/array-order-only")
        am3.data["target"]["scopes"][0]["expected"] = False
        am3.data["target"]["scopes"][0]["coverage"] = "scanned"
        reasons3 = evaluate_manifest_gate(bm3, am3, br3, ar3)
        sc_r = [r for r in reasons3 if r.code == "SCOPE_NOT_SCANNED"][0]
        pointers3 = [ref.pointer for ref in sc_r.refs]
        self.assertIn("/target/scopes/0/expected", pointers3)
        self.assertNotIn("/target/scopes/0/coverage", pointers3)


if __name__ == "__main__":
    unittest.main()
