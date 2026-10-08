from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
import unittest

from trivy_remediation_evidence.comparator import (
    ComparisonResult,
    EvidenceItem,
    FindingObservation,
    Identity,
    compare_manifests_and_reports,
)
from trivy_remediation_evidence.models import SourceInput
from trivy_remediation_evidence.reader import read_source_file
from trivy_remediation_evidence.reasons import InputRef, Reason
from trivy_remediation_evidence.validator import HAS_JSONSCHEMA, validate_source


class TestComparator(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures_dir = Path("outputs/fixtures")

    def load_fixture_inputs(
        self, folder_rel: str, run_validate: bool = True
    ) -> tuple[SourceInput, SourceInput, SourceInput, SourceInput]:
        folder = Path("outputs") / folder_rel
        bm = read_source_file(folder / "before.manifest.json", "before", "manifest")
        am = read_source_file(folder / "after.manifest.json", "after", "manifest")
        br = read_source_file(folder / "before.json", "before", "report")
        ar = read_source_file(folder / "after.json", "after", "report")

        if run_validate and HAS_JSONSCHEMA:
            validate_source(bm)
            validate_source(am)
            validate_source(br)
            validate_source(ar)

        return bm, am, br, ar

    # --- 1. Oracle tests for 20 fixture variants ---

    def test_case1_array_order_only_oracle(self) -> None:
        """Case 1 array-order-only: array ordering differences are comparable."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparable")
        self.assertEqual(res.cli_exit_code, 0)
        self.assertEqual(res.observed_counts, {"before": 2, "after": 2})
        self.assertEqual(res.summary, {"new": 0, "persistent": 2, "not_detected": 0, "comparison_unavailable": 0})
        self.assertEqual([r.code for r in res.global_reasons], [])
        self.assertEqual(len(res.items), 2)
        for item in res.items:
            self.assertEqual(item.classification, "persistent")
            self.assertEqual(item.remediation_conclusion, "not_established")
            self.assertEqual(item.reasons[0].code, "SAME_IDENTITY")

    def test_case2_one_new_oracle(self) -> None:
        """Case 2 one-new: 1 persistent, 1 new finding."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/02/one-new")
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparable")
        self.assertEqual(res.cli_exit_code, 0)
        self.assertEqual(res.observed_counts, {"before": 1, "after": 2})
        self.assertEqual(res.summary, {"new": 1, "persistent": 1, "not_detected": 0, "comparison_unavailable": 0})
        new_items = [it for it in res.items if it.classification == "new"]
        self.assertEqual(len(new_items), 1)
        self.assertEqual(new_items[0].reasons[0].code, "NEW_OBSERVATION")
        # Check empty side references for new item: before manifest scope coverage + before report Results
        refs = new_items[0].reasons[0].refs
        pointers = [ref.pointer for ref in refs]
        self.assertIn("/target/scopes/0/coverage", pointers)
        self.assertIn("/Results", pointers)

    def test_case3_one_not_detected_oracle(self) -> None:
        """Case 3 one-not-detected: 1 not_detected finding."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/03/one-not-detected")
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparable")
        self.assertEqual(res.cli_exit_code, 0)
        self.assertEqual(res.observed_counts, {"before": 1, "after": 0})
        self.assertEqual(res.summary, {"new": 0, "persistent": 0, "not_detected": 1, "comparison_unavailable": 0})
        not_det_items = [it for it in res.items if it.classification == "not_detected"]
        self.assertEqual(len(not_det_items), 1)
        self.assertEqual(not_det_items[0].remediation_conclusion, "not_established")
        self.assertEqual(not_det_items[0].reasons[0].code, "NOT_DETECTED_UNDER_EQUAL_CONDITIONS")
        # Check empty side references: after manifest scope coverage + after report Results
        refs = not_det_items[0].reasons[0].refs
        pointers = [ref.pointer for ref in refs]
        self.assertIn("/target/scopes/0/coverage", pointers)
        self.assertIn("/Results", pointers)

    def test_case4_version_update_persistent_oracle(self) -> None:
        """Case 4 version-update-persistent: Version change still preserves identity."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/04/version-update-persistent")
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparable")
        self.assertEqual(res.observed_counts, {"before": 1, "after": 1})
        self.assertEqual(res.summary, {"new": 0, "persistent": 1, "not_detected": 0, "comparison_unavailable": 0})
        # InstalledVersion changed in raw observation, but join is by 7-element identity
        item = res.items[0]
        self.assertEqual(item.classification, "persistent")
        self.assertEqual(item.before[0].installed_version, "1.0.0")
        self.assertEqual(item.after[0].installed_version, "2.0.0")

    def test_case5_same_name_distinct_path_ecosystem_oracle(self) -> None:
        """Case 5 same-name-distinct-path-ecosystem: distinct paths/ecosystems are separated."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/05/same-name-distinct-path-ecosystem")
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparable")
        self.assertEqual(res.observed_counts, {"before": 3, "after": 2})
        self.assertEqual(res.summary, {"new": 0, "persistent": 2, "not_detected": 1, "comparison_unavailable": 0})
        self.assertEqual(len(res.items), 3)

    def test_case5_ambiguous_duplicate_oracle(self) -> None:
        """Case 5 ambiguous-duplicate: duplicate identity in before report triggers DUPLICATE_IDENTITY."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/05/ambiguous-duplicate")
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        self.assertEqual(res.cli_exit_code, 2)
        self.assertEqual(res.observed_counts, {"before": 2, "after": 1})
        self.assertEqual(res.summary, {"new": 0, "persistent": 0, "not_detected": 0, "comparison_unavailable": 1})
        self.assertIn("DUPLICATE_IDENTITY", [r.code for r in res.global_reasons])
        item = res.items[0]
        self.assertEqual(item.classification, "comparison_unavailable")
        # Duplicates are NOT deduplicated from observations list
        self.assertEqual(item.before_pointers, ["/Results/0/Vulnerabilities/0", "/Results/0/Vulnerabilities/1"])
        self.assertEqual(item.after_pointers, ["/Results/0/Vulnerabilities/0"])

    def test_case6_gate_oracles(self) -> None:
        """Case 6 scope-missing, scope-excluded, result-missing: all comparison_unavailable."""
        variants = [
            ("fixtures/06/scope-missing", ["SCOPE_SET_MISMATCH"]),
            ("fixtures/06/scope-excluded", ["SCOPE_NOT_SCANNED"]),
            ("fixtures/06/result-missing", ["RESULT_SCOPE_MISMATCH"]),
        ]
        for rel_path, expected_codes in variants:
            with self.subTest(rel_path=rel_path):
                bm, am, br, ar = self.load_fixture_inputs(rel_path)
                res = compare_manifests_and_reports(bm, am, br, ar)
                self.assertEqual(res.comparison, "comparison_unavailable")
                self.assertEqual([r.code for r in res.global_reasons], expected_codes)
                self.assertEqual(res.summary["comparison_unavailable"], 1)

    def test_case7_oracles_standard_lib(self) -> None:
        """Case 7 scanner, db, config, ignore, vex changed: all comparison_unavailable."""
        variants = [
            ("fixtures/07/scanner-changed", ["SCANNER_VERSION_MISMATCH"]),
            ("fixtures/07/db-changed", ["DB_SNAPSHOT_MISMATCH"]),
            ("fixtures/07/config-changed", ["CONFIG_MISMATCH"]),
            ("fixtures/07/ignore-changed", ["CONFIG_MISMATCH"]),
            ("fixtures/07/vex-changed", ["CONFIG_MISMATCH"]),
        ]
        for rel_path, expected_codes in variants:
            with self.subTest(rel_path=rel_path):
                bm, am, br, ar = self.load_fixture_inputs(rel_path)
                res = compare_manifests_and_reports(bm, am, br, ar)
                self.assertEqual(res.comparison, "comparison_unavailable")
                self.assertEqual([r.code for r in res.global_reasons], expected_codes)
                self.assertEqual(res.summary["comparison_unavailable"], 1)

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for manifest-missing and db-hash-missing")
    def test_case7_manifest_missing_and_db_hash_missing_oracles(self) -> None:
        """Case 7 manifest-missing and db-hash-missing: schema validation triggers gate failure."""
        variants = [
            ("fixtures/07/manifest-missing", ["MANIFEST_REQUIRED_MISSING"]),
            ("fixtures/07/db-hash-missing", ["DB_SNAPSHOT_MISSING"]),
        ]
        for rel_path, expected_codes in variants:
            with self.subTest(rel_path=rel_path):
                bm, am, br, ar = self.load_fixture_inputs(rel_path)
                res = compare_manifests_and_reports(bm, am, br, ar)
                self.assertEqual(res.comparison, "comparison_unavailable")
                self.assertEqual([r.code for r in res.global_reasons], expected_codes)
                # Even when manifest is invalid, individual valid identities are extracted
                self.assertEqual(res.observed_counts, {"before": 1, "after": 1})
                self.assertEqual(res.summary["comparison_unavailable"], 1)
                self.assertIsNotNone(res.items[0].identity)

    def test_case8_oracles(self) -> None:
        """Case 8 execution failures, broken json, policy-nonzero-success, unknown-nonzero."""
        # 1. execution-failed
        bm, am, br, ar = self.load_fixture_inputs("fixtures/08/execution-failed")
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        self.assertEqual([r.code for r in res.global_reasons], ["EXECUTION_FAILED"])

        # 2. broken-json (after is broken)
        bm2, am2, br2, ar2 = self.load_fixture_inputs("fixtures/08/broken-json")
        res2 = compare_manifests_and_reports(bm2, am2, br2, ar2)
        self.assertEqual(res2.comparison, "comparison_unavailable")
        self.assertEqual([r.code for r in res2.global_reasons], ["INPUT_INVALID_JSON"])
        self.assertEqual(res2.observed_counts, {"before": 1, "after": None})
        self.assertEqual(len(res2.items), 1)
        self.assertEqual(res2.items[0].before_pointers, ["/Results/0/Vulnerabilities/0"])
        self.assertEqual(res2.items[0].after_pointers, [])

        # 3. policy-nonzero-success
        bm3, am3, br3, ar3 = self.load_fixture_inputs("fixtures/08/policy-nonzero-success")
        res3 = compare_manifests_and_reports(bm3, am3, br3, ar3)
        self.assertEqual(res3.comparison, "comparable")
        self.assertEqual([r.code for r in res3.global_reasons], [])
        self.assertEqual(res3.summary["persistent"], 1)

        # 4. unknown-nonzero
        bm4, am4, br4, ar4 = self.load_fixture_inputs("fixtures/08/unknown-nonzero")
        res4 = compare_manifests_and_reports(bm4, am4, br4, ar4)
        self.assertEqual(res4.comparison, "comparison_unavailable")
        self.assertEqual([r.code for r in res4.global_reasons], ["EXECUTION_STATUS_UNKNOWN"])

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for complete 20 variant batch check")
    def test_all_20_variants_complete_match(self) -> None:
        """Exhaustively match all 20 fixture variants against their expected.json oracle."""
        with open(self.fixtures_dir / "index.json", encoding="utf-8") as f:
            index = json.load(f)

        for entry in index:
            folder = Path("outputs") / entry["folder"]
            variant_name = entry["variant"]

            bm = read_source_file(folder / "before.manifest.json", "before", "manifest")
            am = read_source_file(folder / "after.manifest.json", "after", "manifest")
            br = read_source_file(folder / "before.json", "before", "report")
            ar = read_source_file(folder / "after.json", "after", "report")

            validate_source(bm)
            validate_source(am)
            validate_source(br)
            validate_source(ar)

            res = compare_manifests_and_reports(bm, am, br, ar)

            with open(folder / "expected.json", encoding="utf-8") as ef:
                exp = json.load(ef)

            self.assertEqual(res.comparison, exp["comparison"], f"[{variant_name}] comparison mismatch")
            self.assertEqual(res.cli_exit_code, exp["cliExitCode"], f"[{variant_name}] cliExitCode mismatch")
            self.assertEqual(res.observed_counts, exp["observedCounts"], f"[{variant_name}] observedCounts mismatch")
            self.assertEqual(res.summary, exp["summary"], f"[{variant_name}] summary mismatch")
            actual_codes = [r.code for r in res.global_reasons]
            self.assertEqual(actual_codes, exp["globalReasonCodes"], f"[{variant_name}] globalReasonCodes mismatch")
            self.assertEqual(len(res.items), len(exp["items"]), f"[{variant_name}] items length mismatch")

            for i, (act_item, exp_item) in enumerate(zip(res.items, exp["items"])):
                act_id = act_item.identity.to_dict() if act_item.identity else None
                self.assertEqual(act_id, exp_item["identity"], f"[{variant_name}] item[{i}] identity mismatch")
                self.assertEqual(act_item.classification, exp_item["classification"], f"[{variant_name}] item[{i}] classification mismatch")
                self.assertEqual(act_item.before_pointers, exp_item["beforePointers"], f"[{variant_name}] item[{i}] beforePointers mismatch")
                self.assertEqual(act_item.after_pointers, exp_item["afterPointers"], f"[{variant_name}] item[{i}] afterPointers mismatch")
                self.assertEqual(act_item.remediation_conclusion, exp_item["remediationConclusion"], f"[{variant_name}] item[{i}] remediationConclusion mismatch")

    # --- 2. Additional edge cases and boundaries ---

    def test_duplicate_identity_same_key_multiple_versions(self) -> None:
        """Same (PkgName, VulnerabilityID, path) with multiple versions triggers DUPLICATE_IDENTITY."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        # Duplicate finding in after report with a different version
        dup_vuln = copy.deepcopy(ar.data["Results"][0]["Vulnerabilities"][0])
        dup_vuln["InstalledVersion"] = "9.9.9"
        ar.data["Results"][0]["Vulnerabilities"].append(dup_vuln)

        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        self.assertIn("DUPLICATE_IDENTITY", [r.code for r in res.global_reasons])
        dup_r = [r for r in res.global_reasons if r.code == "DUPLICATE_IDENTITY"][0]
        self.assertIn("/Results/0/Vulnerabilities/0", [ref.pointer for ref in dup_r.refs])
        self.assertIn("/Results/0/Vulnerabilities/1", [ref.pointer for ref in dup_r.refs])

    def test_distinct_paths_separate_identities(self) -> None:
        """Different PkgPath on same package and vulnerability creates separate identities."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        # Add another finding with distinct PkgPath in before report
        second_vuln = copy.deepcopy(br.data["Results"][0]["Vulnerabilities"][0])
        second_vuln["PkgPath"] = "app/sub/package-lock.json"
        br.data["Results"][0]["Vulnerabilities"].append(second_vuln)

        res = compare_manifests_and_reports(bm, am, br, ar)
        # Should not trigger DUPLICATE_IDENTITY because paths differ
        self.assertNotIn("DUPLICATE_IDENTITY", [r.code for r in res.global_reasons])

    def test_missing_or_empty_package_name_and_vulnerability_id(self) -> None:
        """Empty or missing PkgName/VulnerabilityID triggers IDENTITY_MISSING with exact pointers."""
        # 1. Empty PkgName (present but empty -> points to child /PkgName)
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        br.data["Results"][0]["Vulnerabilities"][0]["PkgName"] = ""
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        self.assertIn("IDENTITY_MISSING", [r.code for r in res.global_reasons])
        missing_r = [r for r in res.global_reasons if r.code == "IDENTITY_MISSING"][0]
        self.assertEqual(missing_r.refs[0].pointer, "/Results/0/Vulnerabilities/0/PkgName")
        null_id_items = [it for it in res.items if it.identity is None]
        self.assertEqual(len(null_id_items), 1)
        self.assertEqual(null_id_items[0].before_pointers, ["/Results/0/Vulnerabilities/0"])

        # 2. Omitted PkgName (missing -> points to parent /Results/0/Vulnerabilities/0)
        bm2, am2, br2, ar2 = self.load_fixture_inputs("fixtures/01/array-order-only")
        del br2.data["Results"][0]["Vulnerabilities"][0]["PkgName"]
        res2 = compare_manifests_and_reports(bm2, am2, br2, ar2)
        missing_r2 = [r for r in res2.global_reasons if r.code == "IDENTITY_MISSING"][0]
        self.assertEqual(missing_r2.refs[0].pointer, "/Results/0/Vulnerabilities/0")

        # 3. Empty VulnerabilityID (present but empty -> points to child /VulnerabilityID)
        bm3, am3, br3, ar3 = self.load_fixture_inputs("fixtures/01/array-order-only")
        br3.data["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = ""
        res3 = compare_manifests_and_reports(bm3, am3, br3, ar3)
        missing_r3 = [r for r in res3.global_reasons if r.code == "IDENTITY_MISSING"][0]
        self.assertEqual(missing_r3.refs[0].pointer, "/Results/0/Vulnerabilities/0/VulnerabilityID")

        # 4. Omitted VulnerabilityID (missing -> points to parent /Results/0/Vulnerabilities/0)
        bm4, am4, br4, ar4 = self.load_fixture_inputs("fixtures/01/array-order-only")
        del br4.data["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"]
        res4 = compare_manifests_and_reports(bm4, am4, br4, ar4)
        missing_r4 = [r for r in res4.global_reasons if r.code == "IDENTITY_MISSING"][0]
        self.assertEqual(missing_r4.refs[0].pointer, "/Results/0/Vulnerabilities/0")

    def test_scope_first_match_rejection_and_validation(self) -> None:
        """When multiple scopes match or scope has invalid field, identity is null."""
        # 1. Multiple matching scopes for same Result
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        dup_scope = copy.deepcopy(bm.data["target"]["scopes"][0])
        bm.data["target"]["scopes"].append(dup_scope)
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        self.assertTrue(any(it.identity is None for it in res.items))

        # 2. Scope has invalid field (e.g. empty logicalTargetId)
        bm2, am2, br2, ar2 = self.load_fixture_inputs("fixtures/01/array-order-only")
        bm2.data["target"]["scopes"][0]["logicalTargetId"] = ""
        res2 = compare_manifests_and_reports(bm2, am2, br2, ar2)
        self.assertEqual(res2.comparison, "comparison_unavailable")
        self.assertTrue(any(it.identity is None for it in res2.items))

    def test_extract_purl_strictly_pkg_identifier_string(self) -> None:
        """_extract_purl only keeps string from PkgIdentifier.PURL without str() or top-level fallback."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        # Top-level PURL only should not be extracted
        vuln = br.data["Results"][0]["Vulnerabilities"][0]
        del vuln["PkgIdentifier"]
        vuln["PURL"] = "pkg:npm/top-level@1.0.0"
        res = compare_manifests_and_reports(bm, am, br, ar)
        item = [it for it in res.items if it.before and it.before[0].source.pointer == "/Results/0/Vulnerabilities/0"][0]
        self.assertIsNone(item.before[0].purl)

        # Non-string PkgIdentifier.PURL (e.g. integer) should not be converted to string
        bm2, am2, br2, ar2 = self.load_fixture_inputs("fixtures/01/array-order-only")
        br2.data["Results"][0]["Vulnerabilities"][0]["PkgIdentifier"]["PURL"] = 12345
        res2 = compare_manifests_and_reports(bm2, am2, br2, ar2)
        item2 = [it for it in res2.items if it.before and it.before[0].source.pointer == "/Results/0/Vulnerabilities/0"][0]
        self.assertIsNone(item2.before[0].purl)

    def test_empty_side_coverage_exact_4field_tuple_matching(self) -> None:
        """Empty side coverage resolution must match 4-field tuple and not fallback to index 0."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/02/one-new")
        # In case 2, there is a new finding in after report
        res = compare_manifests_and_reports(bm, am, br, ar)
        new_item = [it for it in res.items if it.classification == "new"][0]
        # Opposing coverage ref should point to the matching scope
        cov_refs = [r for r in new_item.reasons[0].refs if r.pointer.endswith("/coverage")]
        self.assertEqual(len(cov_refs), 1)
        self.assertEqual(cov_refs[0].pointer, "/target/scopes/0/coverage")

    def test_invalid_path_pattern(self) -> None:
        """Path with leading slash, backslash, or .. triggers IDENTITY_PATH_INVALID."""
        invalid_paths = ["/app/package-lock.json", "app\\package-lock.json", "app/../package-lock.json"]
        for p in invalid_paths:
            with self.subTest(invalid_path=p):
                bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
                br.data["Results"][0]["Vulnerabilities"][0]["PkgPath"] = p
                res = compare_manifests_and_reports(bm, am, br, ar)
                self.assertEqual(res.comparison, "comparison_unavailable")
                self.assertIn("IDENTITY_PATH_INVALID", [r.code for r in res.global_reasons])
                self.assertTrue(any(it.identity is None for it in res.items))

    def test_manifest_missing_scopes_preserves_candidate_findings(self) -> None:
        """When manifest has no scopes at all, candidates are still preserved with identity=null."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        bm.data["target"]["scopes"] = []
        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        # All findings in before report cannot resolve scopes, thus identity=null
        unresolved = [it for it in res.items if it.identity is None and it.before_pointers]
        self.assertEqual(len(unresolved), 2)

    def test_both_reports_broken(self) -> None:
        """When both reports are broken, items=[], observedCounts={before: None, after: None}."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        br.parse_state = "invalid_json"
        br.data = None
        ar.parse_state = "invalid_json"
        ar.data = None

        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        self.assertEqual(res.observed_counts, {"before": None, "after": None})
        self.assertEqual(res.items, [])
        self.assertEqual(res.summary, {"new": 0, "persistent": 0, "not_detected": 0, "comparison_unavailable": 0})

    def test_findings_total_count_limit_100000(self) -> None:
        """When total raw findings exceed 100,000, INPUT_LIMIT_EXCEEDED is triggered."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only")
        # Synthesize a large number of findings in before report
        base_vuln = ar.data["Results"][0]["Vulnerabilities"][0]
        # Multiply vulnerabilities to 100,001
        large_vulns = [base_vuln] * 100_001
        ar.data["Results"][0]["Vulnerabilities"] = large_vulns

        res = compare_manifests_and_reports(bm, am, br, ar)
        self.assertEqual(res.comparison, "comparison_unavailable")
        self.assertIn("INPUT_LIMIT_EXCEEDED", [r.code for r in res.global_reasons])


if __name__ == "__main__":
    unittest.main()
