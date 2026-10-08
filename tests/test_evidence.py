from __future__ import annotations

import copy
import json
import math
from pathlib import Path
from typing import Any
import unittest

from trivy_remediation_evidence.comparator import compare_manifests_and_reports
from trivy_remediation_evidence.evidence import (
    build_evidence_dict,
    build_scan_evidence,
    canonical_json_bytes,
    canonical_json_dumps,
    run_pipeline,
)
from trivy_remediation_evidence.models import SourceInput
from trivy_remediation_evidence.reader import read_source_file
from trivy_remediation_evidence.reasons import InputRef, Reason
from trivy_remediation_evidence.validator import (
    DEFAULT_SCHEMAS_DIR,
    HAS_JSONSCHEMA,
    PACKAGE_SCHEMAS_DIR,
    get_validator,
    validate_source,
)


def _resolve_json_pointer(doc: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON pointer against doc."""
    if pointer == "":
        return doc
    parts = pointer.strip("/").split("/")
    cur = doc
    for p in parts:
        p = p.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            idx = int(p)
            cur = cur[idx]
        elif isinstance(cur, dict):
            cur = cur[p]
        else:
            raise KeyError(f"Cannot resolve part {p} in {type(cur)}")
    return cur


class TestEvidence(unittest.TestCase):
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

    # --- 1. Deterministic canonical JSON serialization ---

    def test_canonical_json_formatting_and_determinism(self) -> None:
        """JSON output must be UTF-8 no BOM, 2-space indent, LF, sorted keys, ensure_ascii=False."""
        data = {
            "title": "日本語タイトル",
            "count": 42,
            "alpha": ["b", "a"],
            "nested": {"z": 1, "a": 2},
        }
        dumped = canonical_json_dumps(data)
        raw_bytes = canonical_json_bytes(data)

        # Check LF line ending
        self.assertTrue(dumped.endswith("\n"))
        self.assertNotIn("\r\n", dumped)

        # Check UTF-8 without BOM
        self.assertFalse(raw_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(raw_bytes.decode("utf-8"), dumped)

        # Check key sorting
        lines = dumped.splitlines()
        self.assertTrue(lines[1].strip().startswith('"alpha":'))
        self.assertTrue(lines[5].strip().startswith('"count":'))
        self.assertTrue(lines[6].strip().startswith('"nested":'))
        self.assertTrue(lines[10].strip().startswith('"title":'))

        # Check non-ascii characters are not escaped
        self.assertIn("日本語タイトル", dumped)

    def test_canonical_json_non_finite_rejected(self) -> None:
        """NaN and Infinity must be rejected during canonical JSON serialization."""
        with self.assertRaises(ValueError):
            canonical_json_dumps({"val": float("nan")})

        with self.assertRaises(ValueError):
            canonical_json_dumps({"val": float("inf")})

        with self.assertRaises(ValueError):
            canonical_json_dumps({"val": float("-inf")})

    def test_reexecution_bytes_identical(self) -> None:
        """Re-running pipeline on same inputs produces identical bytes."""
        if not HAS_JSONSCHEMA:
            self.skipTest("Requires jsonschema for run_pipeline")
        folder = Path("outputs/fixtures/01/array-order-only")
        _, exit1, bytes1 = run_pipeline(
            folder / "before.json",
            folder / "after.json",
            folder / "before.manifest.json",
            folder / "after.manifest.json",
        )
        _, exit2, bytes2 = run_pipeline(
            folder / "before.json",
            folder / "after.json",
            folder / "before.manifest.json",
            folder / "after.manifest.json",
        )
        self.assertEqual(bytes1, bytes2)
        self.assertEqual(exit1, exit2)

    # --- 2. Sources fixed order and scanEvidence normalization ---

    def test_sources_fixed_order(self) -> None:
        """Sources array must be strictly: 1. before report, 2. before manifest, 3. after report, 4. after manifest."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only", run_validate=False)
        ev = build_evidence_dict(bm, am, br, ar)
        sources = ev["sources"]
        self.assertEqual(len(sources), 4)
        self.assertEqual(sources[0]["side"], "before")
        self.assertEqual(sources[0]["kind"], "report")
        self.assertEqual(sources[1]["side"], "before")
        self.assertEqual(sources[1]["kind"], "manifest")
        self.assertEqual(sources[2]["side"], "after")
        self.assertEqual(sources[2]["kind"], "report")
        self.assertEqual(sources[3]["side"], "after")
        self.assertEqual(sources[3]["kind"], "manifest")

    def test_scan_evidence_normalization_and_unknown_fields_dropped(self) -> None:
        """scanEvidence must normalize sets/roles/scopes and drop unknown report metadata fields."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only", run_validate=False)
        # Inject unknown field in report Metadata
        br.data["Metadata"]["UnknownExtraField"] = "should_not_appear"

        ev = build_evidence_dict(bm, am, br, ar)
        before_scan = ev["scanEvidence"]["before"]
        self.assertIsNotNone(before_scan)

        # Check unknown report metadata field is dropped
        self.assertEqual(set(before_scan["reportMetadata"].keys()), {"imageId", "repoDigests"})
        self.assertNotIn("UnknownExtraField", before_scan["reportMetadata"])

        # Check repoDigests is sorted
        self.assertEqual(
            before_scan["reportMetadata"]["repoDigests"],
            sorted(before_scan["reportMetadata"]["repoDigests"]),
        )

        # Check effectiveConfig sets are sorted
        ec = before_scan["effectiveConfig"]
        self.assertEqual(ec["scanners"], sorted(ec["scanners"]))
        self.assertEqual(ec["severity"], sorted(ec["severity"]))
        self.assertEqual(ec["packageTypes"], sorted(ec["packageTypes"]))

        # Check databases are sorted by role
        roles = [db["role"] for db in before_scan["databases"]]
        self.assertEqual(roles, sorted(roles))

        # Check scopes are sorted by 4-field tuple
        scope_tuples = [
            (sc["logicalTargetId"], sc["path"], sc["class"], sc["ecosystem"])
            for sc in before_scan["target"]["scopes"]
        ]
        self.assertEqual(scope_tuples, sorted(scope_tuples))

    def test_invalid_manifest_produces_null_scan_evidence(self) -> None:
        """When manifest parseState is invalid, its scanEvidence must be null."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only", run_validate=False)
        bm.parse_state = "invalid_schema"
        bm.data = None

        ev = build_evidence_dict(bm, am, br, ar)
        self.assertIsNone(ev["scanEvidence"]["before"])
        self.assertIsNotNone(ev["scanEvidence"]["after"])

    def test_broken_report_metadata_handling(self) -> None:
        """When report parseState is invalid, reportMetadata in scanEvidence has imageId=None and repoDigests=[]."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only", run_validate=False)
        ar.parse_state = "invalid_json"
        ar.data = None

        ev = build_evidence_dict(bm, am, br, ar)
        after_scan = ev["scanEvidence"]["after"]
        self.assertIsNotNone(after_scan)
        self.assertIsNone(after_scan["reportMetadata"]["imageId"])
        self.assertEqual(after_scan["reportMetadata"]["repoDigests"], [])

    # --- 3. Cross-field, count, and pointer resolution integrity ---

    def test_cross_field_and_count_consistency(self) -> None:
        """Summary counts must match items classification counts, and observedCounts match raw findings."""
        for variant_folder in [
            "fixtures/01/array-order-only",
            "fixtures/02/one-new",
            "fixtures/03/one-not-detected",
            "fixtures/05/ambiguous-duplicate",
            "fixtures/08/broken-json",
        ]:
            with self.subTest(folder=variant_folder):
                bm, am, br, ar = self.load_fixture_inputs(variant_folder, run_validate=False)
                ev = build_evidence_dict(bm, am, br, ar)

                summary = ev["summary"]
                items = ev["items"]

                # Total items match summary sum
                self.assertEqual(len(items), sum(summary.values()))

                # Each category count matches
                for cat in ["new", "persistent", "not_detected", "comparison_unavailable"]:
                    actual_count = sum(1 for it in items if it["classification"] == cat)
                    self.assertEqual(actual_count, summary[cat])

    def test_all_reason_pointers_resolvable_in_source_documents(self) -> None:
        """All JSON pointers in globalReasons and item.reasons must resolve in actual source inputs."""
        for variant_folder in [
            "fixtures/01/array-order-only",
            "fixtures/02/one-new",
            "fixtures/03/one-not-detected",
            "fixtures/05/ambiguous-duplicate",
            "fixtures/06/scope-missing",
            "fixtures/07/scanner-changed",
            "fixtures/08/execution-failed",
        ]:
            with self.subTest(folder=variant_folder):
                bm, am, br, ar = self.load_fixture_inputs(variant_folder, run_validate=False)
                ev = build_evidence_dict(bm, am, br, ar)

                doc_map = {
                    ("before", "manifest"): bm.data,
                    ("after", "manifest"): am.data,
                    ("before", "report"): br.data,
                    ("after", "report"): ar.data,
                }

                # Collect all refs from globalReasons and items
                all_refs = [ref for r in ev["globalReasons"] for ref in r["refs"]]
                for it in ev["items"]:
                    for r in it["reasons"]:
                        all_refs.extend(r["refs"])

                for ref in all_refs:
                    side = ref["side"]
                    kind = ref["kind"]
                    ptr = ref["pointer"]
                    doc = doc_map.get((side, kind))
                    if doc is not None:
                        # Should not raise exception
                        try:
                            resolved = _resolve_json_pointer(doc, ptr)
                            self.assertIsNotNone(resolved)
                        except (KeyError, IndexError) as err:
                            self.fail(f"Pointer {ptr} failed to resolve in {side} {kind}: {err}")

    def test_null_and_empty_preservation_in_observations(self) -> None:
        """Omitted fields must be null, empty strings must remain empty strings."""
        bm, am, br, ar = self.load_fixture_inputs("fixtures/01/array-order-only", run_validate=False)
        vuln = br.data["Results"][0]["Vulnerabilities"][0]
        vuln["PkgPath"] = ""  # Explicit empty string
        del vuln["FixedVersion"]  # Omitted -> null

        ev = build_evidence_dict(bm, am, br, ar)
        item = ev["items"][0]
        obs = item["before"][0]
        self.assertEqual(obs["pkgPath"], "")
        self.assertIsNone(obs["fixedVersion"])

    def test_packaged_schemas_directory_available(self) -> None:
        """Packaged schemas directory must exist and contain required schema files."""
        self.assertTrue(PACKAGE_SCHEMAS_DIR.exists())
        self.assertTrue((PACKAGE_SCHEMAS_DIR / "evidence.schema.json").exists())
        self.assertTrue((PACKAGE_SCHEMAS_DIR / "manifest.schema.json").exists())
        self.assertTrue((PACKAGE_SCHEMAS_DIR / "report.schema.json").exists())
        self.assertTrue((PACKAGE_SCHEMAS_DIR / "reason-catalog.json").exists())

    # --- 4. Schema validation with jsonschema (Python 3.10 auxiliary verification) ---

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema required for evidence schema validation")
    def test_evidence_schema_validation_all_20_variants(self) -> None:
        """Validate generated evidence JSON for all 20 fixture variants against evidence.schema.json."""
        validator = get_validator("evidence")
        with open(self.fixtures_dir / "index.json", encoding="utf-8") as f:
            index = json.load(f)

        for entry in index:
            folder = Path("outputs") / entry["folder"]
            variant_name = entry["variant"]

            ev_dict, exit_code, raw_bytes = run_pipeline(
                before_report_path=folder / "before.json",
                after_report_path=folder / "after.json",
                before_manifest_path=folder / "before.manifest.json",
                after_manifest_path=folder / "after.manifest.json",
            )

            # Validate against evidence.schema.json
            validator.validate(ev_dict)

            # Re-read raw expected to verify exit code
            exp = json.loads((folder / "expected.json").read_bytes())
            self.assertEqual(exit_code, exp["cliExitCode"], f"Exit code mismatch in {variant_name}")


if __name__ == "__main__":
    unittest.main()
