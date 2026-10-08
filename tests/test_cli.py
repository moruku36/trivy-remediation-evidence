from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from trivy_remediation_evidence.cli import _check_conflicts_and_existence, main
from trivy_remediation_evidence.evidence import canonical_json_bytes, run_pipeline
from trivy_remediation_evidence.renderer import render_markdown
from trivy_remediation_evidence.validator import (
    HAS_JSONSCHEMA,
    OUTPUTS_SCHEMAS_DIR,
    PACKAGE_SCHEMAS_DIR,
    MissingDependencyError,
    validate_evidence,
)


class TestCliUnit(unittest.TestCase):
    def test_cli_help(self) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                code = main(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("trivy-remediation-evidence", mock_out.getvalue())

    def test_cli_compare_help(self) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                code = main(["compare", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("--before", mock_out.getvalue())

    def test_cli_invalid_args_quiet(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            code = main(["compare"])
        self.assertEqual(code, 1)
        self.assertEqual(mock_err.getvalue(), "Error: Invalid arguments.\n")

    def test_cli_output_already_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            out_dir.mkdir()
            existing_file = out_dir / "evidence.json"
            existing_file.write_text("existing content", encoding="utf-8")

            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                code = main([
                    "compare",
                    "--before", "outputs/fixtures/01/case01-normal/before.json",
                    "--after", "outputs/fixtures/01/case01-normal/after.json",
                    "--before-manifest", "outputs/fixtures/01/case01-normal/before.manifest.json",
                    "--after-manifest", "outputs/fixtures/01/case01-normal/after.manifest.json",
                    "--out-dir", str(out_dir),
                ])
            self.assertEqual(code, 1)
            self.assertEqual(mock_err.getvalue(), "Error: Output already exists or path conflict.\n")
            # Existing file must not be modified or deleted
            self.assertEqual(existing_file.read_text(encoding="utf-8"), "existing content")

    def test_cli_path_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            # Use an input that is directly in out_dir with name evidence.json
            fake_before = out_dir / "evidence.json"
            fake_before.write_text("fake before", encoding="utf-8")

            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                code = main([
                    "compare",
                    "--before", str(fake_before),
                    "--after", "outputs/fixtures/01/case01-normal/after.json",
                    "--before-manifest", "outputs/fixtures/01/case01-normal/before.manifest.json",
                    "--after-manifest", "outputs/fixtures/01/case01-normal/after.manifest.json",
                    "--out-dir", str(out_dir),
                ])
            self.assertEqual(code, 1)
            self.assertEqual(mock_err.getvalue(), "Error: Output already exists or path conflict.\n")

    def test_unknown_flag_schemas_dir_rejected(self) -> None:
        """Verify that removed/unknown flag --schemas-dir is rejected with exit code 1."""
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            code = main([
                "compare",
                "--before", "outputs/fixtures/01/array-order-only/before.json",
                "--after", "outputs/fixtures/01/array-order-only/after.json",
                "--before-manifest", "outputs/fixtures/01/array-order-only/before.manifest.json",
                "--after-manifest", "outputs/fixtures/01/array-order-only/after.manifest.json",
                "--out-dir", "dummy_out",
                "--schemas-dir", "custom/schemas",
            ])
        self.assertEqual(code, 1)
        self.assertEqual(mock_err.getvalue(), "Error: Invalid arguments.\n")

    def test_publish_failure_write_partial_bytes(self) -> None:
        """Verify rollback when failure happens after writing partial bytes to disk."""
        if not HAS_JSONSCHEMA:
            self.skipTest("Requires jsonschema for full pipeline execution")
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            v_dir = Path("outputs/fixtures/01/array-order-only")

            original_open = open

            class PartialWriteFile:
                def __init__(self, real_file: Any) -> None:
                    self._real = real_file

                def write(self, data: bytes) -> int:
                    # Write partial bytes then fail
                    self._real.write(data[:10])
                    self._real.flush()
                    raise OSError("Simulated partial write failure")

                def flush(self) -> None:
                    self._real.flush()

                def close(self) -> None:
                    self._real.close()

                def __enter__(self) -> Any:
                    return self

                def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                    self.close()

            def mock_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
                f = original_open(file, mode, *args, **kwargs)
                # Intercept fd-based write when publishing evidence.json
                if isinstance(file, int) and "w" in mode:
                    return PartialWriteFile(f)
                return f

            with patch("builtins.open", side_effect=mock_open):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    code = main([
                        "compare",
                        "--before", str(v_dir / "before.json"),
                        "--after", str(v_dir / "after.json"),
                        "--before-manifest", str(v_dir / "before.manifest.json"),
                        "--after-manifest", str(v_dir / "after.manifest.json"),
                        "--out-dir", str(out_dir),
                    ])
            self.assertEqual(code, 1)
            self.assertEqual(mock_err.getvalue(), "Error: Failed to write outputs.\n")
            # Evidence file was partially written, must be completely rolled back (deleted)
            self.assertFalse((out_dir / "evidence.json").exists())
            self.assertFalse((out_dir / "report.ja.md").exists())
            self.assertFalse((out_dir / "report.en.md").exists())

    def test_publish_failure_close(self) -> None:
        """Verify rollback when failure happens during close of published file."""
        if not HAS_JSONSCHEMA:
            self.skipTest("Requires jsonschema for full pipeline execution")
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            v_dir = Path("outputs/fixtures/01/array-order-only")

            original_open = open

            class CloseFailFile:
                def __init__(self, real_file: Any) -> None:
                    self._real = real_file

                def write(self, data: bytes) -> int:
                    return self._real.write(data)

                def flush(self) -> None:
                    self._real.flush()

                def close(self) -> None:
                    self._real.close()
                    raise OSError("Simulated close error")

                def __enter__(self) -> Any:
                    return self

                def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                    self.close()

            def mock_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
                f = original_open(file, mode, *args, **kwargs)
                if isinstance(file, int) and "w" in mode:
                    return CloseFailFile(f)
                return f

            with patch("builtins.open", side_effect=mock_open):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    code = main([
                        "compare",
                        "--before", str(v_dir / "before.json"),
                        "--after", str(v_dir / "after.json"),
                        "--before-manifest", str(v_dir / "before.manifest.json"),
                        "--after-manifest", str(v_dir / "after.manifest.json"),
                        "--out-dir", str(out_dir),
                    ])
            self.assertEqual(code, 1)
            self.assertEqual(mock_err.getvalue(), "Error: Failed to write outputs.\n")
            self.assertFalse((out_dir / "evidence.json").exists())

    def test_publish_failure_second_file(self) -> None:
        """Verify that when 2nd file fails to publish, both 1st and 2nd files are rolled back."""
        if not HAS_JSONSCHEMA:
            self.skipTest("Requires jsonschema for full pipeline execution")
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            out_dir.mkdir()
            v_dir = Path("outputs/fixtures/01/array-order-only")

            original_open_os = os.open

            def mock_os_open(path: Any, flags: int, mode: int = 0o777) -> int:
                # 2nd file is report.ja.md
                if str(path).endswith("report.ja.md"):
                    raise OSError("Simulated 2nd file publish failure")
                return original_open_os(path, flags, mode)

            with patch("os.open", side_effect=mock_os_open):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    code = main([
                        "compare",
                        "--before", str(v_dir / "before.json"),
                        "--after", str(v_dir / "after.json"),
                        "--before-manifest", str(v_dir / "before.manifest.json"),
                        "--after-manifest", str(v_dir / "after.manifest.json"),
                        "--out-dir", str(out_dir),
                    ])
            self.assertEqual(code, 1)
            self.assertEqual(mock_err.getvalue(), "Error: Failed to write outputs.\n")
            # 1st file (evidence.json) must be rolled back (deleted)
            self.assertFalse((out_dir / "evidence.json").exists())
            self.assertFalse((out_dir / "report.ja.md").exists())
            self.assertFalse((out_dir / "report.en.md").exists())

    def test_staging_cleanup_always(self) -> None:
        """Verify staging directory is cleaned up on both success and failure."""
        if not HAS_JSONSCHEMA:
            self.skipTest("Requires jsonschema for full pipeline execution")
        v_dir = Path("outputs/fixtures/01/array-order-only")

        created_staging_dirs: list[str] = []
        original_tempdir = tempfile.TemporaryDirectory

        class MonitoredTempDir(tempfile.TemporaryDirectory):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                created_staging_dirs.append(self.name)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            with patch("tempfile.TemporaryDirectory", side_effect=MonitoredTempDir):
                code = main([
                    "compare",
                    "--before", str(v_dir / "before.json"),
                    "--after", str(v_dir / "after.json"),
                    "--before-manifest", str(v_dir / "before.manifest.json"),
                    "--after-manifest", str(v_dir / "after.manifest.json"),
                    "--out-dir", str(out_dir),
                ])
            self.assertEqual(code, 0)
            self.assertTrue(len(created_staging_dirs) >= 1)
            for d in created_staging_dirs:
                self.assertFalse(os.path.exists(d), f"Staging directory was not cleaned up: {d}")

    def test_missing_dependency_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"

            with patch("trivy_remediation_evidence.evidence.HAS_JSONSCHEMA", False):
                # 1. run_pipeline directly raises MissingDependencyError
                with self.assertRaises(MissingDependencyError) as ctx:
                    run_pipeline(
                        before_report_path="outputs/fixtures/01/array-order-only/before.json",
                        after_report_path="outputs/fixtures/01/array-order-only/after.json",
                        before_manifest_path="outputs/fixtures/01/array-order-only/before.manifest.json",
                        after_manifest_path="outputs/fixtures/01/array-order-only/after.manifest.json",
                    )
                self.assertIn("jsonschema", str(ctx.exception))
                # Ensure no input echo in exception
                self.assertNotIn("array-order-only", str(ctx.exception))

            with patch("trivy_remediation_evidence.cli.run_pipeline", side_effect=MissingDependencyError("Missing required dependency: jsonschema")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    code = main([
                        "compare",
                        "--before", "outputs/fixtures/01/array-order-only/before.json",
                        "--after", "outputs/fixtures/01/array-order-only/after.json",
                        "--before-manifest", "outputs/fixtures/01/array-order-only/before.manifest.json",
                        "--after-manifest", "outputs/fixtures/01/array-order-only/after.manifest.json",
                        "--out-dir", str(out_dir),
                    ])
                self.assertEqual(code, 1)
                self.assertEqual(mock_err.getvalue(), "Error: Missing required dependency: jsonschema.\n")
                self.assertFalse(out_dir.exists())

    def test_package_assets_byte_match(self) -> None:
        """Verify that bundled schemas in package exactly match outputs/schemas/ contract."""
        schema_files = [
            "manifest.schema.json",
            "report.schema.json",
            "evidence.schema.json",
            "reason-catalog.json",
            "README.md",
        ]
        for fname in schema_files:
            pkg_file = PACKAGE_SCHEMAS_DIR / fname
            out_file = OUTPUTS_SCHEMAS_DIR / fname
            self.assertTrue(pkg_file.exists(), f"Missing package schema: {pkg_file}")
            self.assertTrue(out_file.exists(), f"Missing output schema: {out_file}")
            pkg_bytes = pkg_file.read_bytes()
            out_bytes = out_file.read_bytes()
            self.assertEqual(
                pkg_bytes,
                out_bytes,
                f"Byte mismatch between package and contract schema for {fname}",
            )


class TestCliE2E(unittest.TestCase):
    def setUp(self) -> None:
        if not HAS_JSONSCHEMA:
            self.skipTest("Requires jsonschema for full E2E pipeline verification")

    def test_all_20_variants_e2e(self) -> None:
        fixtures_idx = Path("outputs/fixtures/index.json")
        if not fixtures_idx.exists():
            self.skipTest("fixtures/index.json not found")

        meta = json.loads(fixtures_idx.read_text(encoding="utf-8"))
        variants = meta if isinstance(meta, list) else meta.get("variants", [])
        self.assertEqual(len(variants), 20)

        for v in variants:
            v_dir = Path("outputs") / v["folder"]
            expected_file = v_dir / "expected.json"
            expected_data = json.loads(expected_file.read_text(encoding="utf-8"))

            with tempfile.TemporaryDirectory() as tmp_dir:
                out_dir = Path(tmp_dir) / "out"

                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    exit_code = main([
                        "compare",
                        "--before", str(v_dir / "before.json"),
                        "--after", str(v_dir / "after.json"),
                        "--before-manifest", str(v_dir / "before.manifest.json"),
                        "--after-manifest", str(v_dir / "after.manifest.json"),
                        "--out-dir", str(out_dir),
                    ])

                expected_comparison = expected_data.get("comparison")
                expected_exit = 0 if expected_comparison == "comparable" else 2
                self.assertEqual(
                    exit_code,
                    expected_exit,
                    f"Variant {v['variant']} exit code mismatch: got {exit_code}, expected {expected_exit}. stderr: {mock_err.getvalue()}",
                )

                # 3 files must exist
                ev_file = out_dir / "evidence.json"
                ja_file = out_dir / "report.ja.md"
                en_file = out_dir / "report.en.md"
                self.assertTrue(ev_file.exists(), f"Missing evidence.json for {v['variant']}")
                self.assertTrue(ja_file.exists(), f"Missing report.ja.md for {v['variant']}")
                self.assertTrue(en_file.exists(), f"Missing report.en.md for {v['variant']}")

                # Validate evidence JSON with evidence.schema.json
                ev_data = json.loads(ev_file.read_text(encoding="utf-8"))
                validate_evidence(ev_data)

                # Check comparison state and oracle counts
                self.assertEqual(ev_data["comparison"], expected_comparison)
                self.assertEqual(ev_data["summary"], expected_data["summary"])
                self.assertEqual(ev_data["observedCounts"], expected_data["observedCounts"])
                self.assertEqual(len(ev_data["items"]), len(expected_data["items"]))

                # Check JA/EN report content
                ja_text = ja_file.read_text(encoding="utf-8")
                en_text = en_file.read_text(encoding="utf-8")
                self.assertTrue(ja_text.startswith("# Trivy脆弱性比較の証拠\n\n"))
                self.assertTrue(en_text.startswith("# Trivy vulnerability comparison evidence\n\n"))
                self.assertTrue(ja_text.endswith("\n"))
                self.assertTrue(en_text.endswith("\n"))

    def test_deterministic_output_two_runs(self) -> None:
        """Run twice on same input and verify all 3 output files have exact same bytes."""
        v_dir = Path("outputs/fixtures/03/one-not-detected")

        with tempfile.TemporaryDirectory() as tmp_dir1, tempfile.TemporaryDirectory() as tmp_dir2:
            out1 = Path(tmp_dir1) / "out"
            out2 = Path(tmp_dir2) / "out"

            code1 = main([
                "compare",
                "--before", str(v_dir / "before.json"),
                "--after", str(v_dir / "after.json"),
                "--before-manifest", str(v_dir / "before.manifest.json"),
                "--after-manifest", str(v_dir / "after.manifest.json"),
                "--out-dir", str(out1),
            ])
            code2 = main([
                "compare",
                "--before", str(v_dir / "before.json"),
                "--after", str(v_dir / "after.json"),
                "--before-manifest", str(v_dir / "before.manifest.json"),
                "--after-manifest", str(v_dir / "after.manifest.json"),
                "--out-dir", str(out2),
            ])

            self.assertEqual(code1, 0)
            self.assertEqual(code2, 0)

            for fname in ("evidence.json", "report.ja.md", "report.en.md"):
                b1 = (out1 / fname).read_bytes()
                b2 = (out2 / fname).read_bytes()
                self.assertEqual(b1, b2, f"Byte mismatch across runs for {fname}")

    def test_package_assets_from_arbitrary_cwd(self) -> None:
        """Verify that schemas and catalog can be loaded when cwd is completely outside project root."""
        orig_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as foreign_dir:
            try:
                os.chdir(foreign_dir)
                from trivy_remediation_evidence.validator import get_validator
                from trivy_remediation_evidence.renderer import load_reason_catalog

                # Should load bundled schemas without error
                val_m = get_validator("manifest")
                self.assertIsNotNone(val_m)
                val_e = get_validator("evidence")
                self.assertIsNotNone(val_e)

                cat = load_reason_catalog()
                self.assertIn("INPUT_INVALID_JSON", cat)
            finally:
                os.chdir(orig_cwd)

    def test_locale_independence(self) -> None:
        """Verify that running CLI with different locale env variables produces identical bytes."""
        v_dir = Path("outputs/fixtures/01/array-order-only")

        with tempfile.TemporaryDirectory() as tmp_dir1, tempfile.TemporaryDirectory() as tmp_dir2:
            out1 = Path(tmp_dir1) / "out"
            out2 = Path(tmp_dir2) / "out"

            with patch.dict(os.environ, {"LC_ALL": "C", "LANG": "C"}):
                code1 = main([
                    "compare",
                    "--before", str(v_dir / "before.json"),
                    "--after", str(v_dir / "after.json"),
                    "--before-manifest", str(v_dir / "before.manifest.json"),
                    "--after-manifest", str(v_dir / "after.manifest.json"),
                    "--out-dir", str(out1),
                ])

            with patch.dict(os.environ, {"LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"}):
                code2 = main([
                    "compare",
                    "--before", str(v_dir / "before.json"),
                    "--after", str(v_dir / "after.json"),
                    "--before-manifest", str(v_dir / "before.manifest.json"),
                    "--after-manifest", str(v_dir / "after.manifest.json"),
                    "--out-dir", str(out2),
                ])

            self.assertEqual(code1, 0)
            self.assertEqual(code2, 0)
            for fname in ("evidence.json", "report.ja.md", "report.en.md"):
                self.assertEqual(
                    (out1 / fname).read_bytes(),
                    (out2 / fname).read_bytes(),
                    f"Locale caused difference in {fname}",
                )

    def test_broken_json_and_manifest_missing_cli(self) -> None:
        """Verify broken-json and manifest-missing variants via CLI end-to-end."""
        # 1. Broken JSON variant (fixtures/08/broken-json)
        v_dir_broken = Path("outputs/fixtures/08/broken-json")
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            code = main([
                "compare",
                "--before", str(v_dir_broken / "before.json"),
                "--after", str(v_dir_broken / "after.json"),
                "--before-manifest", str(v_dir_broken / "before.manifest.json"),
                "--after-manifest", str(v_dir_broken / "after.manifest.json"),
                "--out-dir", str(out_dir),
            ])
            self.assertEqual(code, 2)
            ev = json.loads((out_dir / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(ev["comparison"], "comparison_unavailable")
            self.assertEqual(ev["observedCounts"]["after"], None)
            self.assertEqual(ev["observedCounts"]["before"], 1)
            self.assertIn("INPUT_INVALID_JSON", [r["code"] for r in ev["globalReasons"]])

        # 2. Manifest missing variant (fixtures/07/manifest-missing)
        v_dir_missing = Path("outputs/fixtures/07/manifest-missing")
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "out"
            code = main([
                "compare",
                "--before", str(v_dir_missing / "before.json"),
                "--after", str(v_dir_missing / "after.json"),
                "--before-manifest", str(v_dir_missing / "before.manifest.json"),
                "--after-manifest", str(v_dir_missing / "after.manifest.json"),
                "--out-dir", str(out_dir),
            ])
            self.assertEqual(code, 2)
            ev = json.loads((out_dir / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(ev["comparison"], "comparison_unavailable")
            self.assertIn("MANIFEST_REQUIRED_MISSING", [r["code"] for r in ev["globalReasons"]])
            # Scan evidence for after should be null because manifest is invalid
            self.assertIsNone(ev["scanEvidence"]["after"])


if __name__ == "__main__":
    unittest.main()

