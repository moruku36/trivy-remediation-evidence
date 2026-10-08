from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from trivy_remediation_evidence.validator import HAS_JSONSCHEMA


class TestWheelUnpackedPackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parent.parent
        cls.wheel_path = cls.project_root / "work" / "wheels" / "trivy_remediation_evidence-0.1.0-py3-none-any.whl"
        cls.unpacked_dir = cls.project_root / "work" / "unpacked_wheel"

        # Ensure wheel exists (built locally without network)
        if not cls.wheel_path.exists():
            import setuptools.build_meta as bm
            cls.wheel_path.parent.mkdir(parents=True, exist_ok=True)
            bm.build_wheel(str(cls.wheel_path.parent))

        # Unpack wheel into work/unpacked_wheel
        cls.unpacked_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(cls.wheel_path) as z:
            z.extractall(cls.unpacked_dir)

    def test_wheel_package_schemas_byte_match(self) -> None:
        """Verify that bundled schemas in unpacked wheel exactly match outputs/schemas contract."""
        schema_files = [
            "manifest.schema.json",
            "report.schema.json",
            "evidence.schema.json",
            "reason-catalog.json",
            "README.md",
        ]
        schemas_in_wheel = self.unpacked_dir / "trivy_remediation_evidence" / "schemas"
        contract_schemas = self.project_root / "outputs" / "schemas"

        for fname in schema_files:
            whl_f = schemas_in_wheel / fname
            contract_f = contract_schemas / fname
            self.assertTrue(whl_f.exists(), f"Missing schema in wheel: {whl_f}")
            self.assertTrue(contract_f.exists(), f"Missing contract schema: {contract_f}")
            self.assertEqual(
                whl_f.read_bytes(),
                contract_f.read_bytes(),
                f"Byte mismatch between wheel and contract schema for {fname}",
            )

    def test_python311_isolated_wheel_import_and_dependency_error(self) -> None:
        """Run isolated Python 3.11 process pointing ONLY to unpacked wheel (no src/ in PYTHONPATH)."""
        py311_exe = self.project_root / ".venv" / "Scripts" / "python.exe"
        if not py311_exe.exists():
            self.skipTest("Python 3.11 .venv not found")

        # Run script in a completely separate temp directory
        with tempfile.TemporaryDirectory() as foreign_dir:
            test_script = """
import sys
import os
from pathlib import Path
from unittest.mock import patch

# Verify that trivy_remediation_evidence is loaded strictly from unpacked wheel
import trivy_remediation_evidence
pkg_file = Path(trivy_remediation_evidence.__file__).resolve()
assert "unpacked_wheel" in str(pkg_file), f"Package not loaded from unpacked wheel: {pkg_file}"
assert "src" not in str(pkg_file), f"Source tree leaked into PYTHONPATH: {pkg_file}"

# Verify reason catalog loads bundled schemas from unpacked package
from trivy_remediation_evidence.renderer import load_reason_catalog
cat = load_reason_catalog()
assert "INPUT_INVALID_JSON" in cat, "Failed to load reason catalog"

# Verify that in this 3.11 environment, jsonschema is actually installed and available
import trivy_remediation_evidence.validator as val
assert val.HAS_JSONSCHEMA is True, "Expected HAS_JSONSCHEMA to be True in verified 3.11 environment"

# Verify missing dependency error on run_pipeline when HAS_JSONSCHEMA is mocked to False
from trivy_remediation_evidence.evidence import run_pipeline
from trivy_remediation_evidence.validator import MissingDependencyError

with patch("trivy_remediation_evidence.validator.HAS_JSONSCHEMA", False):
    try:
        run_pipeline("dummy1.json", "dummy2.json", "dummy3.json", "dummy4.json")
        print("ERROR: Expected MissingDependencyError")
        sys.exit(2)
    except MissingDependencyError as e:
        # Must not leak input path
        assert "dummy" not in str(e), f"Leaked input in error: {e}"
        assert "jsonschema" in str(e)

# Verify CLI exits with code 1 and quiet non-echo error when dependency is missing
from trivy_remediation_evidence.cli import main
with patch("trivy_remediation_evidence.validator.HAS_JSONSCHEMA", False):
    code = main(["compare", "--before", "d1", "--after", "d2", "--before-manifest", "m1", "--after-manifest", "m2", "--out-dir", "out"])
    assert code == 1, f"Expected code 1 for missing dependency, got {code}"

# Verify CLI exits with code 1 for invalid args
code = main(["compare"])
assert code == 1, f"Expected code 1 for invalid args, got {code}"
print("PYTHON311_WHEEL_TEST_OK")
"""
            env = {
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONPATH": str(self.unpacked_dir),
            }
            res = subprocess.run(
                [str(py311_exe), "-c", test_script],
                cwd=foreign_dir,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res.returncode,
                0,
                f"Python 3.11 wheel verification failed: stdout={res.stdout}, stderr={res.stderr}",
            )
            self.assertIn("PYTHON311_WHEEL_TEST_OK", res.stdout)

    def test_python311_isolated_wheel_full_cli(self) -> None:
        """Run isolated Python 3.11 process pointing ONLY to unpacked wheel with full CLI compare."""
        py311_exe = self.project_root / ".venv" / "Scripts" / "python.exe"
        if not py311_exe.exists():
            self.skipTest("Python 3.11 .venv not found")

        with tempfile.TemporaryDirectory() as foreign_dir:
            out_dir = Path(foreign_dir) / "out"
            v_dir = self.project_root / "outputs" / "fixtures" / "03" / "one-not-detected"

            env = {
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONPATH": str(self.unpacked_dir),
            }
            res = subprocess.run(
                [
                    str(py311_exe),
                    "-m",
                    "trivy_remediation_evidence",
                    "compare",
                    "--before", str(v_dir / "before.json"),
                    "--after", str(v_dir / "after.json"),
                    "--before-manifest", str(v_dir / "before.manifest.json"),
                    "--after-manifest", str(v_dir / "after.manifest.json"),
                    "--out-dir", str(out_dir),
                ],
                cwd=foreign_dir,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res.returncode,
                0,
                f"Python 3.11 wheel CLI failed: stdout={res.stdout}, stderr={res.stderr}",
            )
            self.assertTrue((out_dir / "evidence.json").exists())
            self.assertTrue((out_dir / "report.ja.md").exists())
            self.assertTrue((out_dir / "report.en.md").exists())

            # Verify evidence.json sha256 matches case03 example
            import hashlib
            ev_bytes = (out_dir / "evidence.json").read_bytes()
            h = hashlib.sha256(ev_bytes).hexdigest()
            self.assertEqual(h, "97f11c96c836efab928b34fed418281075aa99a6dd0b23e5b83d702f67205875")

    @unittest.skipUnless(sys.version_info[:2] == (3, 10), "Python 3.10 auxiliary verification")
    def test_python310_isolated_wheel_full_cli(self) -> None:
        """Run isolated Python 3.10 process pointing ONLY to unpacked wheel with full CLI compare."""
        # Use py -3.10
        with tempfile.TemporaryDirectory() as foreign_dir:
            out_dir = Path(foreign_dir) / "out"
            v_dir = self.project_root / "outputs" / "fixtures" / "03" / "one-not-detected"

            env = {
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONPATH": str(self.unpacked_dir),
            }
            res = subprocess.run(
                [
                    "py",
                    "-3.10",
                    "-m",
                    "trivy_remediation_evidence",
                    "compare",
                    "--before", str(v_dir / "before.json"),
                    "--after", str(v_dir / "after.json"),
                    "--before-manifest", str(v_dir / "before.manifest.json"),
                    "--after-manifest", str(v_dir / "after.manifest.json"),
                    "--out-dir", str(out_dir),
                ],
                cwd=foreign_dir,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res.returncode,
                0,
                f"Python 3.10 wheel CLI failed: stdout={res.stdout}, stderr={res.stderr}",
            )
            self.assertTrue((out_dir / "evidence.json").exists())
            self.assertTrue((out_dir / "report.ja.md").exists())
            self.assertTrue((out_dir / "report.en.md").exists())

            # Verify evidence.json sha256 matches case03 example
            import hashlib
            ev_bytes = (out_dir / "evidence.json").read_bytes()
            h = hashlib.sha256(ev_bytes).hexdigest()
            self.assertEqual(h, "97f11c96c836efab928b34fed418281075aa99a6dd0b23e5b83d702f67205875")


if __name__ == "__main__":
    unittest.main()
