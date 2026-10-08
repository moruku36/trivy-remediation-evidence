"""Unit and integration tests for real scan collector and verification harness.

Independent unit tests using synthetic archives and mocked subprocess without
requiring real scanner binary, databases, or work/ directory assets.
"""

from __future__ import annotations

from collections.abc import Callable
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import integration_samples.collect_real_scan as collect_module
from integration_samples.collect_real_scan import collect_scans, main
from trivy_remediation_evidence.evidence import run_pipeline


def _create_minimal_github_archive(version: str, commit_hex: str = "12345678abcd") -> bytes:
    """Create a minimal valid GitHub source archive for lodash."""
    root = f"lodash-lodash-{commit_hex}"
    pkg_json = json.dumps({"name": "lodash", "version": version}).encode("utf-8")
    lodash_js = b"module.exports = {};\n"
    license_txt = b"MIT License\n"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti_root = tarfile.TarInfo(name=root)
        ti_root.type = tarfile.DIRTYPE
        ti_root.mode = 0o755
        tf.addfile(ti_root)

        for fname, content in [
            (f"{root}/package.json", pkg_json),
            (f"{root}/lodash.js", lodash_js),
            (f"{root}/LICENSE", license_txt),
        ]:
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(content)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(content))

    return buf.getvalue()


class TestCollectRealScan(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.td.name)

        # 1. Fake scanner binary
        self.fake_trivy = self.test_dir / "trivy.exe"
        self.fake_trivy.write_bytes(b"MZ-fake-trivy-executable-bytes\n")
        self.trivy_sha = hashlib.sha256(self.fake_trivy.read_bytes()).hexdigest()

        # 2. Fake source archives
        self.before_archive = self.test_dir / "lodash-4.17.20.tar.gz"
        self.before_archive.write_bytes(_create_minimal_github_archive("4.17.20", "111122223333"))
        self.before_sha = hashlib.sha256(self.before_archive.read_bytes()).hexdigest()

        self.after_archive = self.test_dir / "lodash-4.17.21.tar.gz"
        self.after_archive.write_bytes(_create_minimal_github_archive("4.17.21", "444455556666"))
        self.after_sha = hashlib.sha256(self.after_archive.read_bytes()).hexdigest()

        # 3. Fake DB cache
        self.cache_dir = self.test_dir / "cache"
        db_dir = self.cache_dir / "db"
        db_dir.mkdir(parents=True)
        self.fake_db = db_dir / "trivy.db"
        self.fake_db.write_bytes(b"SQLite format 3-fake-db\n")
        self.db_sha = hashlib.sha256(self.fake_db.read_bytes()).hexdigest()

        self.fake_meta = db_dir / "metadata.json"
        self.fake_meta.write_bytes(b'{"Version": 2, "UpdatedAt": "2026-10-08T19:05:21Z"}\n')
        self.meta_sha = hashlib.sha256(self.fake_meta.read_bytes()).hexdigest()

        # Patch constants in collect_real_scan module
        self.patchers = [
            patch.object(collect_module, "EXPECTED_TRIVY_BINARY_SHA256", self.trivy_sha),
            patch.object(collect_module, "EXPECTED_BEFORE_ARCHIVE_SHA256", self.before_sha),
            patch.object(collect_module, "EXPECTED_AFTER_ARCHIVE_SHA256", self.after_sha),
            patch.object(collect_module, "EXPECTED_DB_SNAPSHOT_SHA256", self.db_sha),
        ]
        for p in self.patchers:
            p.start()

    def tearDown(self) -> None:
        for p in reversed(self.patchers):
            p.stop()
        self.td.cleanup()

    @staticmethod
    def _sample_vulns(side: str) -> list[dict]:
        persistent = [
            {
                "VulnerabilityID": "CVE-2019-10744",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.20" if side == "before" else "4.17.21",
                "FixedVersion": "",
                "Status": "affected",
                "Severity": "HIGH",
                "Title": "Prototype Pollution in lodash",
                "PkgPath": "",
            },
            {
                "VulnerabilityID": "CVE-2019-1010266",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.20" if side == "before" else "4.17.21",
                "FixedVersion": "",
                "Status": "affected",
                "Severity": "MEDIUM",
                "Title": "CWE-400 in lodash",
                "PkgPath": "",
            },
            {
                "VulnerabilityID": "CVE-2018-16487",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.20" if side == "before" else "4.17.21",
                "FixedVersion": "",
                "Status": "affected",
                "Severity": "HIGH",
                "Title": "Prototype Pollution in lodash",
                "PkgPath": "",
            },
        ]
        if side == "before":
            remediated = [
                {
                    "VulnerabilityID": "CVE-2021-23337",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Status": "fixed",
                    "Severity": "HIGH",
                    "Title": "Command Injection in lodash",
                    "PkgPath": "",
                },
                {
                    "VulnerabilityID": "CVE-2020-28500",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Status": "fixed",
                    "Severity": "MEDIUM",
                    "Title": "Regular Expression Denial of Service (ReDoS) in lodash",
                    "PkgPath": "",
                },
            ]
            return persistent + remediated
        return persistent

    def _make_mock_run(
        self,
        *,
        version_code: int = 0,
        version_stdout: bytes = b"Version: 0.75.0\n",
        scan_code: int = 10,
        custom_report_generator: Callable | None = None,
        modify_on_scan: Callable | None = None,
        stderr_bytes: bytes = b"",
        raise_timeout: bool = False,
    ):
        """Create a mock for subprocess.run simulating Trivy behavior."""
        def _mock_run(command, cwd=None, env=None, capture_output=True, timeout=None, shell=False):
            if "--version" in command:
                return subprocess.CompletedProcess(
                    command,
                    version_code,
                    stdout=version_stdout,
                    stderr=b"",
                )

            if raise_timeout:
                raise subprocess.TimeoutExpired(command, timeout, output=b"", stderr=b"timeout")

            if modify_on_scan is not None:
                modify_on_scan(command)

            output_file: Path | None = None
            for i, arg in enumerate(command):
                if arg == "--output" and i + 1 < len(command):
                    output_file = Path(command[i + 1])
                    break

            ref = command[-1]
            side = "before" if output_file is not None and "before.json" in str(output_file) else "after"
            expected_ver = "4.17.20" if side == "before" else "4.17.21"

            if output_file is not None:
                if custom_report_generator is not None:
                    rep_data = custom_report_generator(side, expected_ver, ref, output_file, cwd)
                    if rep_data is not None:
                        if isinstance(rep_data, bytes):
                            output_file.write_bytes(rep_data)
                        else:
                            output_file.write_text(json.dumps(rep_data, indent=2) + "\n", encoding="utf-8")
                else:
                    # Dynamically read actual config digest from images directory
                    cfg_digest = "sha256:d00d000000000000000000000000000000000000000000000000000000000000"
                    if cwd is not None:
                        idx_file = Path(cwd) / "images" / side / "index.json"
                        if idx_file.is_file():
                            idx_obj = json.loads(idx_file.read_text(encoding="utf-8"))
                            m_hex = idx_obj["manifests"][0]["digest"].split(":", 1)[1]
                            m_obj = json.loads(
                                (Path(cwd) / "images" / side / "blobs" / "sha256" / m_hex).read_text(encoding="utf-8")
                            )
                            cfg_digest = m_obj["config"]["digest"]

                    vulns = self._sample_vulns(side)
                    rep = {
                        "SchemaVersion": 2,
                        "ArtifactType": "container_image",
                        "ArtifactName": ref,
                        "Metadata": {
                            "RepoDigests": [ref],
                            "ImageID": cfg_digest,
                            "ImageConfig": {
                                "os": "linux",
                                "architecture": "amd64",
                            },
                        },
                        "Results": [
                            {
                                "Target": "Node.js",
                                "Class": "lang-pkgs",
                                "Type": "node-pkg",
                                "Packages": [
                                    {
                                        "Name": "lodash",
                                        "Version": expected_ver,
                                        "FilePath": "app/node_modules/lodash/package.json",
                                        "AnalyzedBy": "node-pkg",
                                    }
                                ],
                                "Vulnerabilities": vulns,
                            }
                        ],
                    }
                    output_file.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")

            return subprocess.CompletedProcess(
                command,
                scan_code,
                stdout=b"2026-10-09T00:00:00Z INFO Scanning...\n",
                stderr=stderr_bytes,
            )

        return _mock_run

    def test_pre_execution_security_guards(self) -> None:
        """Reject unverified scanner binary, unverified archives, unverified DB, or existing out_dir."""
        out_dir = self.test_dir / "out1"

        # Tampered binary SHA
        with patch.object(collect_module, "EXPECTED_TRIVY_BINARY_SHA256", "0" * 64):
            with self.assertRaises(ValueError) as ctx:
                collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertIn("Scanner binary SHA-256 mismatch", str(ctx.exception))

        # Tampered before archive SHA
        with patch.object(collect_module, "EXPECTED_BEFORE_ARCHIVE_SHA256", "0" * 64):
            with self.assertRaises(ValueError) as ctx:
                collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertIn("Before archive SHA-256 mismatch", str(ctx.exception))

        # Tampered after archive SHA
        with patch.object(collect_module, "EXPECTED_AFTER_ARCHIVE_SHA256", "0" * 64):
            with self.assertRaises(ValueError) as ctx:
                collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertIn("After archive SHA-256 mismatch", str(ctx.exception))

        # Tampered DB SHA
        with patch.object(collect_module, "EXPECTED_DB_SNAPSHOT_SHA256", "0" * 64):
            with self.assertRaises(ValueError) as ctx:
                collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertIn("Database SHA-256 mismatch", str(ctx.exception))

        # Existing output directory
        out_dir.mkdir()
        with self.assertRaises(FileExistsError):
            collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)

    def test_metadata_validation(self) -> None:
        """Reject invalid or missing Version (must be int 2, not bool) and UpdatedAt."""
        out_dir = self.test_dir / "out_meta"

        # Version as bool
        self.fake_meta.write_bytes(b'{"Version": true, "UpdatedAt": "2026-10-08T19:05:21Z"}\n')
        with self.assertRaises(ValueError) as ctx:
            collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
        self.assertIn("Invalid database Version", str(ctx.exception))

        # Version as string
        self.fake_meta.write_bytes(b'{"Version": "2", "UpdatedAt": "2026-10-08T19:05:21Z"}\n')
        with self.assertRaises(ValueError) as ctx:
            collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
        self.assertIn("Invalid database Version", str(ctx.exception))

        # Version as 3
        self.fake_meta.write_bytes(b'{"Version": 3, "UpdatedAt": "2026-10-08T19:05:21Z"}\n')
        with self.assertRaises(ValueError) as ctx:
            collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
        self.assertIn("Invalid database Version", str(ctx.exception))

        # Missing or empty UpdatedAt
        self.fake_meta.write_bytes(b'{"Version": 2, "UpdatedAt": "  "}\n')
        with self.assertRaises(ValueError) as ctx:
            collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
        self.assertIn("Invalid database UpdatedAt", str(ctx.exception))

    def test_version_command_verification_and_capture(self) -> None:
        """Verify version check failure exits 1 and records capture, while success records details."""
        out_dir = self.test_dir / "out_ver"
        mock_run = self._make_mock_run(version_stdout=b"Version: 0.74.0\n")

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 1)

            capture = json.loads((out_dir / "capture.json").read_text(encoding="utf-8"))
            self.assertFalse(capture["scannerVersionCheck"]["versionMatched"])
            self.assertEqual(capture["scannerVersionCheck"]["binarySha256"], self.trivy_sha)
            self.assertFalse((out_dir / "before.manifest.json").exists())

    def test_normal_successful_collection_and_pipeline_comparable(self) -> None:
        """Verify normal policy 10 collection, schema validity, and pipeline comparable result."""
        out_dir = self.test_dir / "out_normal"
        mock_run = self._make_mock_run(scan_code=10)

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 0)

            # Check capture records
            capture = json.loads((out_dir / "capture.json").read_text(encoding="utf-8"))
            self.assertTrue(capture["scannerVersionCheck"]["versionMatched"])
            self.assertEqual(capture["scannerVersionCheck"]["command"], [str(self.fake_trivy), "--version"])
            self.assertIn("before", capture["scans"])
            self.assertIn("after", capture["scans"])

            before_scan = capture["scans"]["before"]
            self.assertEqual(before_scan["returncode"], 10)
            self.assertTrue(before_scan["hashesUnchanged"])
            self.assertFalse(before_scan["hasErrorLogs"])
            self.assertTrue(before_scan["validation"]["reportValid"])
            self.assertIn("command", before_scan)
            self.assertIn("stdoutSha256", before_scan["logs"])
            self.assertIn("stderrSha256", before_scan["logs"])
            self.assertIn("sha256", before_scan["report"])

            # Verify manifests exist and check content
            b_manifest = json.loads((out_dir / "before.manifest.json").read_text(encoding="utf-8"))
            a_manifest = json.loads((out_dir / "after.manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(b_manifest["execution"]["exitCause"], "findings_policy")
            self.assertEqual(b_manifest["execution"]["exitCode"], 10)
            self.assertEqual(b_manifest["target"]["scopes"][0]["coverage"], "scanned")
            self.assertEqual(b_manifest["databases"][0]["snapshotSha256"], self.db_sha)

            self.assertEqual(a_manifest["execution"]["exitCause"], "findings_policy")
            self.assertEqual(a_manifest["execution"]["exitCode"], 10)

            # Run existing pipeline with the generated outputs
            evidence_data, pipe_exit, _ = run_pipeline(
                out_dir / "before.json",
                out_dir / "after.json",
                out_dir / "before.manifest.json",
                out_dir / "after.manifest.json",
            )
            self.assertEqual(pipe_exit, 0)
            self.assertEqual(evidence_data["comparison"], "comparable")
            self.assertEqual(evidence_data["globalReasons"], [])

            cat_summary = evidence_data["summary"]
            self.assertEqual(cat_summary["persistent"], 3)
            self.assertEqual(cat_summary["not_detected"], 2)
            self.assertEqual(cat_summary["new"], 0)
            self.assertEqual(cat_summary["comparison_unavailable"], 0)

    def test_normal_exit_zero_no_findings(self) -> None:
        """When returncode is 0 and findings count is 0, exitCause is 'normal'."""
        out_dir = self.test_dir / "out_zero"

        def _zero_vulns_generator(side, ver, ref, output_file, cwd):
            cfg_digest = "sha256:d00d000000000000000000000000000000000000000000000000000000000000"
            if cwd is not None:
                idx_file = Path(cwd) / "images" / side / "index.json"
                if idx_file.is_file():
                    idx_obj = json.loads(idx_file.read_text(encoding="utf-8"))
                    m_hex = idx_obj["manifests"][0]["digest"].split(":", 1)[1]
                    m_obj = json.loads(
                        (Path(cwd) / "images" / side / "blobs" / "sha256" / m_hex).read_text(encoding="utf-8")
                    )
                    cfg_digest = m_obj["config"]["digest"]

            return {
                "SchemaVersion": 2,
                "ArtifactType": "container_image",
                "ArtifactName": ref,
                "Metadata": {
                    "RepoDigests": [ref],
                    "ImageID": cfg_digest,
                    "ImageConfig": {"os": "linux", "architecture": "amd64"},
                },
                "Results": [
                    {
                        "Target": "Node.js",
                        "Class": "lang-pkgs",
                        "Type": "node-pkg",
                        "Packages": [
                            {
                                "Name": "lodash",
                                "Version": ver,
                                "FilePath": "app/node_modules/lodash/package.json",
                                "AnalyzedBy": "node-pkg",
                            }
                        ],
                        "Vulnerabilities": [],
                    }
                ],
            }

        mock_run = self._make_mock_run(scan_code=0, custom_report_generator=_zero_vulns_generator)

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 0)

            b_manifest = json.loads((out_dir / "before.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(b_manifest["execution"]["exitCause"], "normal")
            self.assertEqual(b_manifest["execution"]["exitCode"], 0)
            self.assertEqual(b_manifest["target"]["scopes"][0]["coverage"], "scanned")

            evidence_data, pipe_exit, _ = run_pipeline(
                out_dir / "before.json",
                out_dir / "after.json",
                out_dir / "before.manifest.json",
                out_dir / "after.manifest.json",
            )
            self.assertEqual(pipe_exit, 0)
            self.assertEqual(evidence_data["comparison"], "comparable")
            self.assertEqual(evidence_data["items"], [])

    def test_contradictory_zero_with_findings_rejected(self) -> None:
        """When returncode is 0 but findings count > 0, status is unknown/failed."""
        out_dir = self.test_dir / "out_contra"
        mock_run = self._make_mock_run(scan_code=0)  # findings count > 0 with exit code 0

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 1)

            b_manifest = json.loads((out_dir / "before.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(b_manifest["execution"]["exitCause"], "unknown")
            self.assertFalse(b_manifest["execution"]["success"])
            self.assertEqual(b_manifest["target"]["scopes"][0]["coverage"], "failed")

    def test_unexpected_nonzero_rejected(self) -> None:
        """Unexpected returncode (e.g. 2) triggers failure/unknown."""
        out_dir = self.test_dir / "out_rc2"
        mock_run = self._make_mock_run(scan_code=2)

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 1)

            b_manifest = json.loads((out_dir / "before.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(b_manifest["execution"]["exitCause"], "unknown")
            self.assertEqual(b_manifest["target"]["scopes"][0]["coverage"], "failed")

    def test_timeout_omits_manifest_and_captures(self) -> None:
        """TimeoutExpired sets timedOut=True, returncode=None, and omits manifest."""
        out_dir = self.test_dir / "out_timeout"
        mock_run = self._make_mock_run(raise_timeout=True)

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 1)

            capture = json.loads((out_dir / "capture.json").read_text(encoding="utf-8"))
            self.assertTrue(capture["scans"]["before"]["timedOut"])
            self.assertIsNone(capture["scans"]["before"]["returncode"])
            self.assertIn("manifestOmittedReason", capture["scans"]["before"])

            # Manifest must NOT be written when exitCode cannot be represented in schema
            self.assertFalse((out_dir / "before.manifest.json").exists())

    def test_error_logs_rejected(self) -> None:
        """ERROR log in stderr triggers failure."""
        out_dir = self.test_dir / "out_err"
        mock_run = self._make_mock_run(stderr_bytes=b"2026-10-09 ERROR failed to inspect something\n")

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 1)

            b_manifest = json.loads((out_dir / "before.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(b_manifest["execution"]["exitCause"], "failure")
            self.assertEqual(b_manifest["target"]["scopes"][0]["coverage"], "failed")

    def test_baseline_hashes_and_intermediate_tampering(self) -> None:
        """Verify tampering during scan, intermediate tampering between scans, and baseline mismatch."""
        # 1. Tampering during scan (pre/post mismatch)
        out_dir1 = self.test_dir / "out_tamp1"
        def _modify_during_scan(cmd):
            self.fake_db.write_bytes(b"tampered-during-scan\n")

        mock_run1 = self._make_mock_run(modify_on_scan=_modify_during_scan)
        with patch("subprocess.run", side_effect=mock_run1):
            rc1 = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir1)
            self.assertEqual(rc1, 1)
            b_m = json.loads((out_dir1 / "before.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(b_m["target"]["scopes"][0]["coverage"], "failed")

        # Restore fake DB
        self.fake_db.write_bytes(b"SQLite format 3-fake-db\n")

        # 2. Intermediate tampering: change DB only between before scan end and after scan start
        out_dir2 = self.test_dir / "out_tamp2"
        call_count = 0
        def _modify_between_scans(cmd):
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # 2nd scan is 'after'
                self.fake_db.write_bytes(b"tampered-between-scans\n")

        mock_run2 = self._make_mock_run(modify_on_scan=_modify_between_scans)
        with patch("subprocess.run", side_effect=mock_run2):
            rc2 = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir2)
            self.assertEqual(rc2, 1)
            # Before might have succeeded, but after failed due to preHashes != baselineHashes
            a_m = json.loads((out_dir2 / "after.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(a_m["target"]["scopes"][0]["coverage"], "failed")

        # Restore fake DB
        self.fake_db.write_bytes(b"SQLite format 3-fake-db\n")

        # 3. Missing DB file after scan: manifest must be omitted because snapshot SHA is missing
        out_dir3 = self.test_dir / "out_tamp3"
        def _delete_db_on_scan(cmd):
            if self.fake_db.is_file():
                self.fake_db.unlink()

        mock_run3 = self._make_mock_run(modify_on_scan=_delete_db_on_scan)
        with patch("subprocess.run", side_effect=mock_run3):
            rc3 = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir3)
            self.assertEqual(rc3, 1)
            self.assertFalse((out_dir3 / "before.manifest.json").exists())

    def test_report_strict_json_and_reader_validation(self) -> None:
        """Strict reader rejects duplicate JSON keys, NaN values, and non-UTF8."""
        # Duplicate keys
        out_dir1 = self.test_dir / "out_dup_keys"
        dup_report = b'{"SchemaVersion": 2, "SchemaVersion": 2, "ArtifactType": "container_image"}\n'
        mock_run1 = self._make_mock_run(custom_report_generator=lambda *args: dup_report)

        with patch("subprocess.run", side_effect=mock_run1):
            rc1 = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir1)
            self.assertEqual(rc1, 1)
            capture1 = json.loads((out_dir1 / "capture.json").read_text(encoding="utf-8"))
            self.assertFalse(capture1["scans"]["before"]["validation"]["reportValid"])
            self.assertIn("Reader invalid parse_state", capture1["scans"]["before"]["validation"]["errors"][0])

        # NaN float value
        out_dir2 = self.test_dir / "out_nan"
        nan_report = b'{"SchemaVersion": 2, "ArtifactType": "container_image", "val": NaN}\n'
        mock_run2 = self._make_mock_run(custom_report_generator=lambda *args: nan_report)

        with patch("subprocess.run", side_effect=mock_run2):
            rc2 = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir2)
            self.assertEqual(rc2, 1)
            capture2 = json.loads((out_dir2 / "capture.json").read_text(encoding="utf-8"))
            self.assertFalse(capture2["scans"]["before"]["validation"]["reportValid"])

    def test_report_schema_and_structure_validation(self) -> None:
        """Reject null Results, extra Results/Packages, substring digests, and platform mismatch."""
        out_dir = self.test_dir / "out_struct"

        def _make_bad_report(variant: str):
            def _gen(side, ver, ref, output_file, cwd):
                rep = {
                    "SchemaVersion": 2,
                    "ArtifactType": "container_image",
                    "ArtifactName": ref,
                    "Metadata": {
                        "RepoDigests": [ref],
                        "ImageID": "sha256:dummy",
                        "ImageConfig": {"os": "linux", "architecture": "amd64"},
                    },
                    "Results": [
                        {
                            "Target": "Node.js",
                            "Class": "lang-pkgs",
                            "Type": "node-pkg",
                            "Packages": [
                                {
                                    "Name": "lodash",
                                    "Version": ver,
                                    "FilePath": "app/node_modules/lodash/package.json",
                                    "AnalyzedBy": "node-pkg",
                                }
                            ],
                            "Vulnerabilities": [],
                        }
                    ],
                }
                # Fix ImageID from cwd
                if cwd is not None:
                    idx_file = Path(cwd) / "images" / side / "index.json"
                    if idx_file.is_file():
                        idx_obj = json.loads(idx_file.read_text(encoding="utf-8"))
                        m_hex = idx_obj["manifests"][0]["digest"].split(":", 1)[1]
                        m_obj = json.loads(
                            (Path(cwd) / "images" / side / "blobs" / "sha256" / m_hex).read_text(encoding="utf-8")
                        )
                        rep["Metadata"]["ImageID"] = m_obj["config"]["digest"]

                if variant == "null_results":
                    rep["Results"] = None  # type: ignore
                elif variant == "extra_results":
                    rep["Results"].append({"Target": "extra", "Class": "lang-pkgs", "Type": "node-pkg", "Packages": []})
                elif variant == "extra_packages":
                    rep["Results"][0]["Packages"].append({"Name": "extra", "Version": "1.0.0", "FilePath": "extra", "AnalyzedBy": "node-pkg"})
                elif variant == "substring_digest":
                    # Substring match only: bare digest without host:port/sample@
                    rep["Metadata"]["RepoDigests"] = [ref.split("@", 1)[1]]
                elif variant == "trailing_newline_digest":
                    rep["Metadata"]["RepoDigests"] = [ref + "\n"]
                elif variant == "platform_mismatch":
                    rep["Metadata"]["ImageConfig"]["os"] = "windows"
                elif variant == "image_id_mismatch":
                    rep["Metadata"]["ImageID"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

                return rep
            return _gen

        variants = [
            "null_results",
            "extra_results",
            "extra_packages",
            "substring_digest",
            "trailing_newline_digest",
            "platform_mismatch",
            "image_id_mismatch",
        ]
        for v in variants:
            sub_out = out_dir / v
            mock_run = self._make_mock_run(custom_report_generator=_make_bad_report(v))
            with patch("subprocess.run", side_effect=mock_run):
                rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, sub_out)
                self.assertEqual(rc, 1, f"Variant {v} should have failed")
                capture = json.loads((sub_out / "capture.json").read_text(encoding="utf-8"))
                self.assertFalse(capture["scans"]["before"]["validation"]["reportValid"], f"Variant {v} should be marked invalid")

    def test_missing_report_does_not_synthesize_manifest(self) -> None:
        """When report file is not written, collector must NOT fake or fabricate manifest."""
        out_dir = self.test_dir / "out_no_rep"
        mock_run = self._make_mock_run(custom_report_generator=lambda *args: None)

        with patch("subprocess.run", side_effect=mock_run):
            rc = collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)
            self.assertEqual(rc, 1)

            capture = json.loads((out_dir / "capture.json").read_text(encoding="utf-8"))
            self.assertFalse(capture["scans"]["before"]["reportExists"])
            self.assertEqual(capture["scans"]["before"]["validation"]["status"], "missing_report")
            self.assertFalse((out_dir / "before.manifest.json").exists())

    def test_pipeline_rejection_on_failed_coverage(self) -> None:
        """Verify that when collector outputs coverage='failed', run_pipeline marks it comparison_unavailable."""
        out_dir = self.test_dir / "out_pipe_rej"
        mock_run = self._make_mock_run(scan_code=2)  # Generates coverage='failed'

        with patch("subprocess.run", side_effect=mock_run):
            collect_scans(self.fake_trivy, self.cache_dir, self.before_archive, self.after_archive, out_dir)

            evidence_data, pipe_exit, _ = run_pipeline(
                out_dir / "before.json",
                out_dir / "after.json",
                out_dir / "before.manifest.json",
                out_dir / "after.manifest.json",
            )
            self.assertEqual(pipe_exit, 2)
            self.assertEqual(evidence_data["comparison"], "comparison_unavailable")
            codes = [r["code"] for r in evidence_data["globalReasons"]]
            self.assertIn("SCOPE_NOT_SCANNED", codes)

    def test_cli_main_wrapper(self) -> None:
        """Verify CLI main entrypoint."""
        out_dir = self.test_dir / "out_cli"
        mock_run = self._make_mock_run(scan_code=10)

        with patch("subprocess.run", side_effect=mock_run):
            code = main([
                "--trivy", str(self.fake_trivy),
                "--cache-dir", str(self.cache_dir),
                "--before-archive", str(self.before_archive),
                "--after-archive", str(self.after_archive),
                "--out-dir", str(out_dir),
            ])
            self.assertEqual(code, 0)
            self.assertTrue((out_dir / "capture.json").is_file())

    def test_optional_real_scan_probe2_smoke(self) -> None:
        """Optional smoke verification with real probe2 artifacts if present."""
        probe2_dir = Path("work/real-scan-probe2")
        if not probe2_dir.is_dir() or not (probe2_dir / "before.json").is_file():
            self.skipTest("Optional real scan probe2 artifacts not present")

        # Verify real probe2 reports with strict reader and schema validator
        from trivy_remediation_evidence.reader import read_source_file
        from trivy_remediation_evidence.validator import validate_source

        br = read_source_file(probe2_dir / "before.json", "before", "report")
        self.assertEqual(br.parse_state, "valid")
        self.assertEqual(validate_source(br), [])

        ar = read_source_file(probe2_dir / "after.json", "after", "report")
        self.assertEqual(ar.parse_state, "valid")
        self.assertEqual(validate_source(ar), [])

        # Check observed findings count in probe2 reports
        self.assertEqual(len(br.data["Results"][0]["Vulnerabilities"]), 5)
        self.assertEqual(len(ar.data["Results"][0]["Vulnerabilities"]), 3)


if __name__ == "__main__":
    unittest.main()
