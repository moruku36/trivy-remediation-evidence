"""Execution harness and minimal collector for fixed sample and official Trivy 0.75.0.

NOTE: This is NOT a general-purpose production collector. It is a strictly controlled
verification harness specifically for the pinned lodash 4.17.20 / 4.17.21 GitHub source
archives and official Trivy 0.75.0 Windows binary with fixed vulnerability database.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from trivy_remediation_evidence.reader import read_source_file
from trivy_remediation_evidence.validator import validate_source
from .sample_images import LocalRegistry, build_sample_pair

EXPECTED_TRIVY_VERSION = "0.75.0"
EXPECTED_TRIVY_BINARY_SHA256 = "3b4fcf6fec53c4c73c325cfd518c7264100695b19e6c59c6a777e4a67dc9f0e6"
EXPECTED_BEFORE_ARCHIVE_SHA256 = "345283811f0c9a81551ec605a5d6b6c152c40cf11059d6b7568a496c83807a4a"
EXPECTED_AFTER_ARCHIVE_SHA256 = "6a70a8d1053da80c542979250811189b269d6319ff07185f405f960805f973d1"
EXPECTED_DB_SNAPSHOT_SHA256 = "c9cfef803a944f17cf0598728895836184e87ed2fd693ff7949c4113b12451fa"
EXPECTED_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"
EMPTY_RULES_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _calc_sha256(data: bytes) -> str:
    """Calculate hex sha256."""
    return hashlib.sha256(data).hexdigest()


def _get_file_sha256(p: Path) -> str | None:
    """Return hex sha256 of file if exists, else None."""
    if p.is_file():
        return _calc_sha256(p.read_bytes())
    return None


def collect_scans(
    trivy_path: Path | str,
    cache_dir: Path | str,
    before_archive: Path | str,
    after_archive: Path | str,
    out_dir: Path | str,
) -> int:
    """Run Trivy scans for before and after images and generate schema-compliant manifests.

    Returns:
        0 on complete verified success, 1 on failure.
    """
    trivy_path = Path(trivy_path).resolve()
    cache_dir = Path(cache_dir).resolve()
    before_archive = Path(before_archive).resolve()
    after_archive = Path(after_archive).resolve()
    out_dir = Path(out_dir).resolve()

    if out_dir.exists():
        raise FileExistsError(f"Target output directory already exists: {out_dir}")

    # 1. Pre-execution scanner and archive verification
    if not trivy_path.is_file():
        raise FileNotFoundError(f"Scanner binary not found: {trivy_path}")

    actual_scanner_sha = _calc_sha256(trivy_path.read_bytes())
    if actual_scanner_sha != EXPECTED_TRIVY_BINARY_SHA256:
        raise ValueError(
            f"Scanner binary SHA-256 mismatch! Expected {EXPECTED_TRIVY_BINARY_SHA256}, got {actual_scanner_sha}"
        )

    if not before_archive.is_file():
        raise FileNotFoundError(f"Before archive not found: {before_archive}")
    actual_before_sha = _calc_sha256(before_archive.read_bytes())
    if actual_before_sha != EXPECTED_BEFORE_ARCHIVE_SHA256:
        raise ValueError(
            f"Before archive SHA-256 mismatch! Expected {EXPECTED_BEFORE_ARCHIVE_SHA256}, got {actual_before_sha}"
        )

    if not after_archive.is_file():
        raise FileNotFoundError(f"After archive not found: {after_archive}")
    actual_after_sha = _calc_sha256(after_archive.read_bytes())
    if actual_after_sha != EXPECTED_AFTER_ARCHIVE_SHA256:
        raise ValueError(
            f"After archive SHA-256 mismatch! Expected {EXPECTED_AFTER_ARCHIVE_SHA256}, got {actual_after_sha}"
        )

    db_file = cache_dir / "db" / "trivy.db"
    metadata_file = cache_dir / "db" / "metadata.json"
    if not db_file.is_file():
        raise FileNotFoundError(f"Trivy database file not found: {db_file}")
    if not metadata_file.is_file():
        raise FileNotFoundError(f"Trivy database metadata file not found: {metadata_file}")

    actual_db_sha = _calc_sha256(db_file.read_bytes())
    if actual_db_sha != EXPECTED_DB_SNAPSHOT_SHA256:
        raise ValueError(
            f"Database SHA-256 mismatch! Expected {EXPECTED_DB_SNAPSHOT_SHA256}, got {actual_db_sha}"
        )

    metadata_bytes = metadata_file.read_bytes()
    actual_meta_sha = _calc_sha256(metadata_bytes)
    try:
        db_metadata_obj = json.loads(metadata_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to parse database metadata.json: {e}") from e

    if not isinstance(db_metadata_obj, dict):
        raise ValueError("Database metadata.json must be a JSON object")

    ver = db_metadata_obj.get("Version")
    if not isinstance(ver, int) or isinstance(ver, bool) or ver != 2:
        raise ValueError(f"Invalid database Version in metadata.json: expected int 2, got {ver!r}")
    db_schema_version = ver

    updated_at = db_metadata_obj.get("UpdatedAt")
    if not isinstance(updated_at, str) or not updated_at.strip():
        raise ValueError(f"Invalid database UpdatedAt in metadata.json: expected non-empty str, got {updated_at!r}")
    db_updated_at = updated_at

    # Create output directory
    out_dir.mkdir(parents=True, exist_ok=False)

    # 2. Build reproducible OCI images from verified archives
    images_dir = out_dir / "images"
    images_data = build_sample_pair(before_archive, after_archive, images_dir, source_kind="github-source-archive")

    # 3. Create isolated configs and environment
    empty_config_file = out_dir / "empty-config.yaml"
    empty_config_file.write_bytes(b"{}\n")
    empty_config_sha256 = _calc_sha256(b"{}\n")

    empty_ignore_file = out_dir / "empty-ignore"
    empty_ignore_file.write_bytes(b"")
    empty_ignore_sha256 = _calc_sha256(b"")

    empty_docker_dir = out_dir / "empty-docker-config"
    empty_docker_dir.mkdir(exist_ok=True)

    # Scrub TRIVY_* environment variables and isolate DOCKER_CONFIG
    child_env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TRIVY_")}
    child_env["DOCKER_CONFIG"] = str(empty_docker_dir)

    baseline_hashes = {
        "db": actual_db_sha,
        "metadata": actual_meta_sha,
        "config": empty_config_sha256,
        "ignore": empty_ignore_sha256,
        "binary": actual_scanner_sha,
    }

    capture_records: dict[str, Any] = {
        "collectorVersion": "0.1.0",
        "scannerVersion": EXPECTED_TRIVY_VERSION,
        "scannerBinarySha256": actual_scanner_sha,
        "databaseSnapshotSha256": actual_db_sha,
        "databaseMetadataSha256": actual_meta_sha,
        "databaseMetadata": {
            "Version": db_schema_version,
            "UpdatedAt": db_updated_at,
        },
        "baselineHashes": baseline_hashes,
        "images": images_data,
        "scans": {},
    }

    # 4. Measure scanner --version with sanitized env and shell=False
    version_cmd = [str(trivy_path), "--version"]
    v_start_utc = datetime.now(timezone.utc).isoformat()
    try:
        v_proc = subprocess.run(
            version_cmd,
            cwd=out_dir,
            env=child_env,
            capture_output=True,
            timeout=30,
            shell=False,
        )
        v_end_utc = datetime.now(timezone.utc).isoformat()
        v_stdout = v_proc.stdout.decode("utf-8", errors="replace")
        v_stderr = v_proc.stderr.decode("utf-8", errors="replace")
        v_code = v_proc.returncode
    except Exception as e:
        v_end_utc = datetime.now(timezone.utc).isoformat()
        v_stdout = ""
        v_stderr = f"Version command execution failed: {e}\n"
        v_code = -1

    version_matched = (v_code == 0 and EXPECTED_TRIVY_VERSION in v_stdout)
    capture_records["scannerVersionCheck"] = {
        "command": version_cmd,
        "binarySha256": actual_scanner_sha,
        "returncode": v_code,
        "stdout": v_stdout,
        "stderr": v_stderr,
        "startUtc": v_start_utc,
        "endUtc": v_end_utc,
        "versionMatched": version_matched,
    }

    if not version_matched:
        capture_file = out_dir / "capture.json"
        capture_file.write_text(json.dumps(capture_records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    all_scans_succeeded = True

    # 5. Run both scans within the same LocalRegistry context
    with LocalRegistry(images_dir) as registry:
        for side, expected_ver in [("before", "4.17.20"), ("after", "4.17.21")]:
            manifest_digest = images_data[side]["manifestDigest"]
            config_digest = images_data[side]["configDigest"]
            exact_ref = f"127.0.0.1:{registry.port}/sample@{manifest_digest}"
            report_file = out_dir / f"{side}.json"
            stdout_file = out_dir / f"{side}.stdout.log"
            stderr_file = out_dir / f"{side}.stderr.log"

            command = [
                str(trivy_path),
                "image",
                "--cache-dir", str(cache_dir),
                "--config", str(empty_config_file),
                "--ignorefile", str(empty_ignore_file),
                "--scanners", "vuln",
                "--pkg-types", "library",
                "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                "--ignore-unfixed=false",
                "--list-all-pkgs=true",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--skip-vex-repo-update",
                "--skip-version-check",
                "--disable-telemetry",
                "--detection-priority", "precise",
                "--image-src", "remote",
                "--insecure",
                "--platform", "linux/amd64",
                "--exit-code", "10",
                "--exit-on-eol", "0",
                "--format", "json",
                "--output", str(report_file),
                exact_ref,
            ]

            # Pre-scan hash state
            pre_hashes = {
                "db": _get_file_sha256(db_file),
                "metadata": _get_file_sha256(metadata_file),
                "config": _get_file_sha256(empty_config_file),
                "ignore": _get_file_sha256(empty_ignore_file),
                "binary": _get_file_sha256(trivy_path),
            }

            start_utc = datetime.now(timezone.utc).isoformat()

            timed_out = False
            proc_returncode: int | None = None
            try:
                proc = subprocess.run(
                    command,
                    cwd=out_dir,
                    env=child_env,
                    capture_output=True,
                    timeout=180,
                    shell=False,
                )
                proc_returncode = proc.returncode
                stdout_file.write_bytes(proc.stdout)
                stderr_file.write_bytes(proc.stderr)
                raw_stderr = proc.stderr.decode(errors="replace")
            except subprocess.TimeoutExpired as e:
                timed_out = True
                proc_returncode = None
                if e.stdout:
                    stdout_file.write_bytes(e.stdout)
                else:
                    stdout_file.write_bytes(b"")
                if e.stderr:
                    stderr_file.write_bytes(e.stderr)
                else:
                    stderr_file.write_bytes(b"")
                raw_stderr = "TIMEOUT"
            except Exception as e:
                proc_returncode = None
                stdout_file.write_bytes(b"")
                stderr_file.write_text(f"Subprocess execution error: {e}\n", encoding="utf-8")
                raw_stderr = str(e)

            end_utc = datetime.now(timezone.utc).isoformat()

            # Post-scan hash state
            post_hashes = {
                "db": _get_file_sha256(db_file),
                "metadata": _get_file_sha256(metadata_file),
                "config": _get_file_sha256(empty_config_file),
                "ignore": _get_file_sha256(empty_ignore_file),
                "binary": _get_file_sha256(trivy_path),
            }

            stdout_sha = _calc_sha256(stdout_file.read_bytes()) if stdout_file.is_file() else None
            stderr_sha = _calc_sha256(stderr_file.read_bytes()) if stderr_file.is_file() else None

            scan_info: dict[str, Any] = {
                "side": side,
                "command": command,
                "startUtc": start_utc,
                "endUtc": end_utc,
                "returncode": proc_returncode,
                "timedOut": timed_out,
                "preHashes": pre_hashes,
                "postHashes": post_hashes,
                "logs": {
                    "stdout": f"{side}.stdout.log",
                    "stdoutSha256": stdout_sha,
                    "stderr": f"{side}.stderr.log",
                    "stderrSha256": stderr_sha,
                },
                "reportExists": report_file.is_file(),
            }

            # Verify integrity of inputs against baseline:
            # None == None or tampered == tampered cannot pass because both must match baseline_hashes exactly
            hashes_unchanged = (pre_hashes == baseline_hashes and post_hashes == baseline_hashes)
            scan_info["hashesUnchanged"] = hashes_unchanged

            has_error_logs = "ERROR" in raw_stderr or "FATAL" in raw_stderr
            scan_info["hasErrorLogs"] = has_error_logs

            # If report was not generated, record and do not synthesize manifest
            if not report_file.is_file():
                scan_info["validation"] = {"status": "missing_report"}
                scan_info["manifestOmittedReason"] = "Report file was not generated"
                capture_records["scans"][side] = scan_info
                all_scans_succeeded = False
                continue

            raw_report_bytes = report_file.read_bytes()
            report_sha256 = _calc_sha256(raw_report_bytes)
            scan_info["report"] = {
                "file": f"{side}.json",
                "sha256": report_sha256,
            }

            # Parse and validate raw Trivy report using existing strict reader and validator
            report_valid = True
            validation_errors: list[str] = []
            findings_count = 0

            source_input = read_source_file(report_file, side, "report")
            if source_input.parse_state != "valid":
                report_valid = False
                validation_errors.append(f"Reader invalid parse_state: {source_input.parse_state}")
                validation_errors.extend(f"{r.code}:{','.join(ref.pointer for ref in r.refs)}" for r in source_input.reasons)
                report_obj = None
            else:
                schema_reasons = validate_source(source_input)
                if source_input.parse_state != "valid" or schema_reasons:
                    report_valid = False
                    validation_errors.append("Schema validation failed")
                    validation_errors.extend(f"{r.code}:{','.join(ref.pointer for ref in r.refs)}" for r in schema_reasons)
                    report_obj = None
                else:
                    report_obj = source_input.data

            if report_valid and isinstance(report_obj, dict):
                # 1. Top-level checks
                if report_obj.get("SchemaVersion") != 2:
                    report_valid = False
                    validation_errors.append(f"Unexpected SchemaVersion: {report_obj.get('SchemaVersion')}")

                if report_obj.get("ArtifactType") != "container_image":
                    report_valid = False
                    validation_errors.append(f"Unexpected ArtifactType: {report_obj.get('ArtifactType')}")

                # 2. Metadata checks
                metadata_section = report_obj.get("Metadata")
                if not isinstance(metadata_section, dict):
                    report_valid = False
                    validation_errors.append("Metadata must be a JSON object")
                    metadata_section = {}

                repo_digests = metadata_section.get("RepoDigests")
                if not isinstance(repo_digests, list) or exact_ref not in repo_digests:
                    report_valid = False
                    validation_errors.append(f"RepoDigests does not contain exact ref {exact_ref!r}: {repo_digests!r}")

                actual_img_id = metadata_section.get("ImageID")
                if actual_img_id != config_digest:
                    report_valid = False
                    validation_errors.append(f"ImageID mismatch: expected {config_digest}, got {actual_img_id}")

                img_cfg = metadata_section.get("ImageConfig")
                if not isinstance(img_cfg, dict):
                    report_valid = False
                    validation_errors.append("ImageConfig must be a JSON object")
                    img_cfg = {}

                if (
                    img_cfg.get("os") != "linux"
                    or img_cfg.get("architecture") != "amd64"
                    or img_cfg.get("variant", "") not in ("", None)
                ):
                    report_valid = False
                    validation_errors.append(
                        f"ImageConfig platform mismatch: os={img_cfg.get('os')}, arch={img_cfg.get('architecture')}, variant={img_cfg.get('variant')}"
                    )

                # 3. Results checks (strictly exactly 1 Result: Target='Node.js', Class='lang-pkgs', Type='node-pkg')
                results = report_obj.get("Results")
                if not isinstance(results, list):
                    report_valid = False
                    validation_errors.append("Results must be a list")
                elif len(results) != 1:
                    report_valid = False
                    validation_errors.append(f"Results must contain exactly 1 item, got {len(results)}")
                else:
                    matching_res = results[0]
                    if not isinstance(matching_res, dict):
                        report_valid = False
                        validation_errors.append("Result item must be a JSON object")
                    elif (
                        matching_res.get("Target") != "Node.js"
                        or matching_res.get("Class") != "lang-pkgs"
                        or matching_res.get("Type") != "node-pkg"
                    ):
                        report_valid = False
                        validation_errors.append(
                            f"Result mismatch: Target={matching_res.get('Target')!r}, Class={matching_res.get('Class')!r}, Type={matching_res.get('Type')!r}"
                        )
                    else:
                        # 4. Packages checks (strictly exactly 1 Package: expected lodash)
                        pkgs = matching_res.get("Packages")
                        if not isinstance(pkgs, list):
                            report_valid = False
                            validation_errors.append("Packages must be a list")
                        elif len(pkgs) != 1:
                            report_valid = False
                            validation_errors.append(f"Packages must contain exactly 1 item, got {len(pkgs)}")
                        else:
                            p = pkgs[0]
                            if not isinstance(p, dict):
                                report_valid = False
                                validation_errors.append("Package item must be a JSON object")
                            elif (
                                p.get("Name") != "lodash"
                                or p.get("Version") != expected_ver
                                or p.get("FilePath") != "app/node_modules/lodash/package.json"
                                or p.get("AnalyzedBy") != "node-pkg"
                            ):
                                report_valid = False
                                validation_errors.append(
                                    f"Package mismatch: Name={p.get('Name')!r}, Version={p.get('Version')!r}, FilePath={p.get('FilePath')!r}, AnalyzedBy={p.get('AnalyzedBy')!r}"
                                )

                        vulns = matching_res.get("Vulnerabilities")
                        if vulns is None:
                            findings_count = 0
                        elif isinstance(vulns, list):
                            findings_count = len(vulns)
                        else:
                            report_valid = False
                            validation_errors.append("Vulnerabilities must be a list or omitted")

            scan_info["validation"] = {
                "reportValid": report_valid,
                "errors": validation_errors,
                "findingsCount": findings_count,
            }

            # Determine execution status and coverage
            if (
                report_valid
                and hashes_unchanged
                and not has_error_logs
                and not timed_out
                and proc_returncode is not None
            ):
                if proc_returncode == 10 and findings_count > 0:
                    exec_success = True
                    exec_completed = True
                    exec_report_complete = True
                    exit_cause = "findings_policy"
                    coverage_status = "scanned"
                    completeness = "complete"
                elif proc_returncode == 0 and findings_count == 0:
                    exec_success = True
                    exec_completed = True
                    exec_report_complete = True
                    exit_cause = "normal"
                    coverage_status = "scanned"
                    completeness = "complete"
                else:
                    exec_success = False
                    exec_completed = False
                    exec_report_complete = False
                    exit_cause = "unknown"
                    coverage_status = "failed"
                    completeness = "unknown"
                    all_scans_succeeded = False
            else:
                exec_success = False
                exec_completed = False
                exec_report_complete = False
                exit_cause = "failure" if (has_error_logs or not hashes_unchanged) else "unknown"
                coverage_status = "failed"
                completeness = "unknown"
                all_scans_succeeded = False

            # Check if manifest can be written according to schema requirements:
            # - exitCode must be integer in range 0..255 (manifest.schema.json)
            # - snapshotSha256 must be present
            # - reportSha256 must be present
            can_write_manifest = (
                isinstance(proc_returncode, int)
                and not isinstance(proc_returncode, bool)
                and 0 <= proc_returncode <= 255
                and post_hashes.get("db") is not None
                and report_file.is_file()
            )

            if can_write_manifest:
                manifest_data = {
                    "schemaVersion": 1,
                    "reportSha256": report_sha256,
                    "scanner": {
                        "name": "trivy",
                        "mode": "image",
                        "version": EXPECTED_TRIVY_VERSION,
                    },
                    "databases": [
                        {
                            "role": "vuln",
                            "snapshotSha256": post_hashes["db"],
                            "schemaVersion": db_schema_version,
                            "updatedAt": db_updated_at,
                            "repository": EXPECTED_DB_REPOSITORY,
                            "ociDigest": None,
                        }
                    ],
                    "effectiveConfig": {
                        "completeness": completeness,
                        "scanners": ["vuln"],
                        "packageTypes": ["library"],
                        "severity": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "ignoreUnfixed": False,
                        "ignoreStatus": [],
                        "skipDirs": [],
                        "skipFiles": [],
                        "ignoreFiles": [
                            {
                                "logicalId": "empty-ignore",
                                "contentSha256": EMPTY_RULES_SHA256,
                                "appliedRulesSha256": EMPTY_RULES_SHA256,
                            }
                        ],
                        "vex": [],
                        "regoPolicies": [],
                        "configFiles": [
                            {
                                "logicalId": "empty-config",
                                "contentSha256": empty_config_sha256,
                                "appliedRulesSha256": EMPTY_RULES_SHA256,
                            }
                        ],
                        "extraOptions": {
                            "detection-priority": "precise",
                            "disable-telemetry": True,
                            "exit-code": 10,
                            "exit-on-eol": 0,
                            "image-src": "remote",
                            "insecure": True,
                            "list-all-pkgs": True,
                            "offline-scan": True,
                            "platform": "linux/amd64",
                            "skip-check-update": True,
                            "skip-db-update": True,
                            "skip-java-db-update": True,
                            "skip-version-check": True,
                            "skip-vex-repo-update": True,
                        },
                    },
                    "target": {
                        "logicalId": "local-lodash-sample",
                        "imageDigest": manifest_digest,
                        "platform": {
                            "os": "linux",
                            "architecture": "amd64",
                            "variant": "",
                        },
                        "scopes": [
                            {
                                "logicalTargetId": "installed-lodash",
                                "rawTarget": "Node.js",
                                "path": "app/node_modules/lodash/package.json",
                                "class": "lang-pkgs",
                                "ecosystem": "node-pkg",
                                "expected": True,
                                "coverage": coverage_status,
                            }
                        ],
                    },
                    "execution": {
                        "success": exec_success,
                        "completed": exec_completed,
                        "reportComplete": exec_report_complete,
                        "exitCode": proc_returncode,
                        "configuredExitCode": 10,
                        "configuredExitOnEol": 0,
                        "exitCause": exit_cause,
                    },
                }
                manifest_file = out_dir / f"{side}.manifest.json"
                manifest_file.write_text(json.dumps(manifest_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            else:
                reason_msg = []
                if not (isinstance(proc_returncode, int) and 0 <= proc_returncode <= 255):
                    reason_msg.append(f"exitCode not in range 0..255 ({proc_returncode!r})")
                if post_hashes.get("db") is None:
                    reason_msg.append("Missing database snapshot SHA")
                if not report_file.is_file():
                    reason_msg.append("Missing report file")
                scan_info["manifestOmittedReason"] = "; ".join(reason_msg)

            capture_records["scans"][side] = scan_info

    # 6. Save execution capture
    capture_file = out_dir / "capture.json"
    capture_file.write_text(json.dumps(capture_records, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return 0 if all_scans_succeeded else 1


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for collect_real_scan."""
    parser = argparse.ArgumentParser(
        description="Run official Trivy 0.75.0 verification harness and collect manifests/reports for fixed sample."
    )
    parser.add_argument("--trivy", required=True, help="Path to official Trivy 0.75.0 executable")
    parser.add_argument("--cache-dir", required=True, help="Path to Trivy cache directory")
    parser.add_argument("--before-archive", required=True, help="Path to lodash-4.17.20.tar.gz")
    parser.add_argument("--after-archive", required=True, help="Path to lodash-4.17.21.tar.gz")
    parser.add_argument("--out-dir", required=True, help="Target output directory (must not exist)")

    args = parser.parse_args(argv)

    try:
        return collect_scans(
            trivy_path=args.trivy,
            cache_dir=args.cache_dir,
            before_archive=args.before_archive,
            after_archive=args.after_archive,
            out_dir=args.out_dir,
        )
    except FileExistsError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
