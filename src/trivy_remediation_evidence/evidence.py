from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .comparator import ComparisonResult, compare_manifests_and_reports
from .models import SourceInput
from .reader import read_source_file
from .validator import (
    DEFAULT_SCHEMAS_DIR,
    HAS_JSONSCHEMA,
    MissingDependencyError,
    get_validator,
    validate_evidence,
    validate_source,
)


def build_scan_evidence(
    manifest_src: SourceInput,
    report_src: SourceInput,
) -> dict[str, Any] | None:
    """Build normalized scanEvidence dict for one side (before or after).

    Returns None if manifest is not valid schema or data is missing.
    """
    if manifest_src.parse_state != "valid" or not isinstance(manifest_src.data, dict):
        return None

    m_data = manifest_src.data

    # 1. scanner
    scanner_raw = m_data.get("scanner", {})
    scanner = {
        "mode": scanner_raw.get("mode", "image"),
        "name": scanner_raw.get("name", "trivy"),
        "version": scanner_raw.get("version", ""),
    }

    # 2. databases (sorted by role)
    dbs_raw = m_data.get("databases", [])
    databases = [
        {
            "ociDigest": db.get("ociDigest"),
            "repository": db.get("repository", ""),
            "role": db.get("role", ""),
            "schemaVersion": db.get("schemaVersion", 1),
            "snapshotSha256": db.get("snapshotSha256", ""),
            "updatedAt": db.get("updatedAt", ""),
        }
        for db in dbs_raw
        if isinstance(db, dict)
    ]
    databases.sort(key=lambda d: str(d["role"]))

    # 3. effectiveConfig (sorted sets and assets)
    ec_raw = m_data.get("effectiveConfig", {})

    def _sort_assets(assets_list: Any) -> list[dict[str, str]]:
        if not isinstance(assets_list, list):
            return []
        res = [
            {
                "appliedRulesSha256": a.get("appliedRulesSha256", ""),
                "contentSha256": a.get("contentSha256", ""),
                "logicalId": a.get("logicalId", ""),
            }
            for a in assets_list
            if isinstance(a, dict)
        ]
        res.sort(
            key=lambda x: (
                str(x["logicalId"]),
                str(x["contentSha256"]),
                str(x["appliedRulesSha256"]),
            )
        )
        return res

    effective_config = {
        "completeness": ec_raw.get("completeness", "complete"),
        "configFiles": _sort_assets(ec_raw.get("configFiles")),
        "extraOptions": ec_raw.get("extraOptions", {}) if isinstance(ec_raw.get("extraOptions"), dict) else {},
        "ignoreFiles": _sort_assets(ec_raw.get("ignoreFiles")),
        "ignoreStatus": sorted(ec_raw.get("ignoreStatus", [])) if isinstance(ec_raw.get("ignoreStatus"), list) else [],
        "ignoreUnfixed": bool(ec_raw.get("ignoreUnfixed", False)),
        "packageTypes": sorted(ec_raw.get("packageTypes", [])) if isinstance(ec_raw.get("packageTypes"), list) else [],
        "regoPolicies": _sort_assets(ec_raw.get("regoPolicies")),
        "scanners": sorted(ec_raw.get("scanners", [])) if isinstance(ec_raw.get("scanners"), list) else [],
        "severity": sorted(ec_raw.get("severity", [])) if isinstance(ec_raw.get("severity"), list) else [],
        "skipDirs": sorted(ec_raw.get("skipDirs", [])) if isinstance(ec_raw.get("skipDirs"), list) else [],
        "skipFiles": sorted(ec_raw.get("skipFiles", [])) if isinstance(ec_raw.get("skipFiles"), list) else [],
        "vex": _sort_assets(ec_raw.get("vex")),
    }

    # 4. target (platform and sorted scopes)
    target_raw = m_data.get("target", {})
    plat_raw = target_raw.get("platform", {})
    platform = {
        "architecture": plat_raw.get("architecture", ""),
        "os": plat_raw.get("os", ""),
        "variant": plat_raw.get("variant", ""),
    }

    scopes_raw = target_raw.get("scopes", [])
    scopes = [
        {
            "class": sc.get("class", ""),
            "coverage": sc.get("coverage", ""),
            "ecosystem": sc.get("ecosystem", ""),
            "expected": bool(sc.get("expected", True)),
            "logicalTargetId": sc.get("logicalTargetId", ""),
            "path": sc.get("path", ""),
            "rawTarget": sc.get("rawTarget", ""),
        }
        for sc in scopes_raw
        if isinstance(sc, dict)
    ]
    scopes.sort(
        key=lambda s: (
            str(s["logicalTargetId"]),
            str(s["path"]),
            str(s["class"]),
            str(s["ecosystem"]),
        )
    )

    target = {
        "imageDigest": target_raw.get("imageDigest", ""),
        "logicalId": target_raw.get("logicalId", ""),
        "platform": platform,
        "scopes": scopes,
    }

    # 5. execution
    ex_raw = m_data.get("execution", {})
    execution = {
        "completed": bool(ex_raw.get("completed", False)),
        "configuredExitCode": ex_raw.get("configuredExitCode", 0),
        "configuredExitOnEol": ex_raw.get("configuredExitOnEol", 0),
        "exitCause": ex_raw.get("exitCause", "unknown"),
        "exitCode": ex_raw.get("exitCode", 0),
        "reportComplete": bool(ex_raw.get("reportComplete", False)),
        "success": bool(ex_raw.get("success", False)),
    }

    # 6. reportMetadata (never extract unknown report fields)
    if report_src.parse_state == "valid" and isinstance(report_src.data, dict):
        meta_raw = report_src.data.get("Metadata", {}) if isinstance(report_src.data.get("Metadata"), dict) else {}
        repo_digests_raw = meta_raw.get("RepoDigests", [])
        repo_digests = sorted(set(repo_digests_raw)) if isinstance(repo_digests_raw, list) else []
        report_metadata = {
            "imageId": meta_raw.get("ImageID"),
            "repoDigests": repo_digests,
        }
    else:
        report_metadata = {
            "imageId": None,
            "repoDigests": [],
        }

    return {
        "databases": databases,
        "effectiveConfig": effective_config,
        "execution": execution,
        "reportMetadata": report_metadata,
        "scanner": scanner,
        "target": target,
    }


def build_evidence_dict(
    before_manifest: SourceInput,
    after_manifest: SourceInput,
    before_report: SourceInput,
    after_report: SourceInput,
    comparison_res: ComparisonResult | None = None,
) -> dict[str, Any]:
    """Construct complete Evidence dictionary matching schemas/evidence.schema.json."""
    if comparison_res is None:
        comparison_res = compare_manifests_and_reports(
            before_manifest, after_manifest, before_report, after_report
        )

    # 4 sources in strictly defined fixed order:
    # 1: before report, 2: before manifest, 3: after report, 4: after manifest
    sources = [
        before_report.to_source_dict(),
        before_manifest.to_source_dict(),
        after_report.to_source_dict(),
        after_manifest.to_source_dict(),
    ]

    scan_evidence = {
        "after": build_scan_evidence(after_manifest, after_report),
        "before": build_scan_evidence(before_manifest, before_report),
    }

    evidence = {
        "comparison": comparison_res.comparison,
        "globalReasons": [r.to_dict() for r in comparison_res.global_reasons],
        "items": [it.to_dict() for it in comparison_res.items],
        "observedCounts": comparison_res.observed_counts,
        "scanEvidence": scan_evidence,
        "schemaVersion": 1,
        "sources": sources,
        "summary": comparison_res.summary,
    }

    return evidence


def canonical_json_dumps(data: Any) -> str:
    """Serialize data into deterministic canonical JSON (2-space indent, keys sorted, LF, no trailing whitespace)."""
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize data into deterministic canonical JSON bytes (UTF-8, no BOM)."""
    return canonical_json_dumps(data).encode("utf-8")


def run_pipeline(
    before_report_path: Path | str,
    after_report_path: Path | str,
    before_manifest_path: Path | str,
    after_manifest_path: Path | str,
    schemas_dir: Path | str | None = None,
) -> tuple[dict[str, Any], int, bytes]:
    """Internal API: Read inputs, validate schema, evaluate gate & identity, return (evidence_dict, exit_code, json_bytes).

    Raises:
        MissingDependencyError: if jsonschema dependency is not available.
        ValueError: if evidence schema validation fails.
    """
    if not HAS_JSONSCHEMA:
        raise MissingDependencyError("Missing required dependency: jsonschema")

    br = read_source_file(before_report_path, "before", "report")
    ar = read_source_file(after_report_path, "after", "report")
    bm = read_source_file(before_manifest_path, "before", "manifest")
    am = read_source_file(after_manifest_path, "after", "manifest")

    validate_source(br, schemas_dir)
    validate_source(ar, schemas_dir)
    validate_source(bm, schemas_dir)
    validate_source(am, schemas_dir)

    comparison_res = compare_manifests_and_reports(bm, am, br, ar)
    evidence_dict = build_evidence_dict(bm, am, br, ar, comparison_res)

    # Validate output evidence dict against evidence.schema.json
    validate_evidence(evidence_dict, schemas_dir)

    json_bytes = canonical_json_bytes(evidence_dict)

    return evidence_dict, comparison_res.cli_exit_code, json_bytes

