from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal

from .manifest_gate import evaluate_manifest_gate
from .models import SourceInput
from .reasons import InputKind, InputRef, Reason, Side

# Pattern strictly matching valid path according to evidence.schema.json
# @os or POSIX relative path with no leading slash, no consecutive slashes,
# no . or .. segments, and no backslashes.
PATH_PATTERN = re.compile(
    r"^(?:@os|(?!(?:.*\\|/|.*//|.*(?:^|/)\.{1,2}(?:/|$)))[^/]+(?:/[^/]+)*)$"
)


def _extract_str_or_null(d: dict[str, Any], key: str) -> str | None:
    if key in d:
        val = d[key]
        if isinstance(val, str):
            return val
    return None


def _extract_purl(vuln: dict[str, Any]) -> str | None:
    pkg_ident = vuln.get("PkgIdentifier")
    if isinstance(pkg_ident, dict) and "PURL" in pkg_ident:
        p = pkg_ident["PURL"]
        if isinstance(p, str):
            return p
    return None


def _parse_pointer_indices(pointer: str) -> tuple[int, ...]:
    parts = pointer.strip("/").split("/")
    indices: list[int] = []
    for p in parts:
        if p.isdigit():
            indices.append(int(p))
    return tuple(indices)


@dataclass(frozen=True)
class Identity:
    image_logical_id: str
    target_logical_id: str
    path: str
    class_: str
    ecosystem: str
    package_name: str
    vulnerability_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "imageLogicalId": self.image_logical_id,
            "targetLogicalId": self.target_logical_id,
            "path": self.path,
            "class": self.class_,
            "ecosystem": self.ecosystem,
            "packageName": self.package_name,
            "vulnerabilityId": self.vulnerability_id,
        }

    def sort_key(self) -> tuple[str, str, str, str, str, str, str]:
        return (
            self.image_logical_id,
            self.target_logical_id,
            self.path,
            self.class_,
            self.ecosystem,
            self.package_name,
            self.vulnerability_id,
        )


@dataclass
class FindingObservation:
    source: InputRef
    installed_version: str | None
    fixed_version: str | None
    status: str | None
    pkg_id: str | None
    purl: str | None
    severity: str | None
    title: str | None
    pkg_path: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "installedVersion": self.installed_version,
            "fixedVersion": self.fixed_version,
            "status": self.status,
            "pkgId": self.pkg_id,
            "purl": self.purl,
            "severity": self.severity,
            "title": self.title,
            "pkgPath": self.pkg_path,
        }


@dataclass
class EvidenceItem:
    identity: Identity | None
    classification: Literal["new", "persistent", "not_detected", "comparison_unavailable"]
    remediation_conclusion: Literal["not_established"] = "not_established"
    before: list[FindingObservation] = field(default_factory=list)
    after: list[FindingObservation] = field(default_factory=list)
    reasons: list[Reason] = field(default_factory=list)

    @property
    def before_pointers(self) -> list[str]:
        return [obs.source.pointer for obs in self.before]

    @property
    def after_pointers(self) -> list[str]:
        return [obs.source.pointer for obs in self.after]

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict() if self.identity else None,
            "classification": self.classification,
            "remediationConclusion": self.remediation_conclusion,
            "before": [obs.to_dict() for obs in self.before],
            "after": [obs.to_dict() for obs in self.after],
            "reasons": [r.to_dict() for r in self.reasons],
        }


@dataclass
class ComparisonResult:
    comparison: Literal["comparable", "comparison_unavailable"]
    global_reasons: list[Reason]
    observed_counts: dict[str, int | None]
    summary: dict[str, int]
    items: list[EvidenceItem]
    cli_exit_code: int


def _item_sort_key(item: EvidenceItem) -> tuple[Any, ...]:
    if item.identity is not None:
        return (0, *item.identity.sort_key())
    else:
        first_obs = item.before[0] if item.before else item.after[0]
        return (1, first_obs.source.side, _parse_pointer_indices(first_obs.source.pointer))


@dataclass
class _ExtractedFinding:
    side: Side
    identity: Identity | None
    obs: FindingObservation
    scope_idx: int | None
    scope_tuple: tuple[str, str, str, str] | None
    failure_reason: Reason | None


def _extract_findings_from_side(
    side: Side,
    manifest_src: SourceInput,
    report_src: SourceInput,
) -> tuple[list[_ExtractedFinding], int | None, list[Reason]]:
    findings: list[_ExtractedFinding] = []
    reasons: list[Reason] = []

    if report_src.parse_state != "valid" or not isinstance(report_src.data, dict):
        return [], None, reasons

    results = report_src.data.get("Results")
    if not isinstance(results, list):
        return [], 0, reasons

    raw_finding_count = 0

    manifest_data = manifest_src.data if isinstance(manifest_src.data, dict) else {}
    target_obj = manifest_data.get("target") if isinstance(manifest_data.get("target"), dict) else {}
    image_logical_id = target_obj.get("logicalId")
    scopes = target_obj.get("scopes") if isinstance(target_obj.get("scopes"), list) else []

    for r_idx, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        vulns = result.get("Vulnerabilities")
        if not isinstance(vulns, list):
            continue

        raw_target = result.get("Target")
        class_val = result.get("Class")
        type_val = result.get("Type")

        # Match all matching scopes and verify exact uniqueness and individual field validity
        matching_scopes: list[tuple[int, dict[str, Any]]] = []
        for s_idx, scope in enumerate(scopes):
            if isinstance(scope, dict):
                if (
                    scope.get("rawTarget") == raw_target
                    and scope.get("class") == class_val
                    and scope.get("ecosystem") == type_val
                ):
                    lt_id = scope.get("logicalTargetId")
                    sc_path = scope.get("path")
                    sc_class = scope.get("class")
                    sc_eco = scope.get("ecosystem")
                    if (
                        isinstance(lt_id, str)
                        and len(lt_id) > 0
                        and isinstance(sc_path, str)
                        and bool(PATH_PATTERN.match(sc_path))
                        and isinstance(sc_class, str)
                        and sc_class in ("os-pkgs", "lang-pkgs")
                        and isinstance(sc_eco, str)
                        and len(sc_eco) > 0
                    ):
                        matching_scopes.append((s_idx, scope))

        matched_scope_idx: int | None = None
        matched_scope: dict[str, Any] | None = None
        matched_scope_tuple: tuple[str, str, str, str] | None = None
        if len(matching_scopes) == 1:
            matched_scope_idx, matched_scope = matching_scopes[0]
            matched_scope_tuple = (
                str(matched_scope["logicalTargetId"]),
                str(matched_scope["path"]),
                str(matched_scope["class"]),
                str(matched_scope["ecosystem"]),
            )

        for v_idx, vuln in enumerate(vulns):
            raw_finding_count += 1
            v_ptr = f"/Results/{r_idx}/Vulnerabilities/{v_idx}"
            source_ref = InputRef(side, "report", v_ptr)

            if not isinstance(vuln, dict):
                reason = Reason("IDENTITY_MISSING", (source_ref,))
                reasons.append(reason)
                findings.append(
                    _ExtractedFinding(
                        side=side,
                        identity=None,
                        obs=FindingObservation(
                            source=source_ref,
                            installed_version=None,
                            fixed_version=None,
                            status=None,
                            pkg_id=None,
                            purl=None,
                            severity=None,
                            title=None,
                            pkg_path=None,
                        ),
                        scope_idx=matched_scope_idx,
                        scope_tuple=matched_scope_tuple,
                        failure_reason=reason,
                    )
                )
                continue

            obs = FindingObservation(
                source=source_ref,
                installed_version=_extract_str_or_null(vuln, "InstalledVersion"),
                fixed_version=_extract_str_or_null(vuln, "FixedVersion"),
                status=_extract_str_or_null(vuln, "Status"),
                pkg_id=_extract_str_or_null(vuln, "PkgID"),
                purl=_extract_purl(vuln),
                severity=_extract_str_or_null(vuln, "Severity"),
                title=_extract_str_or_null(vuln, "Title"),
                pkg_path=_extract_str_or_null(vuln, "PkgPath"),
            )

            # Identity building
            fail_reason: Reason | None = None

            if matched_scope is None:
                fail_reason = Reason("IDENTITY_MISSING", (source_ref,))
            elif not image_logical_id or not isinstance(image_logical_id, str):
                fail_reason = Reason("IDENTITY_MISSING", (source_ref,))
            elif "PkgName" not in vuln:
                # Omitted: points to parent finding
                fail_reason = Reason("IDENTITY_MISSING", (source_ref,))
            elif not isinstance(vuln["PkgName"], str) or len(vuln["PkgName"]) == 0:
                # Present but empty or type violation: points to child PkgName
                fail_reason = Reason(
                    "IDENTITY_MISSING",
                    (InputRef(side, "report", f"{v_ptr}/PkgName"),),
                )
            elif "VulnerabilityID" not in vuln:
                # Omitted: points to parent finding
                fail_reason = Reason("IDENTITY_MISSING", (source_ref,))
            elif not isinstance(vuln["VulnerabilityID"], str) or len(vuln["VulnerabilityID"]) == 0:
                # Present but empty or type violation: points to child VulnerabilityID
                fail_reason = Reason(
                    "IDENTITY_MISSING",
                    (InputRef(side, "report", f"{v_ptr}/VulnerabilityID"),),
                )
            else:
                # Path resolution
                pkg_path = vuln.get("PkgPath")
                if pkg_path is not None and isinstance(pkg_path, str) and len(pkg_path) > 0:
                    resolved_path = pkg_path
                    path_from_pkg = True
                else:
                    resolved_path = matched_scope.get("path")
                    path_from_pkg = False

                if not resolved_path or not isinstance(resolved_path, str) or not PATH_PATTERN.match(resolved_path):
                    ptr = (
                        f"{v_ptr}/PkgPath"
                        if path_from_pkg
                        else f"/target/scopes/{matched_scope_idx}/path"
                    )
                    kind: InputKind = "report" if path_from_pkg else "manifest"
                    fail_reason = Reason("IDENTITY_PATH_INVALID", (InputRef(side, kind, ptr),))

            if fail_reason is not None:
                reasons.append(fail_reason)
                findings.append(
                    _ExtractedFinding(
                        side=side,
                        identity=None,
                        obs=obs,
                        scope_idx=matched_scope_idx,
                        scope_tuple=matched_scope_tuple,
                        failure_reason=fail_reason,
                    )
                )
            else:
                target_logical_id = str(matched_scope["logicalTargetId"])
                class_str = str(matched_scope.get("class", class_val or ""))
                ecosystem_str = str(matched_scope.get("ecosystem", type_val or ""))
                identity = Identity(
                    image_logical_id=str(image_logical_id),
                    target_logical_id=target_logical_id,
                    path=str(resolved_path),
                    class_=class_str,
                    ecosystem=ecosystem_str,
                    package_name=str(vuln["PkgName"]),
                    vulnerability_id=str(vuln["VulnerabilityID"]),
                )
                findings.append(
                    _ExtractedFinding(
                        side=side,
                        identity=identity,
                        obs=obs,
                        scope_idx=matched_scope_idx,
                        scope_tuple=matched_scope_tuple,
                        failure_reason=None,
                    )
                )

    return findings, raw_finding_count, reasons


def compare_manifests_and_reports(
    before_manifest: SourceInput,
    after_manifest: SourceInput,
    before_report: SourceInput,
    after_report: SourceInput,
) -> ComparisonResult:
    """Compare manifests and reports to produce identity-matched comparison result."""
    # 1. Gate reasons from stage 1 & 2
    # Ensure any source with non-valid parse_state has a corresponding reason even if manually synthesized
    state_reasons: list[Reason] = []
    for src in [before_manifest, after_manifest, before_report, after_report]:
        if src.parse_state != "valid" and not src.reasons:
            code_map: dict[str, Any] = {
                "invalid_json": "INPUT_INVALID_JSON",
                "invalid_schema": "INPUT_SCHEMA_INVALID",
                "unreadable": "INPUT_UNREADABLE",
                "limit_exceeded": "INPUT_LIMIT_EXCEEDED",
            }
            code = code_map.get(src.parse_state, "INPUT_INVALID_JSON")
            state_reasons.append(Reason(code, (InputRef(src.side, src.kind, ""),)))

    gate_reasons = evaluate_manifest_gate(
        before_manifest, after_manifest, before_report, after_report
    ) + state_reasons

    # 2. Extract findings
    before_findings, before_raw_count, before_id_reasons = _extract_findings_from_side(
        "before", before_manifest, before_report
    )
    after_findings, after_raw_count, after_id_reasons = _extract_findings_from_side(
        "after", after_manifest, after_report
    )

    observed_counts: dict[str, int | None] = {
        "before": before_raw_count,
        "after": after_raw_count,
    }

    # Total findings limit (100,000)
    total_findings = (before_raw_count or 0) + (after_raw_count or 0)
    limit_reasons: list[Reason] = []
    if total_findings > 100_000:
        limit_refs: list[InputRef] = []
        if (before_raw_count or 0) > 0:
            limit_refs.append(InputRef("before", "report", "/Results"))
        if (after_raw_count or 0) > 0:
            limit_refs.append(InputRef("after", "report", "/Results"))
        limit_reasons.append(Reason("INPUT_LIMIT_EXCEEDED", tuple(sorted(limit_refs))))

    # Duplicate identity check within each side
    duplicate_reasons: list[Reason] = []
    before_id_map: dict[Identity, list[_ExtractedFinding]] = defaultdict(list)
    after_id_map: dict[Identity, list[_ExtractedFinding]] = defaultdict(list)

    before_unresolved: list[_ExtractedFinding] = []
    after_unresolved: list[_ExtractedFinding] = []

    for f in before_findings:
        if f.identity is not None:
            before_id_map[f.identity].append(f)
        else:
            before_unresolved.append(f)

    for f in after_findings:
        if f.identity is not None:
            after_id_map[f.identity].append(f)
        else:
            after_unresolved.append(f)

    # Check duplicates in before and after
    dup_refs: list[InputRef] = []
    for id_val, flist in before_id_map.items():
        if len(flist) > 1:
            for item in flist:
                dup_refs.append(item.obs.source)

    for id_val, flist in after_id_map.items():
        if len(flist) > 1:
            for item in flist:
                dup_refs.append(item.obs.source)

    if dup_refs:
        duplicate_reasons.append(Reason("DUPLICATE_IDENTITY", tuple(sorted(set(dup_refs)))))

    # Combine global reasons
    all_global_reasons_raw = (
        gate_reasons
        + before_id_reasons
        + after_id_reasons
        + limit_reasons
        + duplicate_reasons
    )

    # Deduplicate reasons by (code, refs)
    seen_reasons: dict[tuple[str, tuple[InputRef, ...]], Reason] = {}
    for r in all_global_reasons_raw:
        sorted_refs = tuple(sorted(set(r.refs)))
        key = (r.code, sorted_refs)
        if key not in seen_reasons:
            seen_reasons[key] = Reason(r.code, sorted_refs)

    global_reasons = sorted(seen_reasons.values(), key=lambda r: r.sort_key())

    # Gate outcome
    is_comparable = len(global_reasons) == 0

    items: list[EvidenceItem] = []

    # Map scopes for cross-referencing on empty side
    before_scopes: list[dict[str, Any]] = []
    if isinstance(before_manifest.data, dict) and isinstance(before_manifest.data.get("target"), dict):
        before_scopes = before_manifest.data["target"].get("scopes", [])

    after_scopes: list[dict[str, Any]] = []
    if isinstance(after_manifest.data, dict) and isinstance(after_manifest.data.get("target"), dict):
        after_scopes = after_manifest.data["target"].get("scopes", [])

    def find_opposite_scope_idx(
        scopes: list[dict[str, Any]],
        target_tuple: tuple[str, str, str, str] | None,
    ) -> int | None:
        if target_tuple is None:
            return None
        matches: list[int] = []
        for idx, sc in enumerate(scopes):
            if isinstance(sc, dict):
                sc_tuple = (
                    str(sc.get("logicalTargetId", "")),
                    str(sc.get("path", "")),
                    str(sc.get("class", "")),
                    str(sc.get("ecosystem", "")),
                )
                if sc_tuple == target_tuple:
                    matches.append(idx)
        if len(matches) == 1:
            return matches[0]
        return None

    all_identities = set(before_id_map.keys()) | set(after_id_map.keys())

    for id_val in all_identities:
        b_list = before_id_map.get(id_val, [])
        a_list = after_id_map.get(id_val, [])

        b_obs = [f.obs for f in b_list]
        a_obs = [f.obs for f in a_list]

        b_obs.sort(key=lambda o: _parse_pointer_indices(o.source.pointer))
        a_obs.sort(key=lambda o: _parse_pointer_indices(o.source.pointer))

        if is_comparable:
            if len(b_obs) > 0 and len(a_obs) > 0:
                classification = "persistent"
                refs = tuple(sorted([o.source for o in b_obs] + [o.source for o in a_obs]))
                item_reasons = [Reason("SAME_IDENTITY", refs)]
            elif len(b_obs) == 0 and len(a_obs) > 0:
                classification = "new"
                source_scope_tuple = a_list[0].scope_tuple
                s_idx = find_opposite_scope_idx(before_scopes, source_scope_tuple)
                coverage_ref = (
                    InputRef("before", "manifest", f"/target/scopes/{s_idx}/coverage")
                    if s_idx is not None
                    else InputRef("before", "manifest", "/target/scopes")
                )
                refs_list = [o.source for o in a_obs] + [
                    coverage_ref,
                    InputRef("before", "report", "/Results"),
                ]
                item_reasons = [Reason("NEW_OBSERVATION", tuple(sorted(refs_list)))]
            else:  # len(b_obs) > 0 and len(a_obs) == 0
                classification = "not_detected"
                source_scope_tuple = b_list[0].scope_tuple
                s_idx = find_opposite_scope_idx(after_scopes, source_scope_tuple)
                coverage_ref = (
                    InputRef("after", "manifest", f"/target/scopes/{s_idx}/coverage")
                    if s_idx is not None
                    else InputRef("after", "manifest", "/target/scopes")
                )
                refs_list = [o.source for o in b_obs] + [
                    coverage_ref,
                    InputRef("after", "report", "/Results"),
                ]
                item_reasons = [Reason("NOT_DETECTED_UNDER_EQUAL_CONDITIONS", tuple(sorted(refs_list)))]
        else:
            classification = "comparison_unavailable"
            item_reasons = list(global_reasons)

        item = EvidenceItem(
            identity=id_val,
            classification=classification,
            remediation_conclusion="not_established",
            before=b_obs,
            after=a_obs,
            reasons=item_reasons,
        )
        items.append(item)

    # Add unresolved items (identity = None)
    for f in before_unresolved:
        reasons_for_item = list(global_reasons)
        if f.failure_reason is not None and f.failure_reason not in reasons_for_item:
            reasons_for_item.append(f.failure_reason)
            reasons_for_item.sort(key=lambda r: r.sort_key())

        item = EvidenceItem(
            identity=None,
            classification="comparison_unavailable",
            remediation_conclusion="not_established",
            before=[f.obs],
            after=[],
            reasons=reasons_for_item,
        )
        items.append(item)

    for f in after_unresolved:
        reasons_for_item = list(global_reasons)
        if f.failure_reason is not None and f.failure_reason not in reasons_for_item:
            reasons_for_item.append(f.failure_reason)
            reasons_for_item.sort(key=lambda r: r.sort_key())

        item = EvidenceItem(
            identity=None,
            classification="comparison_unavailable",
            remediation_conclusion="not_established",
            before=[],
            after=[f.obs],
            reasons=reasons_for_item,
        )
        items.append(item)

    # Sort items deterministically
    items.sort(key=_item_sort_key)

    # Summary
    summary = {
        "new": sum(1 for it in items if it.classification == "new"),
        "persistent": sum(1 for it in items if it.classification == "persistent"),
        "not_detected": sum(1 for it in items if it.classification == "not_detected"),
        "comparison_unavailable": sum(1 for it in items if it.classification == "comparison_unavailable"),
    }

    comparison: Literal["comparable", "comparison_unavailable"] = (
        "comparable" if is_comparable else "comparison_unavailable"
    )
    cli_exit_code = 0 if is_comparable else 2

    return ComparisonResult(
        comparison=comparison,
        global_reasons=global_reasons,
        observed_counts=observed_counts,
        summary=summary,
        items=items,
        cli_exit_code=cli_exit_code,
    )
