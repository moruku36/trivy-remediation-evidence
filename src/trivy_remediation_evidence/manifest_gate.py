from __future__ import annotations

from typing import Any

from .models import SourceInput
from .reasons import InputKind, InputRef, Reason, Side

KNOWN_DEDICATED_OPTIONS = {
    "completeness",
    "scanners",
    "package-types", "package_types", "packagetypes",
    "severity",
    "ignore-unfixed", "ignore_unfixed", "ignoreunfixed",
    "ignore-status", "ignore_status", "ignorestatus",
    "skip-dirs", "skip_dirs", "skipdirs",
    "skip-files", "skip_files", "skipfiles",
    "ignore-files", "ignore_files", "ignorefiles",
    "vex",
    "rego-policies", "rego_policies", "regopolicies",
    "config-files", "config_files", "configfiles",
    "extra-options", "extra_options", "extraoptions",
}


def _file_asset_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(entry.get("logicalId", "")),
        str(entry.get("contentSha256", "")),
        str(entry.get("appliedRulesSha256", "")),
    )


def _scope_identity_key(scope: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(scope.get("logicalTargetId", "")),
        str(scope.get("path", "")),
        str(scope.get("class", "")),
        str(scope.get("ecosystem", "")),
    )


def evaluate_manifest_gate(
    before_manifest: SourceInput,
    after_manifest: SourceInput,
    before_report: SourceInput,
    after_report: SourceInput,
) -> list[Reason]:
    """Evaluate manifest gate contracts across the four inputs.

    Returns deduplicated list of global Reason objects sorted by code and refs.
    """
    reasons: list[Reason] = []

    # 1. Collect stage 1 reasons from all inputs
    for source in [before_manifest, after_manifest, before_report, after_report]:
        reasons.extend(source.reasons)

    # 2. Check reportSha256 consistency for each side
    for side, manifest_src, report_src in [
        ("before", before_manifest, before_report),
        ("after", after_manifest, after_report),
    ]:
        if (
            manifest_src.parse_state == "valid"
            and isinstance(manifest_src.data, dict)
            and report_src.sha256 is not None
        ):
            manifest_hash = manifest_src.data.get("reportSha256")
            if manifest_hash != report_src.sha256:
                ref = InputRef(side=side, kind="manifest", pointer="/reportSha256")  # type: ignore[arg-type]
                reasons.append(Reason(code="REPORT_HASH_MISMATCH", refs=(ref,)))

    # 3. Check target.imageDigest evidence in report RepoDigests and platform consistency
    for side, manifest_src, report_src in [
        ("before", before_manifest, before_report),
        ("after", after_manifest, after_report),
    ]:
        if (
            manifest_src.parse_state == "valid"
            and isinstance(manifest_src.data, dict)
            and report_src.parse_state == "valid"
            and isinstance(report_src.data, dict)
        ):
            target = manifest_src.data.get("target")
            metadata = report_src.data.get("Metadata")
            if isinstance(target, dict) and isinstance(metadata, dict):
                # 3.1 RepoDigests match
                manifest_digest = target.get("imageDigest")
                repo_digests = metadata.get("RepoDigests")
                if isinstance(manifest_digest, str) and isinstance(repo_digests, list):
                    found = False
                    for rd in repo_digests:
                        if isinstance(rd, str):
                            if rd == manifest_digest or rd.endswith("@" + manifest_digest):
                                found = True
                                break
                    if not found:
                        ref = InputRef(side=side, kind="manifest", pointer="/target/imageDigest")  # type: ignore[arg-type]
                        reasons.append(Reason(code="IMAGE_EVIDENCE_MISMATCH", refs=(ref,)))

                # 3.2 Platform (os, architecture, variant) consistency
                m_plat = target.get("platform")
                r_cfg = metadata.get("ImageConfig")
                if isinstance(m_plat, dict) and isinstance(r_cfg, dict):
                    # Check os
                    m_os = m_plat.get("os")
                    r_os = r_cfg.get("os")
                    if m_os != r_os:
                        refs = (
                            InputRef(side=side, kind="manifest", pointer="/target/platform/os"),  # type: ignore[arg-type]
                            InputRef(side=side, kind="report", pointer="/Metadata/ImageConfig/os"),  # type: ignore[arg-type]
                        )
                        reasons.append(Reason(code="IMAGE_EVIDENCE_MISMATCH", refs=refs))

                    # Check architecture
                    m_arch = m_plat.get("architecture")
                    r_arch = r_cfg.get("architecture")
                    if m_arch != r_arch:
                        refs = (
                            InputRef(side=side, kind="manifest", pointer="/target/platform/architecture"),  # type: ignore[arg-type]
                            InputRef(side=side, kind="report", pointer="/Metadata/ImageConfig/architecture"),  # type: ignore[arg-type]
                        )
                        reasons.append(Reason(code="IMAGE_EVIDENCE_MISMATCH", refs=refs))

                    # Check variant (omitted in report means "")
                    m_var = m_plat.get("variant", "")
                    r_var = r_cfg.get("variant", "")
                    if m_var != r_var:
                        r_ptr = "/Metadata/ImageConfig/variant" if "variant" in r_cfg else "/Metadata/ImageConfig"
                        refs = (
                            InputRef(side=side, kind="manifest", pointer="/target/platform/variant"),  # type: ignore[arg-type]
                            InputRef(side=side, kind="report", pointer=r_ptr),  # type: ignore[arg-type]
                        )
                        reasons.append(Reason(code="IMAGE_EVIDENCE_MISMATCH", refs=refs))

    # 4. Single-manifest checks: databases validity, effectiveConfig, execution, scopes
    for side, manifest_src in [("before", before_manifest), ("after", after_manifest)]:
        if manifest_src.parse_state == "valid" and isinstance(manifest_src.data, dict):
            # 4.1 databases: role=vuln required, no duplicate roles
            dbs = manifest_src.data.get("databases")
            if isinstance(dbs, list):
                seen_roles: dict[str, int] = {}
                has_vuln = False
                for i, db in enumerate(dbs):
                    if isinstance(db, dict):
                        role = db.get("role")
                        if role == "vuln":
                            has_vuln = True
                        if role in seen_roles:
                            prev_i = seen_roles[role]
                            refs = (
                                InputRef(side=side, kind="manifest", pointer=f"/databases/{prev_i}/role"),  # type: ignore[arg-type]
                                InputRef(side=side, kind="manifest", pointer=f"/databases/{i}/role"),  # type: ignore[arg-type]
                            )
                            reasons.append(Reason(code="DB_SNAPSHOT_MISMATCH", refs=refs))
                        elif isinstance(role, str):
                            seen_roles[role] = i
                if not has_vuln:
                    ref = InputRef(side=side, kind="manifest", pointer="/databases")  # type: ignore[arg-type]
                    reasons.append(Reason(code="DB_SNAPSHOT_MISSING", refs=(ref,)))

            # 4.2 effectiveConfig: completeness, non-empty vuln scanner, no duplicate dedicated extraOptions
            eff_config = manifest_src.data.get("effectiveConfig")
            if isinstance(eff_config, dict):
                if eff_config.get("completeness") != "complete":
                    ref = InputRef(side=side, kind="manifest", pointer="/effectiveConfig/completeness")  # type: ignore[arg-type]
                    reasons.append(Reason(code="CONFIG_INCOMPLETE", refs=(ref,)))

                scanners = eff_config.get("scanners")
                if isinstance(scanners, list):
                    if not scanners or "vuln" not in scanners:
                        ref = InputRef(side=side, kind="manifest", pointer="/effectiveConfig/scanners")  # type: ignore[arg-type]
                        reasons.append(Reason(code="UNSUPPORTED_PROFILE", refs=(ref,)))

                extra = eff_config.get("extraOptions")
                if isinstance(extra, dict):
                    for k in extra.keys():
                        norm_k = str(k).lower().replace("_", "-")
                        clean_k = norm_k.replace("-", "")
                        if norm_k in KNOWN_DEDICATED_OPTIONS or clean_k in KNOWN_DEDICATED_OPTIONS:
                            ref = InputRef(side=side, kind="manifest", pointer=f"/effectiveConfig/extraOptions/{k}")  # type: ignore[arg-type]
                            reasons.append(Reason(code="CONFIG_MISMATCH", refs=(ref,)))

            # 4.3 execution: precise causal pointers
            execution = manifest_src.data.get("execution")
            if isinstance(execution, dict):
                conf_eol = execution.get("configuredExitOnEol")
                if conf_eol != 0:
                    ref = InputRef(side=side, kind="manifest", pointer="/execution/configuredExitOnEol")  # type: ignore[arg-type]
                    reasons.append(Reason(code="UNSUPPORTED_PROFILE", refs=(ref,)))

                success = execution.get("success")
                exit_cause = execution.get("exitCause")
                fail_refs: list[InputRef] = []
                if success is False:
                    fail_refs.append(InputRef(side=side, kind="manifest", pointer="/execution/success"))  # type: ignore[arg-type]
                if exit_cause == "failure":
                    fail_refs.append(InputRef(side=side, kind="manifest", pointer="/execution/exitCause"))  # type: ignore[arg-type]
                if fail_refs:
                    reasons.append(Reason(code="EXECUTION_FAILED", refs=tuple(sorted(fail_refs))))

                completed = execution.get("completed")
                report_complete = execution.get("reportComplete")
                inc_refs: list[InputRef] = []
                if completed is False:
                    inc_refs.append(InputRef(side=side, kind="manifest", pointer="/execution/completed"))  # type: ignore[arg-type]
                if report_complete is False:
                    inc_refs.append(InputRef(side=side, kind="manifest", pointer="/execution/reportComplete"))  # type: ignore[arg-type]
                if inc_refs:
                    reasons.append(Reason(code="EXECUTION_INCOMPLETE", refs=tuple(sorted(inc_refs))))

                exit_code = execution.get("exitCode")
                conf_exit_code = execution.get("configuredExitCode")
                if exit_cause == "unknown":
                    ref = InputRef(side=side, kind="manifest", pointer="/execution/exitCause")  # type: ignore[arg-type]
                    reasons.append(Reason(code="EXECUTION_STATUS_UNKNOWN", refs=(ref,)))
                elif exit_cause == "normal":
                    if exit_code != 0:
                        ref = InputRef(side=side, kind="manifest", pointer="/execution/exitCode")  # type: ignore[arg-type]
                        reasons.append(Reason(code="EXECUTION_STATUS_UNKNOWN", refs=(ref,)))
                elif exit_cause == "findings_policy":
                    if exit_code == 0 or exit_code != conf_exit_code:
                        ref = InputRef(side=side, kind="manifest", pointer="/execution/exitCode")  # type: ignore[arg-type]
                        reasons.append(Reason(code="EXECUTION_STATUS_UNKNOWN", refs=(ref,)))

            # 4.4 scopes expected and coverage (precise causal pointers)
            target = manifest_src.data.get("target")
            if isinstance(target, dict):
                scopes = target.get("scopes")
                if isinstance(scopes, list):
                    for idx, sc in enumerate(scopes):
                        if isinstance(sc, dict):
                            sc_refs: list[InputRef] = []
                            if sc.get("expected") is not True:
                                sc_refs.append(InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{idx}/expected"))  # type: ignore[arg-type]
                            if sc.get("coverage") != "scanned":
                                sc_refs.append(InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{idx}/coverage"))  # type: ignore[arg-type]
                            if sc_refs:
                                reasons.append(Reason(code="SCOPE_NOT_SCANNED", refs=tuple(sorted(sc_refs))))

    # 5. Scopes internal uniqueness and bidirectional 1:1 Result mapping
    for side, manifest_src, report_src in [
        ("before", before_manifest, before_report),
        ("after", after_manifest, after_report),
    ]:
        if manifest_src.parse_state == "valid" and isinstance(manifest_src.data, dict):
            target = manifest_src.data.get("target")
            if isinstance(target, dict):
                scopes = target.get("scopes")
                if isinstance(scopes, list):
                    # 5.1 Check internal scope uniqueness
                    seen_logical: dict[tuple[str, str, str, str], int] = {}
                    seen_raw: dict[tuple[str, str, str], int] = {}
                    for i, sc in enumerate(scopes):
                        if isinstance(sc, dict):
                            log_k = _scope_identity_key(sc)
                            if log_k in seen_logical:
                                prev_i = seen_logical[log_k]
                                refs = (
                                    InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{prev_i}"),  # type: ignore[arg-type]
                                    InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{i}"),  # type: ignore[arg-type]
                                )
                                reasons.append(Reason(code="SCOPE_SET_MISMATCH", refs=refs))
                            else:
                                seen_logical[log_k] = i

                            raw_k = (str(sc.get("rawTarget", "")), str(sc.get("class", "")), str(sc.get("ecosystem", "")))
                            if raw_k in seen_raw:
                                prev_i = seen_raw[raw_k]
                                refs = (
                                    InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{prev_i}"),  # type: ignore[arg-type]
                                    InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{i}"),  # type: ignore[arg-type]
                                )
                                reasons.append(Reason(code="RESULT_SCOPE_MISMATCH", refs=refs))
                            else:
                                seen_raw[raw_k] = i

                    # 5.2 Bidirectional 1:1 check with report Results
                    if report_src.parse_state == "valid" and isinstance(report_src.data, dict):
                        results = report_src.data.get("Results")
                        if isinstance(results, list):
                            scanned_scopes = [
                                (i, sc)
                                for i, sc in enumerate(scopes)
                                if isinstance(sc, dict) and sc.get("coverage") == "scanned"
                            ]

                            result_entries = [
                                (j, (str(r.get("Target", "")), str(r.get("Class", "")), str(r.get("Type", ""))))
                                for j, r in enumerate(results)
                                if isinstance(r, dict)
                            ]

                            scope_to_results: dict[int, list[int]] = {}
                            result_to_scopes: dict[int, list[int]] = {j: [] for j, _ in result_entries}

                            for s_idx, sc in scanned_scopes:
                                sc_raw_k = (str(sc.get("rawTarget", "")), str(sc.get("class", "")), str(sc.get("ecosystem", "")))
                                matches = [j for j, r_k in result_entries if r_k == sc_raw_k]
                                scope_to_results[s_idx] = matches
                                for j in matches:
                                    result_to_scopes[j].append(s_idx)

                            mismatch_refs: list[InputRef] = []
                            mismatch_found = False

                            for s_idx, matches in scope_to_results.items():
                                if len(matches) != 1:
                                    mismatch_found = True
                                    mismatch_refs.append(InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{s_idx}"))  # type: ignore[arg-type]
                                    if not matches:
                                        mismatch_refs.append(InputRef(side=side, kind="report", pointer="/Results"))  # type: ignore[arg-type]
                                    else:
                                        for j in matches:
                                            mismatch_refs.append(InputRef(side=side, kind="report", pointer=f"/Results/{j}"))  # type: ignore[arg-type]

                            for j, s_matches in result_to_scopes.items():
                                if len(s_matches) != 1:
                                    mismatch_found = True
                                    mismatch_refs.append(InputRef(side=side, kind="report", pointer=f"/Results/{j}"))  # type: ignore[arg-type]
                                    for s_idx in s_matches:
                                        mismatch_refs.append(InputRef(side=side, kind="manifest", pointer=f"/target/scopes/{s_idx}"))  # type: ignore[arg-type]

                            if mismatch_found:
                                sorted_m_refs = tuple(sorted(set(mismatch_refs)))
                                reasons.append(Reason(code="RESULT_SCOPE_MISMATCH", refs=sorted_m_refs))

    # 6. Pairwise comparison across before and after manifests
    # Only evaluated when BOTH manifests are valid (suppress derived diagnostics if manifest invalid)
    if (
        before_manifest.parse_state == "valid"
        and isinstance(before_manifest.data, dict)
        and after_manifest.parse_state == "valid"
        and isinstance(after_manifest.data, dict)
    ):
        b_data = before_manifest.data
        a_data = after_manifest.data

        # 6.1 Scanner version match
        b_sc = b_data.get("scanner", {})
        a_sc = a_data.get("scanner", {})
        if b_sc.get("version") != a_sc.get("version"):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/scanner/version"),
                InputRef(side="after", kind="manifest", pointer="/scanner/version"),
            )
            reasons.append(Reason(code="SCANNER_VERSION_MISMATCH", refs=refs))

        # 6.2 Databases match (by role, snapshotSha256)
        b_dbs = b_data.get("databases", [])
        a_dbs = a_data.get("databases", [])
        b_db_map: dict[str, tuple[int, dict[str, Any]]] = {
            db.get("role"): (i, db) for i, db in enumerate(b_dbs) if isinstance(db, dict) and "role" in db
        }
        a_db_map: dict[str, tuple[int, dict[str, Any]]] = {
            db.get("role"): (i, db) for i, db in enumerate(a_dbs) if isinstance(db, dict) and "role" in db
        }

        if set(b_db_map.keys()) != set(a_db_map.keys()):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/databases"),
                InputRef(side="after", kind="manifest", pointer="/databases"),
            )
            reasons.append(Reason(code="DB_SNAPSHOT_MISMATCH", refs=refs))
        else:
            for role, (b_idx, b_db) in b_db_map.items():
                a_idx, a_db = a_db_map[role]
                if b_db.get("snapshotSha256") != a_db.get("snapshotSha256"):
                    refs = (
                        InputRef(side="before", kind="manifest", pointer=f"/databases/{b_idx}/snapshotSha256"),
                        InputRef(side="after", kind="manifest", pointer=f"/databases/{a_idx}/snapshotSha256"),
                    )
                    reasons.append(Reason(code="DB_SNAPSHOT_MISMATCH", refs=refs))

        # 6.3 effectiveConfig match
        b_cfg = b_data.get("effectiveConfig", {})
        a_cfg = a_data.get("effectiveConfig", {})

        set_fields = ["scanners", "packageTypes", "severity", "ignoreStatus", "skipDirs", "skipFiles"]
        for fld in set_fields:
            b_val = b_cfg.get(fld, [])
            a_val = a_cfg.get(fld, [])
            if set(b_val) != set(a_val):
                refs = (
                    InputRef(side="before", kind="manifest", pointer=f"/effectiveConfig/{fld}"),
                    InputRef(side="after", kind="manifest", pointer=f"/effectiveConfig/{fld}"),
                )
                reasons.append(Reason(code="CONFIG_MISMATCH", refs=refs))

        if b_cfg.get("ignoreUnfixed") != a_cfg.get("ignoreUnfixed"):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/effectiveConfig/ignoreUnfixed"),
                InputRef(side="after", kind="manifest", pointer="/effectiveConfig/ignoreUnfixed"),
            )
            reasons.append(Reason(code="CONFIG_MISMATCH", refs=refs))

        asset_fields = ["ignoreFiles", "vex", "regoPolicies", "configFiles"]
        for fld in asset_fields:
            b_list = b_cfg.get(fld, [])
            a_list = a_cfg.get(fld, [])
            b_set = {_file_asset_key(e) for e in b_list if isinstance(e, dict)}
            a_set = {_file_asset_key(e) for e in a_list if isinstance(e, dict)}
            if b_set != a_set:
                refs = (
                    InputRef(side="before", kind="manifest", pointer=f"/effectiveConfig/{fld}"),
                    InputRef(side="after", kind="manifest", pointer=f"/effectiveConfig/{fld}"),
                )
                reasons.append(Reason(code="CONFIG_MISMATCH", refs=refs))

        if b_cfg.get("extraOptions") != a_cfg.get("extraOptions"):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/effectiveConfig/extraOptions"),
                InputRef(side="after", kind="manifest", pointer="/effectiveConfig/extraOptions"),
            )
            reasons.append(Reason(code="CONFIG_MISMATCH", refs=refs))

        # 6.4 Exit policy match
        b_exec = b_data.get("execution", {})
        a_exec = a_data.get("execution", {})
        if b_exec.get("configuredExitCode") != a_exec.get("configuredExitCode"):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/execution/configuredExitCode"),
                InputRef(side="after", kind="manifest", pointer="/execution/configuredExitCode"),
            )
            reasons.append(Reason(code="EXIT_POLICY_MISMATCH", refs=refs))
        if b_exec.get("configuredExitOnEol") != a_exec.get("configuredExitOnEol"):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/execution/configuredExitOnEol"),
                InputRef(side="after", kind="manifest", pointer="/execution/configuredExitOnEol"),
            )
            reasons.append(Reason(code="EXIT_POLICY_MISMATCH", refs=refs))

        # 6.5 Target ID and platform match (imageDigest difference is ALLOWED)
        b_tgt = b_data.get("target", {})
        a_tgt = a_data.get("target", {})
        if b_tgt.get("logicalId") != a_tgt.get("logicalId"):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/target/logicalId"),
                InputRef(side="after", kind="manifest", pointer="/target/logicalId"),
            )
            reasons.append(Reason(code="TARGET_ID_MISMATCH", refs=refs))

        if b_tgt.get("platform") != a_tgt.get("platform"):
            refs = (
                InputRef(side="before", kind="manifest", pointer="/target/platform"),
                InputRef(side="after", kind="manifest", pointer="/target/platform"),
            )
            reasons.append(Reason(code="TARGET_ID_MISMATCH", refs=refs))

        # 6.6 Scopes set match
        b_scopes = b_tgt.get("scopes", [])
        a_scopes = a_tgt.get("scopes", [])
        b_scope_set = {_scope_identity_key(s) for s in b_scopes if isinstance(s, dict)}
        a_scope_set = {_scope_identity_key(s) for s in a_scopes if isinstance(s, dict)}

        if not b_scope_set and not a_scope_set:
            refs = (
                InputRef(side="before", kind="manifest", pointer="/target/scopes"),
                InputRef(side="after", kind="manifest", pointer="/target/scopes"),
            )
            reasons.append(Reason(code="SCOPE_NOT_SCANNED", refs=refs))
        elif b_scope_set != a_scope_set:
            refs = (
                InputRef(side="before", kind="manifest", pointer="/target/scopes"),
                InputRef(side="after", kind="manifest", pointer="/target/scopes"),
            )
            reasons.append(Reason(code="SCOPE_SET_MISMATCH", refs=refs))

    # 7. Deduplicate and sort all reasons
    dedup: dict[tuple[str, tuple[tuple[str, str, str], ...]], Reason] = {}
    for r in reasons:
        sorted_refs = tuple(sorted(r.refs))
        sorted_r = Reason(code=r.code, refs=sorted_refs)
        dedup[sorted_r.sort_key()] = sorted_r

    return sorted(dedup.values())
