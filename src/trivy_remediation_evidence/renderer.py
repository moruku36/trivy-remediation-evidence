from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .validator import DEFAULT_SCHEMAS_DIR, OUTPUTS_SCHEMAS_DIR, PACKAGE_SCHEMAS_DIR

CHAR_ESCAPE_MAP = {
    "&": "&#38;",
    "<": "&#60;",
    ">": "&#62;",
    '"': "&#34;",
    "'": "&#39;",
    "\\": "&#92;",
    "|": "&#124;",
    "`": "&#96;",
    "*": "&#42;",
    "_": "&#95;",
    "{": "&#123;",
    "}": "&#125;",
    "[": "&#91;",
    "]": "&#93;",
    "(": "&#40;",
    ")": "&#41;",
    "#": "&#35;",
    "+": "&#43;",
    "-": "&#45;",
    ".": "&#46;",
    "!": "&#33;",
    "~": "&#126;",
    ":": "&#58;",
}

BIDI_CONTROL_CODEPOINTS = {
    0x061C,  # ALM
    0x200E,  # LRM
    0x200F,  # RLM
    0x202A,  # LRE
    0x202B,  # RLE
    0x202C,  # PDF
    0x202D,  # LRO
    0x202E,  # RLO
    0x2066,  # LRI
    0x2067,  # RLI
    0x2068,  # FSI
    0x2069,  # PDI
}

LABELS: dict[str, dict[str, Any]] = {
    "ja": {
        "h1": "# Trivy脆弱性比較の証拠",
        "comparison_prefix": "比較状態&#58; ",
        "comparison_states": {
            "comparable": "比較可能",
            "comparison_unavailable": "比較不可",
        },
        "summary_h2": "## 分類件数",
        "summary_headers": ["分類", "件数"],
        "classifications": {
            "new": "新規",
            "persistent": "継続",
            "not_detected": "今回未検出",
            "comparison_unavailable": "比較不可",
        },
        "observed_before": "before観測数&#58; ",
        "observed_after": "after観測数&#58; ",
        "reasons_h2": "## 比較条件と理由",
        "reasons_headers": ["code", "説明", "参照"],
        "sources_h2": "## 入力の証拠",
        "sources_headers": ["side", "kind", "sha256", "parseState"],
        "scan_h2": "## 実行の証拠",
        "scan_headers": ["field", "value"],
        "items_h2": "## 検出項目",
        "items_headers": [
            "imageLogicalId",
            "targetLogicalId",
            "path",
            "class",
            "ecosystem",
            "packageName",
            "vulnerabilityId",
            "分類",
            "beforeVersion",
            "afterVersion",
            "beforeStatus",
            "afterStatus",
            "beforeFixedVersion",
            "afterFixedVersion",
            "Title",
            "evidence",
            "reasonCodes",
            "remediationConclusion",
        ],
        "caveat_h2": "## 制約",
        "caveat_p1": "今回未検出は修正済みの証明ではありません。Status・FixedVersionは配布元の修正版情報です。",
        "caveat_p2": "この比較は供給されたJSONとmanifestの記録に基づきます。manifestの正しさや実際の修正作業を独立に検証していません。",
        "unknown": "不明",
        "empty": "空文字列",
    },
    "en": {
        "h1": "# Trivy vulnerability comparison evidence",
        "comparison_prefix": "Comparison&#58; ",
        "comparison_states": {
            "comparable": "Comparable",
            "comparison_unavailable": "Comparison unavailable",
        },
        "summary_h2": "## Classification counts",
        "summary_headers": ["Classification", "Count"],
        "classifications": {
            "new": "New",
            "persistent": "Persistent",
            "not_detected": "Not detected in this scan",
            "comparison_unavailable": "Comparison unavailable",
        },
        "observed_before": "before observed count&#58; ",
        "observed_after": "after observed count&#58; ",
        "reasons_h2": "## Comparison conditions and reasons",
        "reasons_headers": ["Code", "Explanation", "References"],
        "sources_h2": "## Input evidence",
        "sources_headers": ["side", "kind", "sha256", "parseState"],
        "scan_h2": "## Scan evidence",
        "scan_headers": ["field", "value"],
        "items_h2": "## Findings",
        "items_headers": [
            "imageLogicalId",
            "targetLogicalId",
            "path",
            "class",
            "ecosystem",
            "packageName",
            "vulnerabilityId",
            "Classification",
            "beforeVersion",
            "afterVersion",
            "beforeStatus",
            "afterStatus",
            "beforeFixedVersion",
            "afterFixedVersion",
            "Title",
            "evidence",
            "reasonCodes",
            "remediationConclusion",
        ],
        "caveat_h2": "## Limitations",
        "caveat_p1": "Not detected in this scan does not prove remediation. Status and FixedVersion describe distributor fix information.",
        "caveat_p2": "This comparison relies on the supplied JSON and manifest records. It does not independently verify manifest accuracy or remediation work.",
        "unknown": "Unknown",
        "empty": "Empty string",
    },
}

_CATALOG_CACHE: dict[str, dict[str, Any]] = {}


def load_reason_catalog(schemas_dir: Path | str | None = None) -> dict[str, Any]:
    """Load reason-catalog.json."""
    schemas_path = Path(schemas_dir) if schemas_dir is not None else DEFAULT_SCHEMAS_DIR
    cat_file = schemas_path / "reason-catalog.json"
    if not cat_file.exists():
        alt_path = OUTPUTS_SCHEMAS_DIR if schemas_path == PACKAGE_SCHEMAS_DIR else PACKAGE_SCHEMAS_DIR
        alt_file = alt_path / "reason-catalog.json"
        if alt_file.exists():
            cat_file = alt_file
        else:
            return {}

    cache_key = str(cat_file.resolve())
    if cache_key in _CATALOG_CACHE:
        return _CATALOG_CACHE[cache_key]

    try:
        content = json.loads(cat_file.read_bytes().decode("utf-8"))
        if isinstance(content, dict):
            _CATALOG_CACHE[cache_key] = content
            return content
        return {}
    except Exception:
        return {}


def _escape_str(s: str) -> str:
    """Escape dynamic string into safe markdown plain text.

    Single pass: & < > " ' and markdown special chars to decimal entities (e.g. &#38;).
    Colon to &#58;.
    CRLF, CR, LF to '↵'.
    Tab to '⇥'.
    C0 control and DEL to \\uXXXX.
    Bidi controls to \\uXXXX.
    """
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i : i + 2] == "\r\n":
            out.append("↵")
            i += 2
            continue
        c = s[i]
        if c == "\r" or c == "\n":
            out.append("↵")
            i += 1
            continue
        if c == "\t":
            out.append("⇥")
            i += 1
            continue
        if c in CHAR_ESCAPE_MAP:
            out.append(CHAR_ESCAPE_MAP[c])
            i += 1
            continue
        code = ord(c)
        if (0x00 <= code <= 0x1F) or code == 0x7F:
            out.append(f"\\u{code:04X}")
            i += 1
            continue
        if code in BIDI_CONTROL_CODEPOINTS:
            out.append(f"\\u{code:04X}")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def escape_markdown(val: Any, language: str = "ja") -> str:
    """Escape any value for Markdown display according to format contract."""
    lang_labels = LABELS.get(language, LABELS["ja"])
    if val is None:
        return lang_labels["unknown"]
    if isinstance(val, str):
        if val == "":
            return lang_labels["empty"]
        return _escape_str(val)
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, (list, dict)):
        json_compact = json.dumps(val, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        return _escape_str(json_compact)
    return _escape_str(str(val))


def _render_table_row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def render_markdown(
    evidence: dict[str, Any],
    language: str = "ja",
    schemas_dir: Path | str | None = None,
) -> str:
    """Render canonical Markdown report (JA or EN) from evidence dictionary."""
    if language not in ("ja", "en"):
        raise ValueError(f"Unsupported language: {language}")

    labels = LABELS[language]
    catalog = load_reason_catalog(schemas_dir)

    lines: list[str] = []

    # 1. H1
    lines.append(labels["h1"])
    lines.append("")

    # 2. Comparison state
    comp_state_key = evidence.get("comparison", "comparison_unavailable")
    comp_state_label = labels["comparison_states"].get(comp_state_key, labels["comparison_states"]["comparison_unavailable"])
    lines.append(f"{labels['comparison_prefix']}{comp_state_label}")
    lines.append("")

    # 3. Classification counts (H2)
    lines.append(labels["summary_h2"])
    lines.append("")

    # Summary table (4 fixed rows: new, persistent, not_detected, comparison_unavailable)
    summary = evidence.get("summary", {})
    lines.append(_render_table_row(labels["summary_headers"]))
    lines.append("| --- | --- |")
    for key in ("new", "persistent", "not_detected", "comparison_unavailable"):
        row_label = labels["classifications"][key]
        count = summary.get(key, 0)
        lines.append(_render_table_row([row_label, str(count)]))
    lines.append("")

    # Observed counts (2 lines below summary table)
    obs = evidence.get("observedCounts", {})
    b_obs = obs.get("before")
    a_obs = obs.get("after")
    b_obs_str = escape_markdown(b_obs, language)
    a_obs_str = escape_markdown(a_obs, language)
    lines.append(f"{labels['observed_before']}{b_obs_str}")
    lines.append(f"{labels['observed_after']}{a_obs_str}")
    lines.append("")

    # 4. Comparison conditions and reasons (H2)
    lines.append(labels["reasons_h2"])
    lines.append("")
    lines.append(_render_table_row(labels["reasons_headers"]))
    lines.append("| --- | --- | --- |")
    global_reasons = evidence.get("globalReasons", [])
    for gr in global_reasons:
        code = gr.get("code", "")
        code_str = escape_markdown(code, language)
        desc_entry = catalog.get(code, {})
        desc_text = desc_entry.get(language, code)
        desc_str = escape_markdown(desc_text, language)
        refs = gr.get("refs", [])
        refs_list = [f"{r.get('side')}:{r.get('kind')}:{r.get('pointer')}" for r in refs]
        refs_str = escape_markdown(refs_list, language)
        lines.append(_render_table_row([code_str, desc_str, refs_str]))
    lines.append("")

    # 5. Input evidence (H2)
    lines.append(labels["sources_h2"])
    lines.append("")
    lines.append(_render_table_row(labels["sources_headers"]))
    lines.append("| --- | --- | --- | --- |")
    sources = evidence.get("sources", [])
    for s in sources:
        side_str = escape_markdown(s.get("side"), language)
        kind_str = escape_markdown(s.get("kind"), language)
        sha_str = escape_markdown(s.get("sha256"), language)
        parse_str = escape_markdown(s.get("parseState"), language)
        lines.append(_render_table_row([side_str, kind_str, sha_str, parse_str]))
    lines.append("")

    # 6. Scan evidence (H2)
    lines.append(labels["scan_h2"])
    lines.append("")
    scan_ev = evidence.get("scanEvidence") or {}

    for side in ("before", "after"):
        lines.append(f"### {side}")
        lines.append("")
        side_ev = scan_ev.get(side)
        if side_ev is None:
            lines.append(labels["unknown"])
            lines.append("")
        else:
            lines.append(_render_table_row(labels["scan_headers"]))
            lines.append("| --- | --- |")
            # 9 fixed fields in order:
            # scanner.version, target.logicalId, target.imageDigest, target.platform,
            # databases, effectiveConfig, target.scopes, execution, reportMetadata
            scanner = side_ev.get("scanner") or {}
            target = side_ev.get("target") or {}

            fields_data = [
                ("scanner.version", scanner.get("version")),
                ("target.logicalId", target.get("logicalId")),
                ("target.imageDigest", target.get("imageDigest")),
                ("target.platform", target.get("platform")),
                ("databases", side_ev.get("databases")),
                ("effectiveConfig", side_ev.get("effectiveConfig")),
                ("target.scopes", target.get("scopes")),
                ("execution", side_ev.get("execution")),
                ("reportMetadata", side_ev.get("reportMetadata")),
            ]
            for f_name, f_val in fields_data:
                lines.append(_render_table_row([f_name, escape_markdown(f_val, language)]))
            lines.append("")

    # 7. Findings (H2)
    lines.append(labels["items_h2"])
    lines.append("")
    lines.append(_render_table_row(labels["items_headers"]))
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")

    items = evidence.get("items", [])
    for it in items:
        ident = it.get("identity")
        if ident is None:
            id_cells = [labels["unknown"]] * 7
        else:
            id_cells = [
                escape_markdown(ident.get("imageLogicalId"), language),
                escape_markdown(ident.get("targetLogicalId"), language),
                escape_markdown(ident.get("path"), language),
                escape_markdown(ident.get("class"), language),
                escape_markdown(ident.get("ecosystem"), language),
                escape_markdown(ident.get("packageName"), language),
                escape_markdown(ident.get("vulnerabilityId"), language),
            ]

        # Classification
        cls_key = it.get("classification", "comparison_unavailable")
        cls_label = labels["classifications"].get(cls_key, labels["classifications"]["comparison_unavailable"])

        b_findings = it.get("before", [])
        a_findings = it.get("after", [])

        def _format_finding_field(findings: list[dict[str, Any]], field: str) -> str:
            vals = [f.get(field) for f in findings]
            if len(vals) == 0:
                return "[]"
            if len(vals) == 1:
                return escape_markdown(vals[0], language)
            return escape_markdown(vals, language)

        b_ver = _format_finding_field(b_findings, "installedVersion")
        a_ver = _format_finding_field(a_findings, "installedVersion")
        b_st = _format_finding_field(b_findings, "status")
        a_st = _format_finding_field(a_findings, "status")
        b_fix = _format_finding_field(b_findings, "fixedVersion")
        a_fix = _format_finding_field(a_findings, "fixedVersion")

        # Title: ordered array of before+after titles (including null), no dedup
        titles = [f.get("title") for f in b_findings] + [f.get("title") for f in a_findings]
        title_str = escape_markdown(titles, language)

        # Evidence: before source, after source, and all reasons refs
        ev_refs = []
        for f in b_findings:
            src = f.get("source", {})
            ev_refs.append(f"{src.get('side')}:{src.get('kind')}:{src.get('pointer')}")
        for f in a_findings:
            src = f.get("source", {})
            ev_refs.append(f"{src.get('side')}:{src.get('kind')}:{src.get('pointer')}")
        for r in it.get("reasons", []):
            for ref in r.get("refs", []):
                ev_refs.append(f"{ref.get('side')}:{ref.get('kind')}:{ref.get('pointer')}")
        evidence_str = escape_markdown(ev_refs, language)

        # ReasonCodes: canonical JSON array
        codes = [r.get("code") for r in it.get("reasons", []) if "code" in r]
        codes_str = escape_markdown(codes, language)

        # RemediationConclusion: plain text
        rem_concl = it.get("remediationConclusion", "not_established")
        rem_concl_str = escape_markdown(rem_concl, language)

        row_cells = (
            id_cells
            + [
                cls_label,
                b_ver,
                a_ver,
                b_st,
                a_st,
                b_fix,
                a_fix,
                title_str,
                evidence_str,
                codes_str,
                rem_concl_str,
            ]
        )
        lines.append(_render_table_row(row_cells))
    lines.append("")

    # 8. Limitations (H2)
    lines.append(labels["caveat_h2"])
    lines.append("")
    lines.append(labels["caveat_p1"])
    lines.append("")
    lines.append(labels["caveat_p2"])
    lines.append("")

    return "\n".join(lines)
