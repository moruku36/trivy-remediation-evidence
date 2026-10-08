"""trivy-remediation-evidence package."""

from .comparator import (
    ComparisonResult,
    EvidenceItem,
    FindingObservation,
    Identity,
    compare_manifests_and_reports,
)
from .evidence import (
    build_evidence_dict,
    build_scan_evidence,
    canonical_json_bytes,
    canonical_json_dumps,
    run_pipeline,
)
from .renderer import escape_markdown, render_markdown
from .cli import main

__version__ = "0.1.0"
__all__ = [
    "ComparisonResult",
    "EvidenceItem",
    "FindingObservation",
    "Identity",
    "compare_manifests_and_reports",
    "build_evidence_dict",
    "build_scan_evidence",
    "canonical_json_bytes",
    "canonical_json_dumps",
    "run_pipeline",
    "escape_markdown",
    "render_markdown",
    "main",
]


