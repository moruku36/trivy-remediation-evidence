from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from .reasons import InputKind, Reason, Side

ParseState = Literal[
    "valid",
    "invalid_json",
    "invalid_schema",
    "unreadable",
    "limit_exceeded",
]


@dataclass
class SourceInput:
    side: Side
    kind: InputKind
    sha256: str | None
    parse_state: ParseState
    data: Any | None = None
    reasons: list[Reason] = field(default_factory=list)

    def to_source_dict(self) -> dict[str, Any]:
        """Convert to sources item defined in evidence.schema.json."""
        return {
            "side": self.side,
            "kind": self.kind,
            "sha256": self.sha256,
            "parseState": self.parse_state,
        }
