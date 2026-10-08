from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ReasonCode = Literal[
    "INPUT_UNREADABLE",
    "INPUT_LIMIT_EXCEEDED",
    "INPUT_INVALID_JSON",
    "INPUT_SCHEMA_INVALID",
    "UNSUPPORTED_REPORT_SCHEMA",
    "UNSUPPORTED_PROFILE",
    "MANIFEST_REQUIRED_MISSING",
    "MANIFEST_VERSION_UNSUPPORTED",
    "REPORT_HASH_MISMATCH",
    "IMAGE_EVIDENCE_MISMATCH",
    "SCANNER_VERSION_MISMATCH",
    "DB_SNAPSHOT_MISSING",
    "DB_SNAPSHOT_MISMATCH",
    "CONFIG_INCOMPLETE",
    "CONFIG_MISMATCH",
    "EXIT_POLICY_MISMATCH",
    "TARGET_ID_MISMATCH",
    "SCOPE_SET_MISMATCH",
    "SCOPE_NOT_SCANNED",
    "RESULT_SCOPE_MISMATCH",
    "EXECUTION_FAILED",
    "EXECUTION_INCOMPLETE",
    "EXECUTION_STATUS_UNKNOWN",
    "IDENTITY_MISSING",
    "IDENTITY_PATH_INVALID",
    "DUPLICATE_IDENTITY",
    "NEW_OBSERVATION",
    "SAME_IDENTITY",
    "NOT_DETECTED_UNDER_EQUAL_CONDITIONS",
]

Side = Literal["before", "after"]
InputKind = Literal["report", "manifest"]


@dataclass(frozen=True)
class InputRef:
    side: Side
    kind: InputKind
    pointer: str

    def __post_init__(self) -> None:
        if self.pointer != "" and not self.pointer.startswith("/"):
            raise ValueError("Invalid JSON Pointer format")

    def to_dict(self) -> dict[str, str]:
        return {
            "side": self.side,
            "kind": self.kind,
            "pointer": self.pointer,
        }

    def sort_key(self) -> tuple[str, str, str]:
        return (self.side, self.kind, self.pointer)

    def __lt__(self, other: InputRef) -> bool:
        return self.sort_key() < other.sort_key()


@dataclass(frozen=True)
class Reason:
    code: ReasonCode
    refs: tuple[InputRef, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "refs": [r.to_dict() for r in self.refs],
        }

    def sort_key(self) -> tuple[str, tuple[tuple[str, str, str], ...]]:
        return (self.code, tuple(r.sort_key() for r in self.refs))

    def __lt__(self, other: Reason) -> bool:
        return self.sort_key() < other.sort_key()


REASON_CATALOG: dict[ReasonCode, dict[str, str]] = {
    "INPUT_UNREADABLE": {
        "ja": "入力を読めない",
        "en": "Input cannot be read",
    },
    "INPUT_LIMIT_EXCEEDED": {
        "ja": "入力上限超過",
        "en": "Input limit exceeded",
    },
    "INPUT_INVALID_JSON": {
        "ja": "JSONまたはUTF-8不正",
        "en": "Invalid JSON or UTF-8",
    },
    "INPUT_SCHEMA_INVALID": {
        "ja": "入力スキーマ違反",
        "en": "Input schema violation",
    },
    "UNSUPPORTED_REPORT_SCHEMA": {
        "ja": "未対応report schema",
        "en": "Unsupported report schema",
    },
    "UNSUPPORTED_PROFILE": {
        "ja": "未対応スキャン設定",
        "en": "Unsupported scan profile",
    },
    "MANIFEST_REQUIRED_MISSING": {
        "ja": "manifest必須情報不足",
        "en": "Required manifest information missing",
    },
    "MANIFEST_VERSION_UNSUPPORTED": {
        "ja": "未対応manifest版",
        "en": "Unsupported manifest version",
    },
    "REPORT_HASH_MISMATCH": {
        "ja": "report hash不一致",
        "en": "Report hash mismatch",
    },
    "IMAGE_EVIDENCE_MISMATCH": {
        "ja": "image証拠不整合",
        "en": "Image evidence mismatch",
    },
    "SCANNER_VERSION_MISMATCH": {
        "ja": "scanner版不一致",
        "en": "Scanner version mismatch",
    },
    "DB_SNAPSHOT_MISSING": {
        "ja": "実DB snapshot不足",
        "en": "Actual database snapshot missing",
    },
    "DB_SNAPSHOT_MISMATCH": {
        "ja": "DB snapshot不一致",
        "en": "Database snapshot mismatch",
    },
    "CONFIG_INCOMPLETE": {
        "ja": "有効設定の記録不足",
        "en": "Effective configuration incomplete",
    },
    "CONFIG_MISMATCH": {
        "ja": "有効設定不一致",
        "en": "Effective configuration mismatch",
    },
    "EXIT_POLICY_MISMATCH": {
        "ja": "終了ポリシー不一致",
        "en": "Exit policy mismatch",
    },
    "TARGET_ID_MISMATCH": {
        "ja": "論理imageまたはplatform不一致",
        "en": "Logical image or platform mismatch",
    },
    "SCOPE_SET_MISMATCH": {
        "ja": "対象範囲集合不一致",
        "en": "Scope set mismatch",
    },
    "SCOPE_NOT_SCANNED": {
        "ja": "対象範囲が未スキャン",
        "en": "Scope not scanned",
    },
    "RESULT_SCOPE_MISMATCH": {
        "ja": "Resultとscopeの対応不一致",
        "en": "Result and scope mapping mismatch",
    },
    "EXECUTION_FAILED": {
        "ja": "実行失敗",
        "en": "Execution failed",
    },
    "EXECUTION_INCOMPLETE": {
        "ja": "実行未完了",
        "en": "Execution incomplete",
    },
    "EXECUTION_STATUS_UNKNOWN": {
        "ja": "実行状態未確認",
        "en": "Execution status not established",
    },
    "IDENTITY_MISSING": {
        "ja": "同一性の情報不足",
        "en": "Identity information missing",
    },
    "IDENTITY_PATH_INVALID": {
        "ja": "同一性path不正",
        "en": "Invalid identity path",
    },
    "DUPLICATE_IDENTITY": {
        "ja": "識別不能な重複",
        "en": "Ambiguous duplicate identity",
    },
    "NEW_OBSERVATION": {
        "ja": "同条件でafterにのみ検出",
        "en": "Observed only after under equal conditions",
    },
    "SAME_IDENTITY": {
        "ja": "両側で同じ同一性を検出",
        "en": "Same identity observed on both sides",
    },
    "NOT_DETECTED_UNDER_EQUAL_CONDITIONS": {
        "ja": "同条件でafterに未検出",
        "en": "Not detected after under equal conditions",
    },
}
