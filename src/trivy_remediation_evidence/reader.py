from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

from .models import SourceInput
from .reasons import InputKind, InputRef, Reason, Side

# Upper limits strictly defined in DESIGN.ja.md
MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MiB (52,428,800 bytes)
MAX_JSON_DEPTH = 64
MAX_STRING_BYTES = 1 * 1024 * 1024  # 1 MiB (1,048,576 UTF-8 bytes)
MAX_FINDINGS_COUNT = 100_000

# JSON RFC 8259 Section 2 insignificant whitespace characters only
JSON_WHITESPACE = {' ', '\t', '\n', '\r'}
CHUNK_SIZE = 64 * 1024  # 64 KiB for streaming file reads


class ReaderError(Exception):
    """Base exception for strict reader without echoing user input."""


class LimitExceededError(ReaderError):
    """Raised when an input limit is exceeded."""


class InvalidJsonError(ReaderError):
    """Raised when JSON syntax or encoding is invalid."""


def check_json_nesting_depth(text: str, max_depth: int = MAX_JSON_DEPTH) -> None:
    depth = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch in "{[":
                depth += 1
                if depth > max_depth:
                    raise LimitExceededError("JSON depth limit exceeded")
            elif ch in "}]":
                depth -= 1


def check_string_utf8_and_limits(s: str, max_bytes: int = MAX_STRING_BYTES) -> None:
    try:
        raw = s.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidJsonError("Unpaired surrogate code point detected in JSON string")
    if len(raw) > max_bytes:
        raise LimitExceededError("String UTF-8 byte length limit exceeded")


def check_value_limits(val: Any, max_bytes: int = MAX_STRING_BYTES) -> None:
    stack = [val]
    while stack:
        curr = stack.pop()
        if isinstance(curr, str):
            check_string_utf8_and_limits(curr, max_bytes)
        elif isinstance(curr, float):
            if math.isnan(curr) or math.isinf(curr):
                raise InvalidJsonError("Non-finite number detected")
        elif isinstance(curr, dict):
            for k, v in curr.items():
                if isinstance(k, str):
                    check_string_utf8_and_limits(k, max_bytes)
                stack.append(v)
        elif isinstance(curr, list):
            stack.extend(curr)


def check_findings_count(data: Any, max_findings: int = MAX_FINDINGS_COUNT) -> None:
    if not isinstance(data, dict):
        return
    results = data.get("Results")
    if not isinstance(results, list):
        return
    total = 0
    for item in results:
        if isinstance(item, dict):
            vulns = item.get("Vulnerabilities")
            if isinstance(vulns, list):
                total += len(vulns)
                if total > max_findings:
                    raise LimitExceededError("Findings count limit exceeded")


def _strict_pairs_hook(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    res: dict[Any, Any] = {}
    for k, v in pairs:
        if k in res:
            raise InvalidJsonError("Duplicate object key detected")
        if isinstance(k, str):
            check_string_utf8_and_limits(k, MAX_STRING_BYTES)
        res[k] = v
    return res


def _strict_parse_constant(constant: str) -> None:
    raise InvalidJsonError("Non-finite constant detected")


def read_json_bytes(
    raw_bytes: bytes,
    side: Side,
    kind: InputKind,
) -> SourceInput:
    """Strictly parse raw bytes into a SourceInput."""
    # 1. Size limit
    if len(raw_bytes) > MAX_FILE_BYTES:
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_LIMIT_EXCEEDED", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="limit_exceeded",
            data=None,
            reasons=[reason],
        )

    # 2. SHA-256 calculation
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # 3. BOM & strict UTF-8
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_INVALID_JSON", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="invalid_json",
            data=None,
            reasons=[reason],
        )

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_INVALID_JSON", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="invalid_json",
            data=None,
            reasons=[reason],
        )

    # 4. Nesting depth check
    try:
        check_json_nesting_depth(text, max_depth=MAX_JSON_DEPTH)
    except LimitExceededError:
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_LIMIT_EXCEEDED", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="limit_exceeded",
            data=None,
            reasons=[reason],
        )

    # 5. Skip strictly JSON whitespace (SP, TAB, LF, CR)
    idx = 0
    while idx < len(text) and text[idx] in JSON_WHITESPACE:
        idx += 1

    if idx >= len(text):
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_INVALID_JSON", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="invalid_json",
            data=None,
            reasons=[reason],
        )

    # 6. JSON decode with strict hooks
    decoder = json.JSONDecoder(
        object_pairs_hook=_strict_pairs_hook,
        parse_constant=_strict_parse_constant,
    )

    try:
        data, end_idx = decoder.raw_decode(text, idx)
        while end_idx < len(text) and text[end_idx] in JSON_WHITESPACE:
            end_idx += 1
        if end_idx < len(text):
            raise InvalidJsonError("Trailing characters or non-JSON whitespace detected")
    except (json.JSONDecodeError, InvalidJsonError):
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_INVALID_JSON", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="invalid_json",
            data=None,
            reasons=[reason],
        )
    except ValueError:
        # Handles Python 3.11 int string conversion limit (e.g. b'1'*5000)
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_LIMIT_EXCEEDED", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="limit_exceeded",
            data=None,
            reasons=[reason],
        )

    # 7. Value limits (UTF-8 byte length, unpaired surrogates, non-finite float)
    try:
        check_value_limits(data, max_bytes=MAX_STRING_BYTES)
    except LimitExceededError:
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_LIMIT_EXCEEDED", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="limit_exceeded",
            data=None,
            reasons=[reason],
        )
    except InvalidJsonError:
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_INVALID_JSON", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=sha256,
            parse_state="invalid_json",
            data=None,
            reasons=[reason],
        )

    # 8. Finding count limit (for report)
    if kind == "report":
        try:
            check_findings_count(data, max_findings=MAX_FINDINGS_COUNT)
        except LimitExceededError:
            ref = InputRef(side=side, kind=kind, pointer="")
            reason = Reason(code="INPUT_LIMIT_EXCEEDED", refs=(ref,))
            return SourceInput(
                side=side,
                kind=kind,
                sha256=sha256,
                parse_state="limit_exceeded",
                data=None,
                reasons=[reason],
            )

    return SourceInput(
        side=side,
        kind=kind,
        sha256=sha256,
        parse_state="valid",
        data=data,
        reasons=[],
    )


def read_source_file(
    file_path: Path | str,
    side: Side,
    kind: InputKind,
) -> SourceInput:
    """Read a source file strictly with streaming chunk hashing."""
    path = Path(file_path)
    hasher = hashlib.sha256()
    total_bytes = 0
    chunks: list[bytes] = []
    limit_exceeded = False

    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                total_bytes += len(chunk)
                if not limit_exceeded:
                    if total_bytes > MAX_FILE_BYTES:
                        limit_exceeded = True
                        chunks.clear()  # Free memory immediately on overflow
                    else:
                        chunks.append(chunk)
    except (OSError, IOError):
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_UNREADABLE", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=None,
            parse_state="unreadable",
            data=None,
            reasons=[reason],
        )

    file_sha256 = hasher.hexdigest()

    if limit_exceeded:
        ref = InputRef(side=side, kind=kind, pointer="")
        reason = Reason(code="INPUT_LIMIT_EXCEEDED", refs=(ref,))
        return SourceInput(
            side=side,
            kind=kind,
            sha256=file_sha256,
            parse_state="limit_exceeded",
            data=None,
            reasons=[reason],
        )

    raw_bytes = b"".join(chunks)
    return read_json_bytes(raw_bytes, side=side, kind=kind)
