from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import SourceInput
from .reasons import InputKind, InputRef, Reason, Side

try:
    import jsonschema
    from jsonschema.validators import Draft202012Validator
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    Draft202012Validator = Any  # type: ignore

class MissingDependencyError(RuntimeError):
    """Raised when an optional or required external dependency is not available."""
    pass


PACKAGE_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"
OUTPUTS_SCHEMAS_DIR = Path("outputs/schemas")
DEFAULT_SCHEMAS_DIR = PACKAGE_SCHEMAS_DIR if PACKAGE_SCHEMAS_DIR.exists() else OUTPUTS_SCHEMAS_DIR
HEX64_PATTERN = re.compile(r"^[a-f0-9]{64}$")

_VALIDATORS: dict[str, Any] = {}


def to_json_pointer(path: tuple[Any, ...] | list[Any]) -> str:
    """Convert a path list to RFC 6901 JSON pointer."""
    if not path:
        return ""
    parts = []
    for item in path:
        part = str(item).replace("~", "~0").replace("/", "~1")
        parts.append(part)
    return "/" + "/".join(parts)


def get_validator(kind: str, schemas_dir: Path | str | None = None) -> Any:
    """Load schema and return cached Draft202012Validator instance."""
    if not HAS_JSONSCHEMA:
        raise MissingDependencyError("Missing required dependency: jsonschema")

    schemas_path = Path(schemas_dir) if schemas_dir is not None else DEFAULT_SCHEMAS_DIR
    schema_file = schemas_path / f"{kind}.schema.json"
    if not schema_file.exists():
        # Fallback to alternate directory if not found
        alt_path = OUTPUTS_SCHEMAS_DIR if schemas_path == PACKAGE_SCHEMAS_DIR else PACKAGE_SCHEMAS_DIR
        alt_file = alt_path / f"{kind}.schema.json"
        if alt_file.exists():
            schemas_path = alt_path
            schema_file = alt_file
        else:
            raise FileNotFoundError(f"Schema file not found for kind: {kind}")

    cache_key = f"{schemas_path.resolve()}_{kind}"
    if cache_key in _VALIDATORS:
        return _VALIDATORS[cache_key]

    schema_bytes = schema_file.read_bytes()
    schema_dict = json.loads(schema_bytes.decode("utf-8"))

    validator = Draft202012Validator(schema_dict)
    _VALIDATORS[cache_key] = validator
    return validator


def _validate_manifest(
    data: Any,
    side: Side,
    validator: Any,
) -> list[Reason]:
    reasons: list[Reason] = []
    if not isinstance(data, dict):
        ref = InputRef(side=side, kind="manifest", pointer="")
        return [Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,))]

    handled_pointers: set[str] = set()

    # 1. schemaVersion
    if "schemaVersion" not in data or data["schemaVersion"] is None:
        ref = InputRef(side=side, kind="manifest", pointer="")
        reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
        handled_pointers.add("/schemaVersion")
    elif not isinstance(data["schemaVersion"], int) or isinstance(data["schemaVersion"], bool):
        ref = InputRef(side=side, kind="manifest", pointer="/schemaVersion")
        reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
        handled_pointers.add("/schemaVersion")
    elif data["schemaVersion"] != 1:
        ref = InputRef(side=side, kind="manifest", pointer="/schemaVersion")
        reasons.append(Reason(code="MANIFEST_VERSION_UNSUPPORTED", refs=(ref,)))
        handled_pointers.add("/schemaVersion")

    # 2. scanner.mode and scanner.name
    scanner = data.get("scanner")
    if scanner is None and "scanner" in data:
        ref = InputRef(side=side, kind="manifest", pointer="")
        reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
        handled_pointers.add("/scanner")
    elif isinstance(scanner, dict):
        if "name" in scanner:
            name_val = scanner["name"]
            if name_val is None:
                ref = InputRef(side=side, kind="manifest", pointer="/scanner")
                reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
                handled_pointers.add("/scanner/name")
            elif not isinstance(name_val, str):
                ref = InputRef(side=side, kind="manifest", pointer="/scanner/name")
                reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
                handled_pointers.add("/scanner/name")
            elif name_val != "trivy":
                ref = InputRef(side=side, kind="manifest", pointer="/scanner/name")
                reasons.append(Reason(code="UNSUPPORTED_PROFILE", refs=(ref,)))
                handled_pointers.add("/scanner/name")

        if "mode" in scanner:
            mode_val = scanner["mode"]
            if mode_val is None:
                ref = InputRef(side=side, kind="manifest", pointer="/scanner")
                reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
                handled_pointers.add("/scanner/mode")
            elif not isinstance(mode_val, str):
                ref = InputRef(side=side, kind="manifest", pointer="/scanner/mode")
                reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
                handled_pointers.add("/scanner/mode")
            elif mode_val != "image":
                ref = InputRef(side=side, kind="manifest", pointer="/scanner/mode")
                reasons.append(Reason(code="UNSUPPORTED_PROFILE", refs=(ref,)))
                handled_pointers.add("/scanner/mode")

    # 3. databases and snapshotSha256
    dbs = data.get("databases")
    if dbs is None and "databases" in data:
        ref = InputRef(side=side, kind="manifest", pointer="")
        reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
        handled_pointers.add("/databases")
    elif isinstance(dbs, list):
        for i, db in enumerate(dbs):
            if isinstance(db, dict):
                ptr_db = f"/databases/{i}"
                ptr_hash = f"/databases/{i}/snapshotSha256"
                if "snapshotSha256" not in db or db["snapshotSha256"] is None or db["snapshotSha256"] == "":
                    ref = InputRef(side=side, kind="manifest", pointer=ptr_db)
                    reasons.append(Reason(code="DB_SNAPSHOT_MISSING", refs=(ref,)))
                    handled_pointers.add(ptr_hash)
                elif not isinstance(db["snapshotSha256"], str) or isinstance(db["snapshotSha256"], bool):
                    ref = InputRef(side=side, kind="manifest", pointer=ptr_hash)
                    reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
                    handled_pointers.add(ptr_hash)
                elif not HEX64_PATTERN.match(db["snapshotSha256"]):
                    ref = InputRef(side=side, kind="manifest", pointer=ptr_hash)
                    reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
                    handled_pointers.add(ptr_hash)

    # 4. Check root required properties for None (null) values
    root_required = [
        "schemaVersion", "reportSha256", "scanner", "databases",
        "effectiveConfig", "target", "execution"
    ]
    for req_key in root_required:
        if req_key in data and data[req_key] is None:
            ptr = f"/{req_key}"
            if ptr not in handled_pointers:
                ref = InputRef(side=side, kind="manifest", pointer="")
                reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
                handled_pointers.add(ptr)

    # 5. Delegate remainder to jsonschema validator
    for error in validator.iter_errors(data):
        path_list = list(error.path)
        pointer = to_json_pointer(path_list)

        if error.validator != "required" and pointer in handled_pointers:
            continue

        if error.validator == "required":
            parent: Any = data
            for p in path_list:
                if isinstance(parent, dict) and p in parent:
                    parent = parent[p]
                elif isinstance(parent, list) and isinstance(p, int) and 0 <= p < len(parent):
                    parent = parent[p]
                else:
                    parent = None
                    break

            missing_props: list[str] = []
            if isinstance(parent, dict) and isinstance(error.validator_value, list):
                missing_props = [k for k in error.validator_value if k not in parent]

            for prop in missing_props:
                child_ptr = f"{pointer}/{prop}" if pointer else f"/{prop}"
                if child_ptr in handled_pointers:
                    continue

                if path_list and path_list[0] == "databases" and prop == "snapshotSha256":
                    db_idx = path_list[1] if len(path_list) > 1 else 0
                    db_ptr = f"/databases/{db_idx}"
                    ref = InputRef(side=side, kind="manifest", pointer=db_ptr)
                    reasons.append(Reason(code="DB_SNAPSHOT_MISSING", refs=(ref,)))
                else:
                    ref = InputRef(side=side, kind="manifest", pointer=pointer)
                    reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
        elif error.validator == "type" and error.instance is None:
            # A required property was present as null
            parent_ptr = to_json_pointer(path_list[:-1])
            ref = InputRef(side=side, kind="manifest", pointer=parent_ptr)
            reasons.append(Reason(code="MANIFEST_REQUIRED_MISSING", refs=(ref,)))
        else:
            ref = InputRef(side=side, kind="manifest", pointer=pointer)
            reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))

    # Deduplicate and sort reasons
    dedup: dict[tuple[str, tuple[tuple[str, str, str], ...]], Reason] = {}
    for r in reasons:
        sorted_refs = tuple(sorted(r.refs))
        sorted_r = Reason(code=r.code, refs=sorted_refs)
        dedup[sorted_r.sort_key()] = sorted_r

    return sorted(dedup.values())


def _validate_report(
    data: Any,
    side: Side,
    validator: Any,
) -> list[Reason]:
    reasons: list[Reason] = []
    if not isinstance(data, dict):
        ref = InputRef(side=side, kind="report", pointer="")
        return [Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,))]

    handled_pointers: set[str] = set()

    # 1. SchemaVersion
    if "SchemaVersion" not in data or data["SchemaVersion"] is None:
        ref = InputRef(side=side, kind="report", pointer="")
        reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
        handled_pointers.add("/SchemaVersion")
    elif not isinstance(data["SchemaVersion"], int) or isinstance(data["SchemaVersion"], bool):
        ref = InputRef(side=side, kind="report", pointer="/SchemaVersion")
        reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
        handled_pointers.add("/SchemaVersion")
    elif data["SchemaVersion"] != 2:
        ref = InputRef(side=side, kind="report", pointer="/SchemaVersion")
        reasons.append(Reason(code="UNSUPPORTED_REPORT_SCHEMA", refs=(ref,)))
        handled_pointers.add("/SchemaVersion")

    # 2. ArtifactType
    if "ArtifactType" in data:
        art_val = data["ArtifactType"]
        if art_val is None or not isinstance(art_val, str):
            ref = InputRef(side=side, kind="report", pointer="/ArtifactType")
            reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))
            handled_pointers.add("/ArtifactType")
        elif art_val != "container_image":
            ref = InputRef(side=side, kind="report", pointer="/ArtifactType")
            reasons.append(Reason(code="UNSUPPORTED_PROFILE", refs=(ref,)))
            handled_pointers.add("/ArtifactType")

    # 3. Delegate to jsonschema validator
    for error in validator.iter_errors(data):
        path_list = list(error.path)
        pointer = to_json_pointer(path_list)

        if pointer in handled_pointers:
            continue

        ref = InputRef(side=side, kind="report", pointer=pointer)
        reasons.append(Reason(code="INPUT_SCHEMA_INVALID", refs=(ref,)))

    # Deduplicate and sort reasons
    dedup: dict[tuple[str, tuple[tuple[str, str, str], ...]], Reason] = {}
    for r in reasons:
        sorted_refs = tuple(sorted(r.refs))
        sorted_r = Reason(code=r.code, refs=sorted_refs)
        dedup[sorted_r.sort_key()] = sorted_r

    return sorted(dedup.values())


def validate_source(
    source: SourceInput,
    schemas_dir: Path | str | None = None,
) -> list[Reason]:
    """Validate a source input against JSON schema.

    If source.parse_state is not 'valid', existing reasons are returned.
    If schema errors exist, parse_state is updated to 'invalid_schema'.
    Data is NOT converted to an empty report on validation failure.
    """
    if source.parse_state != "valid":
        return list(source.reasons)

    if not HAS_JSONSCHEMA:
        raise MissingDependencyError("Missing required dependency: jsonschema")

    validator = get_validator(source.kind, schemas_dir)
    if source.kind == "manifest":
        new_reasons = _validate_manifest(source.data, source.side, validator)
    elif source.kind == "report":
        new_reasons = _validate_report(source.data, source.side, validator)
    else:
        new_reasons = []

    if new_reasons:
        source.parse_state = "invalid_schema"
        source.reasons.extend(new_reasons)

    return new_reasons


def validate_evidence(
    evidence: dict[str, Any],
    schemas_dir: Path | str | None = None,
) -> None:
    """Validate generated evidence dictionary against evidence.schema.json.

    Raises:
        MissingDependencyError: if jsonschema is not installed.
        ValueError: if evidence does not conform to schema.
    """
    if not HAS_JSONSCHEMA:
        raise MissingDependencyError("Missing required dependency: jsonschema")

    validator = get_validator("evidence", schemas_dir)
    errors = list(validator.iter_errors(evidence))
    if errors:
        raise ValueError(f"Evidence schema validation failed with {len(errors)} error(s)")

