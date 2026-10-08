"""Sample OCI image layout generator and minimal local registry for integration testing.

Strictly uses Python standard library without external dependencies.
Supports both GitHub source archive (lodash-lodash-<commit>/) and npm package archive (package/).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.server
import io
import json
from pathlib import Path
import re
import socketserver
import sys
import tarfile
import threading
from typing import Any
import urllib.parse

ALLOWED_VERSIONS = {"4.17.20", "4.17.21"}
MAX_ARCHIVE_FILE_BYTES = 10 * 1024 * 1024      # 10 MiB
MAX_MEMBERS = 10000
MAX_TOTAL_EXTRACTED_BYTES = 20 * 1024 * 1024  # 20 MiB
MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024       # 5 MiB

SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}\Z")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}\Z")
GITHUB_ROOT_PATTERN = re.compile(r"^lodash-lodash-[0-9a-fA-F]+\Z")

REQUIRED_SOURCE_FILES = ("package.json", "lodash.js", "LICENSE")

ALLOWED_MANIFEST_MEDIA_TYPES = {"application/vnd.oci.image.manifest.v1+json"}
ALLOWED_CONFIG_MEDIA_TYPES = {"application/vnd.oci.image.config.v1+json"}
ALLOWED_LAYER_MEDIA_TYPES = {"application/vnd.oci.image.layer.v1.tar+gzip"}


def _canonical_json_bytes(obj: Any) -> bytes:
    """Serialize object to compact canonical UTF-8 JSON bytes with trailing newline."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _calc_sha256(data: bytes) -> str:
    """Calculate hex sha256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def _calc_digest(data: bytes) -> str:
    """Calculate sha256:<hex> digest string."""
    return f"sha256:{_calc_sha256(data)}"


def _inspect_archive_members(
    tf: tarfile.TarFile,
    source_kind: str,
) -> tuple[str, str, list[tarfile.TarInfo], set[str], set[str]]:
    """Stream-iterate and validate all archive members before reading content.

    Returns:
        (resolved_source_kind, root_name, all_members, all_file_paths, all_dir_paths)
    """
    member_count = 0
    declared_total_size = 0
    seen_clean_paths: set[str] = set()
    all_file_paths: set[str] = set()
    all_dir_paths: set[str] = set()
    detected_root: str | None = None
    detected_kind: str | None = None if source_kind == "auto" else source_kind
    raw_members: list[tarfile.TarInfo] = []

    for m in tf:
        member_count += 1
        if member_count > MAX_MEMBERS:
            raise ValueError(f"Archive member count exceeds limit ({member_count} > {MAX_MEMBERS})")

        # 1. Path syntax validation
        if "\\" in m.name:
            raise ValueError(f"Backslash not allowed in archive member path: {m.name!r}")
        if m.name.startswith("/") or m.name.startswith("\\"):
            raise ValueError(f"Absolute path not allowed in archive member: {m.name!r}")
        if "//" in m.name:
            raise ValueError(f"Empty internal path segment not allowed: {m.name!r}")

        # Trailing slash only allowed for directory
        if m.name.endswith("/") and not m.isdir():
            raise ValueError(f"Trailing slash not allowed on non-directory member: {m.name!r}")

        clean_name = m.name.rstrip("/")
        if not clean_name:
            raise ValueError(f"Invalid empty path in archive member: {m.name!r}")

        # Relative path traversal check
        parts = clean_name.split("/")
        for p in parts:
            if p in (".", "..", ""):
                raise ValueError(f"Path traversal or empty segment in member: {m.name!r}")

        # Duplicate path check
        if clean_name in seen_clean_paths:
            raise ValueError(f"Duplicate member path in archive: {clean_name!r}")
        seen_clean_paths.add(clean_name)

        # 2. Member type validation (only regular file or directory)
        if not (m.isdir() or m.isfile()):
            raise ValueError(f"Disallowed member type ({m.type!r}) in archive: {m.name!r}")

        # 3. Size validation
        if m.isfile():
            if m.size > MAX_SINGLE_FILE_BYTES:
                raise ValueError(f"File size exceeds single file limit: {m.size} > {MAX_SINGLE_FILE_BYTES}")
            declared_total_size += m.size
            if declared_total_size > MAX_TOTAL_EXTRACTED_BYTES:
                raise ValueError(f"Total extracted size exceeds limit: {declared_total_size} > {MAX_TOTAL_EXTRACTED_BYTES}")
            all_file_paths.add(clean_name)
        elif m.isdir():
            all_dir_paths.add(clean_name)

        # 4. Root / sourceKind detection and validation
        first_segment = parts[0]
        if detected_root is None:
            if detected_kind == "npm-package-archive" or (detected_kind is None and first_segment == "package"):
                if first_segment != "package":
                    raise ValueError(f"Root directory does not match npm package root: {first_segment!r}")
                detected_root = "package"
                detected_kind = "npm-package-archive"
            elif detected_kind == "github-source-archive" or (detected_kind is None and GITHUB_ROOT_PATTERN.fullmatch(first_segment)):
                if not GITHUB_ROOT_PATTERN.fullmatch(first_segment):
                    raise ValueError(f"Root directory does not match github root pattern: {first_segment!r}")
                detected_root = first_segment
                detected_kind = "github-source-archive"
            else:
                raise ValueError(f"Unrecognized or unsupported root directory segment: {first_segment!r}")

        # Verify member strictly starts with detected_root
        if first_segment != detected_root:
            raise ValueError(f"Archive member does not belong to root {detected_root!r}: {m.name!r}")

        raw_members.append(m)

    if detected_root is None or detected_kind is None:
        raise ValueError("Archive is empty or contains no valid root directory")

    # 5. Check path conflicts between files and directories
    conflict_paths = all_file_paths & all_dir_paths
    if conflict_paths:
        raise ValueError(f"Path conflict: path declared as both file and directory: {conflict_paths}")

    for f_path in all_file_paths:
        f_parts = f_path.split("/")
        for i in range(1, len(f_parts)):
            ancestor = "/".join(f_parts[:i])
            if ancestor in all_file_paths:
                raise ValueError(f"Path conflict: file {ancestor!r} cannot be ancestor of {f_path!r}")

    for d_path in all_dir_paths:
        d_parts = d_path.split("/")
        for i in range(1, len(d_parts)):
            ancestor = "/".join(d_parts[:i])
            if ancestor in all_file_paths:
                raise ValueError(f"Path conflict: file {ancestor!r} cannot be ancestor of directory {d_path!r}")

    return detected_kind, detected_root, raw_members, all_file_paths, all_dir_paths


def build_sample(
    tgz_path: Path | str,
    expected_version: str,
    out_dir: Path | str,
    source_kind: str = "auto",
) -> dict[str, Any]:
    """Safely inspect archive and build deterministic OCI image layout.

    Supports both GitHub source archives (lodash-lodash-<commit>/) and npm package archives (package/).

    Args:
        tgz_path: Path to archive tar.gz
        expected_version: Must be '4.17.20' or '4.17.21'
        out_dir: Target directory for OCI image layout
        source_kind: 'auto', 'github-source-archive', or 'npm-package-archive'

    Returns:
        Metadata dict with archiveSha256, sourceKind, version, digests, fileSha256s, and paths.
    """
    if expected_version not in ALLOWED_VERSIONS:
        raise ValueError(f"Unsupported expected_version: {expected_version!r} (must be in {ALLOWED_VERSIONS})")

    tgz_path = Path(tgz_path)
    if not tgz_path.is_file():
        raise FileNotFoundError(f"Input archive not found: {tgz_path}")

    # Check input archive compressed byte limit before reading full content
    st_size = tgz_path.stat().st_size
    if st_size > MAX_ARCHIVE_FILE_BYTES:
        raise ValueError(f"Archive file size exceeds limit: {st_size} > {MAX_ARCHIVE_FILE_BYTES}")

    archive_bytes = tgz_path.read_bytes()
    if len(archive_bytes) > MAX_ARCHIVE_FILE_BYTES:
        raise ValueError(f"Archive byte size exceeds limit: {len(archive_bytes)} > {MAX_ARCHIVE_FILE_BYTES}")

    archive_sha256 = _calc_sha256(archive_bytes)

    # 1. Stream-iterate and validate archive members
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
            resolved_kind, root_name, members, file_paths, _ = _inspect_archive_members(tf, source_kind)

            # Map of clean_path -> TarInfo
            member_map = {m.name.rstrip("/"): m for m in members if m.isfile()}

            files_to_pack: dict[str, bytes] = {}  # dest rel_path under app/node_modules/lodash/ -> bytes
            file_sha256s: dict[str, str] = {}

            if resolved_kind == "github-source-archive":
                # For source archive, strictly extract ONLY the 3 root files: package.json, lodash.js, LICENSE
                for req_file in REQUIRED_SOURCE_FILES:
                    src_clean_path = f"{root_name}/{req_file}"
                    if src_clean_path not in member_map:
                        raise ValueError(f"Required source file missing in archive: {src_clean_path}")

                    m = member_map[src_clean_path]
                    f = tf.extractfile(m)
                    if f is None:
                        raise ValueError(f"Unable to read archive file: {m.name!r}")
                    content = f.read()
                    if len(content) != m.size:
                        raise ValueError(f"Byte length mismatch for {m.name!r}")

                    files_to_pack[req_file] = content
                    file_sha256s[req_file] = _calc_sha256(content)

            elif resolved_kind == "npm-package-archive":
                # For npm package archive, extract all files under package/
                for clean_path, m in member_map.items():
                    if clean_path.startswith("package/"):
                        rel = clean_path[len("package/"):]
                        f = tf.extractfile(m)
                        if f is None:
                            raise ValueError(f"Unable to read archive file: {m.name!r}")
                        content = f.read()
                        if len(content) != m.size:
                            raise ValueError(f"Byte length mismatch for {m.name!r}")
                        files_to_pack[rel] = content
                        file_sha256s[rel] = _calc_sha256(content)

                if "package.json" not in files_to_pack:
                    raise ValueError("Missing package.json in archive")

            else:
                raise ValueError(f"Unsupported sourceKind: {resolved_kind}")

    except (tarfile.TarError, gzip.BadGzipFile) as e:
        raise ValueError(f"Invalid tar archive: {e}") from e

    # 2. Validate package.json
    try:
        pkg_json = json.loads(files_to_pack["package.json"].decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to parse package.json as valid UTF-8 JSON: {e}") from e

    if not isinstance(pkg_json, dict):
        raise ValueError("package.json must be a JSON object")

    if pkg_json.get("name") != "lodash":
        raise ValueError(f"package.json name mismatch: expected 'lodash', got {pkg_json.get('name')!r}")

    if pkg_json.get("version") != expected_version:
        raise ValueError(f"package.json version mismatch: expected {expected_version!r}, got {pkg_json.get('version')!r}")

    # 3. Build deterministic OCI image layer
    # Target structure: app/node_modules/lodash/...
    layer_entries: list[tuple[str, bool, bytes]] = []  # (path, is_dir, content)

    base_dirs = ["app", "app/node_modules", "app/node_modules/lodash"]
    for bd in base_dirs:
        layer_entries.append((bd, True, b""))

    seen_dirs = set(base_dirs)
    for rel_path, content in files_to_pack.items():
        parts = rel_path.split("/")
        for i in range(1, len(parts)):
            sub_d = "app/node_modules/lodash/" + "/".join(parts[:i])
            if sub_d not in seen_dirs:
                seen_dirs.add(sub_d)
                layer_entries.append((sub_d, True, b""))
        file_path = "app/node_modules/lodash/" + rel_path
        layer_entries.append((file_path, False, content))

    layer_entries.sort(key=lambda x: x[0])

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.PAX_FORMAT) as layer_tf:
        for path_str, is_dir, content_bytes in layer_entries:
            ti = tarfile.TarInfo(name=path_str)
            ti.uid = 0
            ti.gid = 0
            ti.uname = ""
            ti.gname = ""
            ti.mtime = 0
            if is_dir:
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                ti.size = 0
                layer_tf.addfile(ti)
            else:
                ti.type = tarfile.REGTYPE
                ti.mode = 0o644
                ti.size = len(content_bytes)
                layer_tf.addfile(ti, io.BytesIO(content_bytes))

    uncompressed_tar = tar_buf.getvalue()
    diff_id = _calc_digest(uncompressed_tar)

    gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=0.0) as gz:
        gz.write(uncompressed_tar)
    layer_bytes = gz_buf.getvalue()
    layer_digest = _calc_digest(layer_bytes)
    layer_size = len(layer_bytes)

    # 4. Generate OCI Image Config JSON
    config_obj = {
        "architecture": "amd64",
        "config": {},
        "os": "linux",
        "rootfs": {
            "diff_ids": [diff_id],
            "type": "layers",
        },
    }
    config_bytes = _canonical_json_bytes(config_obj)
    config_digest = _calc_digest(config_bytes)
    config_size = len(config_bytes)

    # 5. Generate OCI Manifest JSON
    manifest_obj = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": layer_size,
            }
        ],
    }
    manifest_bytes = _canonical_json_bytes(manifest_obj)
    manifest_digest = _calc_digest(manifest_bytes)
    manifest_size = len(manifest_bytes)

    # 6. Generate OCI Index JSON
    index_obj = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": manifest_size,
            }
        ],
    }
    index_bytes = _canonical_json_bytes(index_obj)

    # 7. Write OCI image layout to out_dir
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError(f"Output directory exists and is not empty: {out_dir}")

    blobs_dir = out_dir / "blobs" / "sha256"
    blobs_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "oci-layout").write_bytes(b'{"imageLayoutVersion":"1.0.0"}\n')
    (out_dir / "index.json").write_bytes(index_bytes)

    layer_hex = layer_digest.split(":", 1)[1]
    config_hex = config_digest.split(":", 1)[1]
    manifest_hex = manifest_digest.split(":", 1)[1]

    (blobs_dir / layer_hex).write_bytes(layer_bytes)
    (blobs_dir / config_hex).write_bytes(config_bytes)
    (blobs_dir / manifest_hex).write_bytes(manifest_bytes)

    # Verify written files integrity and descriptor relationships
    assert (blobs_dir / layer_hex).stat().st_size == layer_size
    assert _calc_digest((blobs_dir / layer_hex).read_bytes()) == layer_digest

    assert (blobs_dir / config_hex).stat().st_size == config_size
    assert _calc_digest((blobs_dir / config_hex).read_bytes()) == config_digest

    assert (blobs_dir / manifest_hex).stat().st_size == manifest_size
    assert _calc_digest((blobs_dir / manifest_hex).read_bytes()) == manifest_digest

    return {
        "archiveSha256": archive_sha256,
        "sourceKind": resolved_kind,
        "version": expected_version,
        "manifestDigest": manifest_digest,
        "configDigest": config_digest,
        "layerDigest": layer_digest,
        "diffId": diff_id,
        "outDir": str(out_dir),
        "fileSha256s": file_sha256s,
    }


def build_sample_pair(
    before_tgz: Path | str,
    after_tgz: Path | str,
    out_dir: Path | str,
    source_kind: str = "auto",
) -> dict[str, Any]:
    """Build before (4.17.20) and after (4.17.21) sample OCI images into out_dir.

    Refuses overwrite if out_dir already exists.
    """
    out_dir = Path(out_dir)
    if out_dir.exists():
        raise FileExistsError(f"Output directory already exists: {out_dir}")

    out_dir.mkdir(parents=True, exist_ok=False)

    before_dir = out_dir / "before"
    after_dir = out_dir / "after"

    before_res = build_sample(before_tgz, "4.17.20", before_dir, source_kind=source_kind)
    after_res = build_sample(after_tgz, "4.17.21", after_dir, source_kind=source_kind)

    index_data = {
        "before": {
            "archiveSha256": before_res["archiveSha256"],
            "configDigest": before_res["configDigest"],
            "fileSha256s": before_res["fileSha256s"],
            "layerDigest": before_res["layerDigest"],
            "manifestDigest": before_res["manifestDigest"],
            "relativePath": "before",
            "sourceKind": before_res["sourceKind"],
            "version": before_res["version"],
        },
        "after": {
            "archiveSha256": after_res["archiveSha256"],
            "configDigest": after_res["configDigest"],
            "fileSha256s": after_res["fileSha256s"],
            "layerDigest": after_res["layerDigest"],
            "manifestDigest": after_res["manifestDigest"],
            "relativePath": "after",
            "sourceKind": after_res["sourceKind"],
            "version": after_res["version"],
        },
    }

    index_path = out_dir / "index.json"
    index_path.write_text(json.dumps(index_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return index_data


class _RegistryHandler(http.server.BaseHTTPRequestHandler):
    """Read-only minimal OCI Distribution server handler."""

    server_version = "MinimalOCIRegistry/1.0"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard log output."""
        pass

    def _send_method_not_allowed(self) -> None:
        """Reject mutation methods with 405 Method Not Allowed."""
        self.send_response(405)
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        self.send_header("Content-Type", "application/json")
        body = b'{"errors":[{"code":"UNSUPPORTED","message":"Method not allowed"}]}\n'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self._send_method_not_allowed()

    def do_PUT(self) -> None:
        self._send_method_not_allowed()

    def do_DELETE(self) -> None:
        self._send_method_not_allowed()

    def do_PATCH(self) -> None:
        self._send_method_not_allowed()

    def do_GET(self) -> None:
        self._handle(is_head=False)

    def do_HEAD(self) -> None:
        self._handle(is_head=True)

    def _handle(self, is_head: bool) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Reject path traversal, backslashes, double slashes
        if ".." in path or "\\" in path or "//" in path:
            self.send_error(400, "Bad Request")
            return

        # GET /v2/ or HEAD /v2/
        if path == "/v2/":
            self.send_response(200)
            self.send_header("Docker-Distribution-API-Version", "registry/2.0")
            self.send_header("Content-Type", "application/json")
            body = b"{}\n"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not is_head:
                self.wfile.write(body)
            return

        # GET /v2/sample/manifests/sha256:<hex>
        manifest_prefix = "/v2/sample/manifests/"
        if path.startswith(manifest_prefix):
            ref = path[len(manifest_prefix):]
            if not DIGEST_PATTERN.fullmatch(ref):
                self.send_error(404, "Manifest reference not found")
                return

            registry: LocalRegistry = self.server.registry  # type: ignore[attr-defined]
            entry = registry.get_manifest(ref)
            if entry is None:
                self.send_error(404, "Manifest not found")
                return

            data, media_type = entry
            self.send_response(200)
            self.send_header("Docker-Distribution-API-Version", "registry/2.0")
            self.send_header("Docker-Content-Digest", ref)
            self.send_header("Content-Type", media_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if not is_head:
                self.wfile.write(data)
            return

        # GET /v2/sample/blobs/sha256:<hex>
        blob_prefix = "/v2/sample/blobs/"
        if path.startswith(blob_prefix):
            digest = path[len(blob_prefix):]
            if not DIGEST_PATTERN.fullmatch(digest):
                self.send_error(404, "Blob digest not found")
                return

            registry = self.server.registry  # type: ignore[attr-defined]
            entry = registry.get_blob(digest)
            if entry is None:
                self.send_error(404, "Blob not found")
                return

            data, media_type = entry
            self.send_response(200)
            self.send_header("Docker-Distribution-API-Version", "registry/2.0")
            self.send_header("Docker-Content-Digest", digest)
            self.send_header("Content-Type", media_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if not is_head:
                self.wfile.write(data)
            return

        # Unknown route or unknown repository (only 'sample' allowed)
        self.send_error(404, "Not Found")


class LocalRegistry:
    """Read-only minimal OCI Distribution server context manager.

    Serves immutable manifests and blobs for repository 'sample' from pre-built OCI layouts.
    Strictly validates index descriptors and verifies actual blob digests/sizes before serving.
    Binds strictly to 127.0.0.1 on a random available port.
    Does not map URLs directly to filesystem files.
    """

    def __init__(self, images: list[Any] | dict[str, Any] | Path | str) -> None:
        self._manifests: dict[str, tuple[bytes, str]] = {}
        self._blobs: dict[str, tuple[bytes, str]] = {}
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0
        self.base_url: str = ""

        # Normalize images input
        items = images if isinstance(images, list) else [images]
        for item in items:
            self._register_image(item)

    def _register_image(self, item: Any) -> None:
        """Register manifests and blobs from an OCI layout directory or result dict."""
        layout_dir: Path
        if isinstance(item, (str, Path)):
            p = Path(item)
            if (p / "before" / "index.json").is_file() and (p / "after" / "index.json").is_file():
                self._register_image(p / "before")
                self._register_image(p / "after")
                return
            layout_dir = p
        elif isinstance(item, dict):
            if "before" in item and "after" in item:
                self._register_image(item["before"])
                self._register_image(item["after"])
                return
            if "outDir" in item:
                layout_dir = Path(item["outDir"])
            elif "relativePath" in item and "baseDir" in item:
                layout_dir = Path(item["baseDir"]) / item["relativePath"]
            else:
                raise TypeError(f"Unsupported image item dict: {item}")
        else:
            raise TypeError(f"Unsupported image item type: {type(item)}")

        # Verify layout directory structure
        oci_layout_file = layout_dir / "oci-layout"
        if not oci_layout_file.is_file():
            raise ValueError(f"oci-layout file missing in layout: {layout_dir}")

        index_file = layout_dir / "index.json"
        if not index_file.is_file():
            raise FileNotFoundError(f"index.json not found in layout: {layout_dir}")

        try:
            index_data = json.loads(index_file.read_text("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to parse index.json in {layout_dir}: {e}") from e

        if not isinstance(index_data, dict):
            raise ValueError(f"index.json must be a JSON object: {layout_dir}")

        if index_data.get("schemaVersion") != 2:
            raise ValueError(f"Unsupported index.json schemaVersion: {index_data.get('schemaVersion')}")

        manifests_list = index_data.get("manifests")
        if not isinstance(manifests_list, list) or not manifests_list:
            raise ValueError(f"index.json has invalid or empty manifests list: {layout_dir}")

        blobs_dir = layout_dir / "blobs" / "sha256"
        if not blobs_dir.is_dir():
            raise ValueError(f"blobs/sha256 directory missing in layout: {layout_dir}")

        for m_desc in manifests_list:
            if not isinstance(m_desc, dict):
                raise ValueError("Manifest descriptor in index.json must be a dict")

            m_digest = m_desc.get("digest")
            if not isinstance(m_digest, str) or not DIGEST_PATTERN.fullmatch(m_digest):
                raise ValueError(f"Invalid manifest digest in index.json: {m_digest!r}")

            m_type = m_desc.get("mediaType")
            if m_type not in ALLOWED_MANIFEST_MEDIA_TYPES:
                raise ValueError(f"Invalid or disallowed manifest mediaType: {m_type!r}")

            m_size = m_desc.get("size")
            if not isinstance(m_size, int) or isinstance(m_size, bool) or m_size < 0:
                raise ValueError(f"Invalid manifest declared size: {m_size!r}")

            m_hex = m_digest.split(":", 1)[1]
            m_path = blobs_dir / m_hex
            if not m_path.is_file():
                raise ValueError(f"Missing manifest blob file on disk: {m_path}")

            m_bytes = m_path.read_bytes()
            if len(m_bytes) != m_size:
                raise ValueError(f"Size mismatch for manifest blob {m_digest}: declared {m_size}, actual {len(m_bytes)}")

            if _calc_digest(m_bytes) != m_digest:
                raise ValueError(f"Integrity check failed for manifest blob {m_digest}")

            self._manifests[m_digest] = (m_bytes, m_type)

            # Parse manifest and strictly verify config and layer blobs
            try:
                m_obj = json.loads(m_bytes.decode("utf-8"))
            except Exception as e:
                raise ValueError(f"Failed to parse manifest JSON {m_digest}: {e}") from e

            if not isinstance(m_obj, dict):
                raise ValueError(f"Manifest JSON must be an object: {m_digest}")

            # Verify Config
            cfg_desc = m_obj.get("config")
            if not isinstance(cfg_desc, dict):
                raise ValueError(f"Manifest {m_digest} missing config descriptor object")

            cfg_digest = cfg_desc.get("digest")
            if not isinstance(cfg_digest, str) or not DIGEST_PATTERN.fullmatch(cfg_digest):
                raise ValueError(f"Invalid config digest in manifest {m_digest}: {cfg_digest!r}")

            cfg_type = cfg_desc.get("mediaType")
            if cfg_type not in ALLOWED_CONFIG_MEDIA_TYPES:
                raise ValueError(f"Invalid config mediaType in manifest {m_digest}: {cfg_type!r}")

            cfg_size = cfg_desc.get("size")
            if not isinstance(cfg_size, int) or isinstance(cfg_size, bool) or cfg_size < 0:
                raise ValueError(f"Invalid config size in manifest {m_digest}: {cfg_size!r}")

            cfg_hex = cfg_digest.split(":", 1)[1]
            cfg_path = blobs_dir / cfg_hex
            if not cfg_path.is_file():
                raise ValueError(f"Missing config blob file on disk: {cfg_path}")

            cfg_bytes = cfg_path.read_bytes()
            if len(cfg_bytes) != cfg_size:
                raise ValueError(f"Size mismatch for config blob {cfg_digest}: declared {cfg_size}, actual {len(cfg_bytes)}")

            if _calc_digest(cfg_bytes) != cfg_digest:
                raise ValueError(f"Integrity check failed for config blob {cfg_digest}")

            self._blobs[cfg_digest] = (cfg_bytes, cfg_type)

            # Verify Layers
            layers_list = m_obj.get("layers")
            if not isinstance(layers_list, list) or not layers_list:
                raise ValueError(f"Manifest {m_digest} must contain at least one layer")

            for lyr_desc in layers_list:
                if not isinstance(lyr_desc, dict):
                    raise ValueError("Layer descriptor in manifest must be a dict")

                lyr_digest = lyr_desc.get("digest")
                if not isinstance(lyr_digest, str) or not DIGEST_PATTERN.fullmatch(lyr_digest):
                    raise ValueError(f"Invalid layer digest in manifest {m_digest}: {lyr_digest!r}")

                lyr_type = lyr_desc.get("mediaType")
                if lyr_type not in ALLOWED_LAYER_MEDIA_TYPES:
                    raise ValueError(f"Invalid layer mediaType in manifest {m_digest}: {lyr_type!r}")

                lyr_size = lyr_desc.get("size")
                if not isinstance(lyr_size, int) or isinstance(lyr_size, bool) or lyr_size < 0:
                    raise ValueError(f"Invalid layer size in manifest {m_digest}: {lyr_size!r}")

                lyr_hex = lyr_digest.split(":", 1)[1]
                lyr_path = blobs_dir / lyr_hex
                if not lyr_path.is_file():
                    raise ValueError(f"Missing layer blob file on disk: {lyr_path}")

                lyr_bytes = lyr_path.read_bytes()
                if len(lyr_bytes) != lyr_size:
                    raise ValueError(f"Size mismatch for layer blob {lyr_digest}: declared {lyr_size}, actual {len(lyr_bytes)}")

                if _calc_digest(lyr_bytes) != lyr_digest:
                    raise ValueError(f"Integrity check failed for layer blob {lyr_digest}")

                self._blobs[lyr_digest] = (lyr_bytes, lyr_type)

    def get_manifest(self, digest: str) -> tuple[bytes, str] | None:
        return self._manifests.get(digest)

    def get_blob(self, digest: str) -> tuple[bytes, str] | None:
        return self._blobs.get(digest)

    def __enter__(self) -> LocalRegistry:
        # Bind strictly to 127.0.0.1 on a random available port
        class _ReusableServer(socketserver.TCPServer):
            allow_reuse_address = True

        self._server = _ReusableServer(("127.0.0.1", 0), _RegistryHandler)
        self._server.registry = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for building sample OCI image layouts."""
    parser = argparse.ArgumentParser(description="Build sample OCI image layouts from archives")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build before and after sample OCI image layouts")
    build_parser.add_argument("--before-tgz", required=True, help="Path to lodash-4.17.20 archive")
    build_parser.add_argument("--after-tgz", required=True, help="Path to lodash-4.17.21 archive")
    build_parser.add_argument("--out-dir", required=True, help="Target output directory")
    build_parser.add_argument(
        "--source-kind",
        choices=["auto", "github-source-archive", "npm-package-archive"],
        default="auto",
        help="Input source kind (default: auto)",
    )

    args = parser.parse_args(argv)

    if args.command == "build":
        try:
            build_sample_pair(
                before_tgz=args.before_tgz,
                after_tgz=args.after_tgz,
                out_dir=args.out_dir,
                source_kind=args.source_kind,
            )
            return 0
        except FileExistsError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 1
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
