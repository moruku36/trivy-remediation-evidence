"""Tests for sample OCI image generator and minimal local registry.

Covers:
- Both GitHub source archive (lodash-lodash-<commit>/) and npm package archive (package/)
- Layer contains strictly the 3 files for source archives
- Content byte equality and SHA-256 recording
- Security boundaries (10MiB archive limit, streaming member limit, double slashes, trailing slashes, path conflicts)
- Strict LocalRegistry validation (descriptor integrity, blob verification, tampering rejection)
- Real lodash sources verification when available
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request

from integration_samples.sample_images import (
    ALLOWED_VERSIONS,
    LocalRegistry,
    build_sample,
    build_sample_pair,
    main,
)


def _make_tgz(
    files: dict[str, bytes | str | None],
    *,
    custom_tarinfos: list[tuple[tarfile.TarInfo, bytes]] | None = None,
) -> bytes:
    """Helper to create synthetic in-memory .tgz bytes."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for path_str, content in files.items():
            ti = tarfile.TarInfo(name=path_str)
            if content is None:
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            else:
                data = content.encode("utf-8") if isinstance(content, str) else content
                ti.type = tarfile.REGTYPE
                ti.mode = 0o644
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))

        if custom_tarinfos:
            for c_ti, c_data in custom_tarinfos:
                if c_data:
                    tf.addfile(c_ti, io.BytesIO(c_data))
                else:
                    tf.addfile(c_ti)

    uncompressed = tar_buf.getvalue()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=0.0) as gz:
        gz.write(uncompressed)
    return gz_buf.getvalue()


def _make_valid_github_source_tgz(
    version: str,
    commit: str = "ded9bc6",
    extra_files: dict[str, bytes | str] | None = None,
) -> bytes:
    """Create synthetic valid GitHub source archive with root lodash-lodash-<commit>/."""
    root = f"lodash-lodash-{commit}"
    pkg_json = {
        "name": "lodash",
        "version": version,
        "description": "Lodash modular utilities.",
    }
    files: dict[str, bytes | str | None] = {
        root: None,
        f"{root}/package.json": json.dumps(pkg_json, indent=2),
        f"{root}/lodash.js": f"/** lodash {version} source **/ module.exports = {{}};\n",
        f"{root}/LICENSE": "MIT License Copyright (c) JS Foundation\n",
        # Extra development / test fixtures that MUST NOT be included in the image
        f"{root}/test": None,
        f"{root}/test/test.js": "console.log('test');\n",
        f"{root}/perf": None,
        f"{root}/perf/perf.js": "console.log('perf');\n",
    }
    if extra_files:
        for k, v in extra_files.items():
            files[f"{root}/{k}"] = v
    return _make_tgz(files)


def _make_valid_lodash_tgz(version: str, extra_files: dict[str, bytes | str] | None = None) -> bytes:
    """Create synthetic valid npm lodash tgz with root package/."""
    pkg_json = {
        "name": "lodash",
        "version": version,
        "description": "Lodash modular utilities.",
        "main": "lodash.js",
    }
    files: dict[str, bytes | str | None] = {
        "package": None,
        "package/package.json": json.dumps(pkg_json, indent=2),
        "package/lodash.js": f"/** lodash {version} **/ module.exports = {{}};\n",
        "package/README.md": f"# lodash {version}\n",
    }
    if extra_files:
        for k, v in extra_files.items():
            files[f"package/{k}"] = v
    return _make_tgz(files)


class TestSampleImages(unittest.TestCase):
    def test_github_source_archive_strictly_3_files_and_byte_match(self) -> None:
        """Verify GitHub source archive extracts strictly the 3 files with exact byte match."""
        pkg_content = json.dumps({"name": "lodash", "version": "4.17.20"}).encode("utf-8")
        js_content = b"/** custom lodash code **/ module.exports = {a: 1};\n"
        lic_content = b"Custom MIT License Text\n"

        tgz_bytes = _make_valid_github_source_tgz("4.17.20", "ded9bc6", {
            "package.json": pkg_content,
            "lodash.js": js_content,
            "LICENSE": lic_content,
        })

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tgz_file = base / "lodash-4.17.20.tar.gz"
            tgz_file.write_bytes(tgz_bytes)
            out_dir = base / "out"

            res = build_sample(tgz_file, "4.17.20", out_dir, source_kind="github-source-archive")

            self.assertEqual(res["sourceKind"], "github-source-archive")
            self.assertEqual(res["version"], "4.17.20")
            self.assertEqual(res["archiveSha256"], hashlib.sha256(tgz_bytes).hexdigest())

            # Check recorded fileSha256s
            self.assertEqual(res["fileSha256s"]["package.json"], hashlib.sha256(pkg_content).hexdigest())
            self.assertEqual(res["fileSha256s"]["lodash.js"], hashlib.sha256(js_content).hexdigest())
            self.assertEqual(res["fileSha256s"]["LICENSE"], hashlib.sha256(lic_content).hexdigest())

            # Inspect layer contents directly
            layer_hex = res["layerDigest"].split(":")[1]
            layer_bytes = (out_dir / "blobs" / "sha256" / layer_hex).read_bytes()
            uncompressed = gzip.decompress(layer_bytes)

            with tarfile.open(fileobj=io.BytesIO(uncompressed)) as tf:
                members = tf.getmembers()
                member_names = sorted(m.name for m in members)

                # Strictly 3 files + 3 parent dirs
                expected_names = [
                    "app",
                    "app/node_modules",
                    "app/node_modules/lodash",
                    "app/node_modules/lodash/LICENSE",
                    "app/node_modules/lodash/lodash.js",
                    "app/node_modules/lodash/package.json",
                ]
                self.assertEqual(member_names, expected_names)

                # Verify exact byte content matches source
                f_lic = tf.extractfile("app/node_modules/lodash/LICENSE")
                self.assertIsNotNone(f_lic)
                self.assertEqual(f_lic.read(), lic_content)

                f_js = tf.extractfile("app/node_modules/lodash/lodash.js")
                self.assertIsNotNone(f_js)
                self.assertEqual(f_js.read(), js_content)

                f_pkg = tf.extractfile("app/node_modules/lodash/package.json")
                self.assertIsNotNone(f_pkg)
                self.assertEqual(f_pkg.read(), pkg_content)

    def test_github_source_missing_required_file_rejection(self) -> None:
        """Reject GitHub source archive if any of package.json, lodash.js, or LICENSE is missing."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            # Missing LICENSE
            root = "lodash-lodash-ded9bc6"
            tgz_bytes = _make_tgz({
                root: None,
                f"{root}/package.json": json.dumps({"name": "lodash", "version": "4.17.20"}),
                f"{root}/lodash.js": "module.exports = {};",
            })
            tgz_file = base / "bad.tar.gz"
            tgz_file.write_bytes(tgz_bytes)

            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("Required source file missing in archive", str(ctx.exception))
            self.assertIn("LICENSE", str(ctx.exception))

    def test_archive_size_and_streaming_limits(self) -> None:
        """Reject archive file >10MiB, member count >10000, single file >5MiB, total >20MiB."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tgz_file = base / "large.tar.gz"

            # Archive file > 10MiB
            tgz_file.write_bytes(b"0" * (10 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("Archive file size exceeds limit", str(ctx.exception))

            # Exceed maximum member count (stream iterator rejects on 10001)
            many_members = [(tarfile.TarInfo(name=f"package/f{i}.txt"), b"") for i in range(10002)]
            for ti, _ in many_members:
                ti.type = tarfile.REGTYPE
                ti.size = 0
            tgz_many = _make_tgz({}, custom_tarinfos=many_members)
            tgz_file.write_bytes(tgz_many)
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("member count exceeds limit", str(ctx.exception))

            # Single file > 5MiB
            large_content = b"x" * (5 * 1024 * 1024 + 1)
            tgz_file.write_bytes(_make_valid_lodash_tgz("4.17.20", {"large.js": large_content}))
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("exceeds single file limit", str(ctx.exception))

            # Total extracted size > 20MiB (5 files of 4.2 MiB = 21 MiB)
            ti_4m_1 = tarfile.TarInfo(name="package/c1.dat")
            ti_4m_1.size = 4 * 1024 * 1024
            ti_4m_2 = tarfile.TarInfo(name="package/c2.dat")
            ti_4m_2.size = 4 * 1024 * 1024
            ti_4m_3 = tarfile.TarInfo(name="package/c3.dat")
            ti_4m_3.size = 4 * 1024 * 1024
            ti_4m_4 = tarfile.TarInfo(name="package/c4.dat")
            ti_4m_4.size = 4 * 1024 * 1024
            ti_4m_5 = tarfile.TarInfo(name="package/c5.dat")
            ti_4m_5.size = 5 * 1024 * 1024

            tgz_21m = _make_tgz(
                {"package/package.json": json.dumps({"name": "lodash", "version": "4.17.20"})},
                custom_tarinfos=[
                    (ti_4m_1, b"a" * ti_4m_1.size),
                    (ti_4m_2, b"b" * ti_4m_2.size),
                    (ti_4m_3, b"c" * ti_4m_3.size),
                    (ti_4m_4, b"d" * ti_4m_4.size),
                    (ti_4m_5, b"e" * ti_4m_5.size),
                ],
            )
            tgz_file.write_bytes(tgz_21m)
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("Total extracted size exceeds limit", str(ctx.exception))

    def test_path_syntax_and_conflicts_rejection(self) -> None:
        """Reject double slashes, trailing slashes on files, duplicate paths, and path conflicts."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tgz_file = base / "sample.tgz"

            # Double slash in path
            ti_ds = tarfile.TarInfo(name="package//foo.js")
            ti_ds.type = tarfile.REGTYPE
            tgz_file.write_bytes(_make_tgz({}, custom_tarinfos=[(ti_ds, b"content")]))
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("Empty internal path segment", str(ctx.exception))

            # Trailing slash on regular file
            ti_ts = tarfile.TarInfo(name="package/file.js/")
            ti_ts.type = tarfile.REGTYPE
            tgz_file.write_bytes(_make_tgz({}, custom_tarinfos=[(ti_ts, b"content")]))
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("Trailing slash not allowed on non-directory", str(ctx.exception))

            # Path conflict: same path declared as both file and directory
            ti_dir = tarfile.TarInfo(name="package/conflict")
            ti_dir.type = tarfile.DIRTYPE
            ti_file = tarfile.TarInfo(name="package/conflict")
            ti_file.type = tarfile.REGTYPE
            # To have them in tar, don't use clean dictionary
            tgz_file.write_bytes(_make_tgz({}, custom_tarinfos=[(ti_dir, b""), (ti_file, b"data")]))
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertTrue("Duplicate member path" in str(ctx.exception) or "Path conflict" in str(ctx.exception))

            # Path conflict: file declared as ancestor of another file
            ti_parent_file = tarfile.TarInfo(name="package/parent")
            ti_parent_file.type = tarfile.REGTYPE
            ti_child_file = tarfile.TarInfo(name="package/parent/child.js")
            ti_child_file.type = tarfile.REGTYPE
            tgz_file.write_bytes(_make_tgz({}, custom_tarinfos=[(ti_parent_file, b"data"), (ti_child_file, b"data")]))
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("Path conflict", str(ctx.exception))

            # package.json is not a dict (e.g. JSON array)
            tgz_bad_json = _make_tgz({"package/package.json": "[1, 2, 3]"})
            tgz_file.write_bytes(tgz_bad_json)
            with self.assertRaises(ValueError) as ctx:
                build_sample(tgz_file, "4.17.20", base / "out")
            self.assertIn("package.json must be a JSON object", str(ctx.exception))

    def test_valid_npm_build_and_determinism(self) -> None:
        """Verify npm archive mode (package/) build and determinism."""
        tgz_bytes_20 = _make_valid_lodash_tgz("4.17.20")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tgz_file_20 = base / "lodash-4.17.20.tgz"
            tgz_file_20.write_bytes(tgz_bytes_20)

            out1 = base / "out1"
            out2 = base / "out2"

            res1 = build_sample(tgz_file_20, "4.17.20", out1, source_kind="npm-package-archive")
            res2 = build_sample(tgz_file_20, "4.17.20", out2, source_kind="npm-package-archive")

            self.assertEqual(res1["sourceKind"], "npm-package-archive")
            self.assertEqual(res1["version"], "4.17.20")
            self.assertEqual(res1["manifestDigest"], res2["manifestDigest"])
            self.assertEqual(res1["configDigest"], res2["configDigest"])
            self.assertEqual(res1["layerDigest"], res2["layerDigest"])
            self.assertEqual(res1["diffId"], res2["diffId"])

    def test_local_registry_strict_validation_and_tamper_rejection(self) -> None:
        """LocalRegistry must strictly validate index descriptors and reject tampered/missing blobs with ValueError."""
        tgz_20 = _make_valid_lodash_tgz("4.17.20")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tgz_f20 = base / "sample.tgz"
            tgz_f20.write_bytes(tgz_20)

            layout_dir = base / "layout"
            build_sample(tgz_f20, "4.17.20", layout_dir)

            # 1. Missing blob file on disk
            blobs_dir = layout_dir / "blobs" / "sha256"
            first_blob = next(blobs_dir.iterdir())
            blob_backup = first_blob.read_bytes()
            first_blob.unlink()

            with self.assertRaises(ValueError) as ctx:
                LocalRegistry(layout_dir)
            self.assertIn("Missing", str(ctx.exception))

            # Restore blob
            first_blob.write_bytes(blob_backup)

            # 2. Tampered blob bytes (hash mismatch)
            first_blob.write_bytes(blob_backup + b"\x00")
            with self.assertRaises(ValueError) as ctx:
                LocalRegistry(layout_dir)
            self.assertTrue("Size mismatch" in str(ctx.exception) or "Integrity check failed" in str(ctx.exception))

            first_blob.write_bytes(blob_backup)

            # 3. Invalid manifest digest in index.json (not sha256:<64 hex>)
            index_path = layout_dir / "index.json"
            index_content = index_path.read_text("utf-8")
            bad_index = index_content.replace("sha256:", "sha512:")
            index_path.write_text(bad_index, "utf-8")

            with self.assertRaises(ValueError) as ctx:
                LocalRegistry(layout_dir)
            self.assertIn("Invalid manifest digest", str(ctx.exception))

            # 4. Declared size mismatch in index.json
            bad_size_index = index_content.replace('"size":', '"size": 99999999, "_old_size":')
            index_path.write_text(bad_size_index, "utf-8")

            with self.assertRaises(ValueError) as ctx:
                LocalRegistry(layout_dir)
            self.assertIn("Size mismatch", str(ctx.exception))

            index_path.write_text(index_content, "utf-8")

            # 5. Invalid mediaType in index.json
            bad_type_index = index_content.replace("application/vnd.oci.image.manifest.v1+json", "application/json")
            index_path.write_text(bad_type_index, "utf-8")

            with self.assertRaises(ValueError) as ctx:
                LocalRegistry(layout_dir)
            self.assertIn("disallowed manifest mediaType", str(ctx.exception))

    def test_local_registry_runtime_endpoints(self) -> None:
        """Verify normal runtime endpoints of LocalRegistry."""
        tgz_20 = _make_valid_lodash_tgz("4.17.20")
        tgz_21 = _make_valid_lodash_tgz("4.17.21")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tgz_f20 = base / "lodash-4.17.20.tgz"
            tgz_f21 = base / "lodash-4.17.21.tgz"
            tgz_f20.write_bytes(tgz_20)
            tgz_f21.write_bytes(tgz_21)

            res20 = build_sample(tgz_f20, "4.17.20", base / "layout20")
            res21 = build_sample(tgz_f21, "4.17.21", base / "layout21")

            with LocalRegistry([res20, res21]) as reg:
                # GET /v2/
                with urllib.request.urlopen(f"{reg.base_url}/v2/") as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers.get("Docker-Distribution-API-Version"), "registry/2.0")

                # GET manifest
                m_digest = res20["manifestDigest"]
                with urllib.request.urlopen(f"{reg.base_url}/v2/sample/manifests/{m_digest}") as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers.get("Docker-Content-Digest"), m_digest)
                    data = resp.read()
                    self.assertEqual(f"sha256:{hashlib.sha256(data).hexdigest()}", m_digest)

                # GET blob
                cfg_digest = res20["configDigest"]
                with urllib.request.urlopen(f"{reg.base_url}/v2/sample/blobs/{cfg_digest}") as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers.get("Docker-Content-Digest"), cfg_digest)

                # 405 on POST
                req = urllib.request.Request(f"{reg.base_url}/v2/sample/manifests/{m_digest}", method="POST")
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                self.assertEqual(ctx.exception.code, 405)

    def test_cli_build_and_pair_support(self) -> None:
        """Verify CLI build command supporting auto source detection and index.json output."""
        tgz_20 = _make_valid_github_source_tgz("4.17.20", "ded9bc6")
        tgz_21 = _make_valid_github_source_tgz("4.17.21", "f299b52")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tgz_f20 = base / "lodash-4.17.20.tar.gz"
            tgz_f21 = base / "lodash-4.17.21.tar.gz"
            tgz_f20.write_bytes(tgz_20)
            tgz_f21.write_bytes(tgz_21)

            out_dir = base / "images_out"

            code = main([
                "build",
                "--before-tgz", str(tgz_f20),
                "--after-tgz", str(tgz_f21),
                "--out-dir", str(out_dir),
            ])
            self.assertEqual(code, 0)

            index_path = out_dir / "index.json"
            self.assertTrue(index_path.is_file())
            index_data = json.loads(index_path.read_text("utf-8"))

            self.assertEqual(index_data["before"]["sourceKind"], "github-source-archive")
            self.assertEqual(index_data["after"]["sourceKind"], "github-source-archive")
            self.assertIn("fileSha256s", index_data["before"])
            self.assertIn("fileSha256s", index_data["after"])

            # LocalRegistry should be able to load paired out_dir directly
            with LocalRegistry(out_dir) as reg:
                self.assertGreater(reg.port, 0)
                m_before = index_data["before"]["manifestDigest"]
                with urllib.request.urlopen(f"{reg.base_url}/v2/sample/manifests/{m_before}") as resp:
                    self.assertEqual(resp.status, 200)

    def test_actual_work_lodash_sources_if_present(self) -> None:
        """Integration test with actual GitHub source archives in work/lodash-sources/ if present."""
        root_dir = Path(__file__).resolve().parent.parent
        src20 = root_dir / "work" / "lodash-sources" / "lodash-4.17.20.tar.gz"
        src21 = root_dir / "work" / "lodash-sources" / "lodash-4.17.21.tar.gz"

        if not (src20.is_file() and src21.is_file()):
            self.skipTest("Actual work/lodash-sources not present")

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "real_images"
            index_data = build_sample_pair(src20, src21, out_dir)

            # Verify against provenance SHA-256
            self.assertEqual(index_data["before"]["archiveSha256"], "345283811f0c9a81551ec605a5d6b6c152c40cf11059d6b7568a496c83807a4a")
            self.assertEqual(index_data["after"]["archiveSha256"], "6a70a8d1053da80c542979250811189b269d6319ff07185f405f960805f973d1")
            self.assertEqual(index_data["before"]["sourceKind"], "github-source-archive")
            self.assertEqual(index_data["after"]["sourceKind"], "github-source-archive")

            # Verify layer contains strictly 3 files
            b_layer_hex = index_data["before"]["layerDigest"].split(":")[1]
            b_layer_bytes = (out_dir / "before" / "blobs" / "sha256" / b_layer_hex).read_bytes()
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(b_layer_bytes))) as tf:
                members = sorted(m.name for m in tf.getmembers())
                self.assertEqual(members, [
                    "app",
                    "app/node_modules",
                    "app/node_modules/lodash",
                    "app/node_modules/lodash/LICENSE",
                    "app/node_modules/lodash/lodash.js",
                    "app/node_modules/lodash/package.json",
                ])

            # Verify LocalRegistry can serve both images
            with LocalRegistry(out_dir) as reg:
                m_before = index_data["before"]["manifestDigest"]
                m_after = index_data["after"]["manifestDigest"]

                with urllib.request.urlopen(f"{reg.base_url}/v2/sample/manifests/{m_before}") as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers.get("Docker-Content-Digest"), m_before)

                with urllib.request.urlopen(f"{reg.base_url}/v2/sample/manifests/{m_after}") as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers.get("Docker-Content-Digest"), m_after)


if __name__ == "__main__":
    unittest.main()
