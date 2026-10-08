from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from trivy_remediation_evidence.reader import (
    MAX_FILE_BYTES,
    MAX_FINDINGS_COUNT,
    MAX_JSON_DEPTH,
    MAX_STRING_BYTES,
    read_json_bytes,
    read_source_file,
)


class TestStrictReader(unittest.TestCase):
    def test_valid_json(self) -> None:
        raw = b'{"name": "test", "count": 42}'
        res = read_json_bytes(raw, side="before", kind="manifest")
        self.assertEqual(res.parse_state, "valid")
        self.assertEqual(res.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(res.data, {"name": "test", "count": 42})
        self.assertEqual(res.reasons, [])

    def test_unreadable_file(self) -> None:
        missing_path = Path("non_existent_file_xyz_12345.json")
        res = read_source_file(missing_path, side="after", kind="report")
        self.assertEqual(res.parse_state, "unreadable")
        self.assertIsNone(res.sha256)
        self.assertIsNone(res.data)
        self.assertEqual(len(res.reasons), 1)
        self.assertEqual(res.reasons[0].code, "INPUT_UNREADABLE")
        self.assertEqual(res.reasons[0].refs[0].pointer, "")

    def test_bom_rejection(self) -> None:
        raw = b"\xef\xbb\xbf" + b'{"valid": true}'
        res = read_json_bytes(raw, side="before", kind="report")
        self.assertEqual(res.parse_state, "invalid_json")
        self.assertEqual(res.sha256, hashlib.sha256(raw).hexdigest())
        self.assertIsNone(res.data)
        self.assertEqual(len(res.reasons), 1)
        self.assertEqual(res.reasons[0].code, "INPUT_INVALID_JSON")

    def test_invalid_utf8_rejection(self) -> None:
        raw = b'{"invalid": \xff\xfe}'
        res = read_json_bytes(raw, side="after", kind="manifest")
        self.assertEqual(res.parse_state, "invalid_json")
        self.assertEqual(len(res.reasons), 1)
        self.assertEqual(res.reasons[0].code, "INPUT_INVALID_JSON")

    def test_duplicate_keys_rejection(self) -> None:
        raw = b'{"duplicate_key": 1, "other": 2, "duplicate_key": 3}'
        res = read_json_bytes(raw, side="before", kind="manifest")
        self.assertEqual(res.parse_state, "invalid_json")
        self.assertEqual(len(res.reasons), 1)
        self.assertEqual(res.reasons[0].code, "INPUT_INVALID_JSON")

    def test_non_finite_rejection(self) -> None:
        for bad_val in [b'{"val": NaN}', b'{"val": Infinity}', b'{"val": -Infinity}', b'{"val": 1e9999}']:
            with self.subTest(bad_val=bad_val):
                res = read_json_bytes(bad_val, side="after", kind="report")
                self.assertEqual(res.parse_state, "invalid_json")
                self.assertEqual(res.reasons[0].code, "INPUT_INVALID_JSON")

    def test_trailing_garbage_rejection(self) -> None:
        for trailing in [b'{"valid": true} trailing_junk', b'{"a": 1} {"b": 2}', b'{"a": 1} ,']:
            with self.subTest(trailing=trailing):
                res = read_json_bytes(trailing, side="before", kind="report")
                self.assertEqual(res.parse_state, "invalid_json")
                self.assertEqual(res.reasons[0].code, "INPUT_INVALID_JSON")

    def test_empty_input_rejection(self) -> None:
        for empty in [b"", b"   \r\n\t  "]:
            with self.subTest(empty=empty):
                res = read_json_bytes(empty, side="after", kind="manifest")
                self.assertEqual(res.parse_state, "invalid_json")
                self.assertEqual(res.reasons[0].code, "INPUT_INVALID_JSON")

    def test_whitespace_strictness_and_nbsp_rejection(self) -> None:
        # Valid JSON whitespace: SP (0x20), TAB (0x09), LF (0x0A), CR (0x0D)
        valid_ws = b" \t\r\n{\"ok\": true}\r\n\t "
        res_valid = read_json_bytes(valid_ws, side="before", kind="report")
        self.assertEqual(res_valid.parse_state, "valid")

        # NBSP (U+00A0: \xc2\xa0) leading
        res_leading_nbsp = read_json_bytes(b"\xc2\xa0{}", side="before", kind="report")
        self.assertEqual(res_leading_nbsp.parse_state, "invalid_json")
        self.assertEqual(res_leading_nbsp.reasons[0].code, "INPUT_INVALID_JSON")

        # NBSP trailing
        res_trailing_nbsp = read_json_bytes(b"{}\xc2\xa0", side="after", kind="report")
        self.assertEqual(res_trailing_nbsp.parse_state, "invalid_json")
        self.assertEqual(res_trailing_nbsp.reasons[0].code, "INPUT_INVALID_JSON")

        # Ideographic space (U+3000: \xe3\x80\x80)
        res_ideo = read_json_bytes(b"\xe3\x80\x80{}", side="before", kind="manifest")
        self.assertEqual(res_ideo.parse_state, "invalid_json")
        self.assertEqual(res_ideo.reasons[0].code, "INPUT_INVALID_JSON")

    def test_large_integer_digit_limit_safe_handling(self) -> None:
        # b'1' * 5000 exceeds Python 3.11 default integer conversion limit (4300 digits)
        raw_large_int = b'{"val": ' + (b"1" * 5000) + b"}"
        res = read_json_bytes(raw_large_int, side="before", kind="report")
        self.assertEqual(res.parse_state, "limit_exceeded")
        self.assertEqual(res.sha256, hashlib.sha256(raw_large_int).hexdigest())
        self.assertEqual(len(res.reasons), 1)
        self.assertEqual(res.reasons[0].code, "INPUT_LIMIT_EXCEEDED")
        self.assertEqual(res.reasons[0].refs[0].pointer, "")

    def test_nesting_depth_boundary(self) -> None:
        # Depth 64: valid
        valid_nested = ("[" * 64) + ("1" + ("]" * 64))
        res_valid = read_json_bytes(valid_nested.encode("utf-8"), side="before", kind="manifest")
        self.assertEqual(res_valid.parse_state, "valid")

        # Depth 65: limit exceeded
        invalid_nested = ("[" * 65) + ("1" + ("]" * 65))
        res_invalid = read_json_bytes(invalid_nested.encode("utf-8"), side="before", kind="manifest")
        self.assertEqual(res_invalid.parse_state, "limit_exceeded")
        self.assertEqual(res_invalid.reasons[0].code, "INPUT_LIMIT_EXCEEDED")

    def test_string_utf8_byte_length_boundaries_ascii_and_japanese(self) -> None:
        # ASCII boundary: 1,048,576 bytes
        s_ascii_exact = "a" * MAX_STRING_BYTES
        raw_ascii_exact = json.dumps({"k": s_ascii_exact}).encode("utf-8")
        res_ascii_exact = read_json_bytes(raw_ascii_exact, side="before", kind="report")
        self.assertEqual(res_ascii_exact.parse_state, "valid")

        # ASCII boundary + 1 byte: 1,048,577 bytes
        s_ascii_over = "a" * (MAX_STRING_BYTES + 1)
        raw_ascii_over = json.dumps({"k": s_ascii_over}).encode("utf-8")
        res_ascii_over = read_json_bytes(raw_ascii_over, side="before", kind="report")
        self.assertEqual(res_ascii_over.parse_state, "limit_exceeded")
        self.assertEqual(res_ascii_over.reasons[0].code, "INPUT_LIMIT_EXCEEDED")

        # Japanese boundary: 'あ' is 3 bytes in UTF-8
        # 349,525 * 3 = 1,048,575 bytes (<= 1 MiB) -> valid
        s_ja_exact = "あ" * 349525
        self.assertEqual(len(s_ja_exact.encode("utf-8")), 1048575)
        raw_ja_exact = json.dumps({"k": s_ja_exact}).encode("utf-8")
        res_ja_exact = read_json_bytes(raw_ja_exact, side="after", kind="report")
        self.assertEqual(res_ja_exact.parse_state, "valid")

        # 349,526 * 3 = 1,048,578 bytes (> 1 MiB) -> limit exceeded
        s_ja_over = "あ" * 349526
        self.assertEqual(len(s_ja_over.encode("utf-8")), 1048578)
        raw_ja_over = json.dumps({"k": s_ja_over}).encode("utf-8")
        res_ja_over = read_json_bytes(raw_ja_over, side="after", kind="report")
        self.assertEqual(res_ja_over.parse_state, "limit_exceeded")
        self.assertEqual(res_ja_over.reasons[0].code, "INPUT_LIMIT_EXCEEDED")

    def test_unpaired_surrogates_rejection(self) -> None:
        # Lone high surrogate
        raw_high = b'{"msg": "\\ud800"}'
        res_high = read_json_bytes(raw_high, side="before", kind="report")
        self.assertEqual(res_high.parse_state, "invalid_json")
        self.assertEqual(res_high.reasons[0].code, "INPUT_INVALID_JSON")

        # Lone low surrogate
        raw_low = b'{"msg": "\\udc00"}'
        res_low = read_json_bytes(raw_low, side="after", kind="report")
        self.assertEqual(res_low.parse_state, "invalid_json")
        self.assertEqual(res_low.reasons[0].code, "INPUT_INVALID_JSON")

        # Valid surrogate pair (U+1F600 GRINNING FACE)
        raw_pair = b'{"msg": "\\ud83d\\ude00"}'
        res_pair = read_json_bytes(raw_pair, side="before", kind="report")
        self.assertEqual(res_pair.parse_state, "valid")
        self.assertEqual(res_pair.data, {"msg": "\U0001f600"})

    def test_streaming_chunk_file_read_and_50mib_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / "large.json"
            # Write 50 MiB + 64 bytes using chunks
            hasher = hashlib.sha256()
            chunk = b"x" * 65536
            total_target = MAX_FILE_BYTES + 64
            written = 0
            with tmp_path.open("wb") as f:
                while written < total_target:
                    to_write = min(len(chunk), total_target - written)
                    f.write(chunk[:to_write])
                    hasher.update(chunk[:to_write])
                    written += to_write

            expected_sha256 = hasher.hexdigest()
            res = read_source_file(tmp_path, side="before", kind="report")
            self.assertEqual(res.parse_state, "limit_exceeded")
            self.assertEqual(res.sha256, expected_sha256)
            self.assertIsNone(res.data)
            self.assertEqual(res.reasons[0].code, "INPUT_LIMIT_EXCEEDED")

    def test_report_findings_count_boundary(self) -> None:
        # Findings count: 100,000 allowed
        vulns_100k = [{"VulnerabilityID": "V-1"} for _ in range(MAX_FINDINGS_COUNT)]
        report_100k = {"SchemaVersion": 2, "Results": [{"Vulnerabilities": vulns_100k}]}
        raw_100k = json.dumps(report_100k).encode("utf-8")
        res_100k = read_json_bytes(raw_100k, side="after", kind="report")
        self.assertEqual(res_100k.parse_state, "valid")

        # Findings count: 100,001 exceeded
        vulns_100k1 = [{"VulnerabilityID": "V-1"} for _ in range(MAX_FINDINGS_COUNT + 1)]
        report_100k1 = {"SchemaVersion": 2, "Results": [{"Vulnerabilities": vulns_100k1}]}
        raw_100k1 = json.dumps(report_100k1).encode("utf-8")
        res_100k1 = read_json_bytes(raw_100k1, side="after", kind="report")
        self.assertEqual(res_100k1.parse_state, "limit_exceeded")
        self.assertEqual(res_100k1.reasons[0].code, "INPUT_LIMIT_EXCEEDED")

    def test_no_echo_of_input_in_errors_or_reasons(self) -> None:
        secret_content = "SECRET_TOKEN_DO_NOT_LEAK_XYZ987"
        raw_broken = f'{{"valid": "{secret_content}"}} trailing_garbage'.encode("utf-8")
        res = read_json_bytes(raw_broken, side="before", kind="report")
        self.assertEqual(res.parse_state, "invalid_json")

        reasons_dump = json.dumps([r.to_dict() for r in res.reasons])
        self.assertNotIn(secret_content, reasons_dump)


if __name__ == "__main__":
    unittest.main()
