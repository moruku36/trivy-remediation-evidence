from __future__ import annotations

import json
from pathlib import Path
import unittest

from trivy_remediation_evidence.renderer import (
    escape_markdown,
    load_reason_catalog,
    render_markdown,
)


class TestRenderer(unittest.TestCase):
    def test_escape_special_characters_and_colon(self) -> None:
        raw = '& < > " \' \\ | ` * _ { } [ ] ( ) # + - . ! ~ :'
        escaped = escape_markdown(raw, "ja")
        expected = (
            "&#38; &#60; &#62; &#34; &#39; &#92; &#124; &#96; &#42; &#95; "
            "&#123; &#125; &#91; &#93; &#40; &#41; &#35; &#43; &#45; &#46; &#33; &#126; &#58;"
        )
        self.assertEqual(escaped, expected)

    def test_escape_no_double_escape(self) -> None:
        # A string that already contains HTML entities should escape each char once without double escaping
        raw = "&#38;"
        escaped = escape_markdown(raw, "ja")
        # '&' -> '&#38;', '#' -> '&#35;', '3' -> '3', '8' -> '8', ';' -> ';' (semicolon is not in map)
        self.assertEqual(escaped, "&#38;&#35;38;")

    def test_escape_crlf_cr_lf_and_tab(self) -> None:
        raw = "line1\r\nline2\rline3\nline4\tcol"
        escaped = escape_markdown(raw, "ja")
        self.assertEqual(escaped, "line1↵line2↵line3↵line4⇥col")

    def test_escape_c0_del_and_bidi(self) -> None:
        # \x00 (NUL), \x1f (US), \x7f (DEL), \u202e (RLO), \u200e (LRM)
        raw = "text\x00ctrl\x1fdel\x7fbidi\u202eoverride\u200emark"
        escaped = escape_markdown(raw, "ja")
        self.assertEqual(
            escaped,
            "text\\u0000ctrl\\u001Fdel\\u007Fbidi\\u202Eoverride\\u200Emark",
        )

    def test_null_and_empty_distinction(self) -> None:
        # JA
        self.assertEqual(escape_markdown(None, "ja"), "不明")
        self.assertEqual(escape_markdown("", "ja"), "空文字列")
        # EN
        self.assertEqual(escape_markdown(None, "en"), "Unknown")
        self.assertEqual(escape_markdown("", "en"), "Empty string")

    def test_boolean_and_numbers(self) -> None:
        self.assertEqual(escape_markdown(True, "ja"), "true")
        self.assertEqual(escape_markdown(False, "ja"), "false")
        self.assertEqual(escape_markdown(0, "ja"), "0")
        self.assertEqual(escape_markdown(12345, "ja"), "12345")

    def test_malicious_title_safety(self) -> None:
        malicious = "synthetic | [link](javascript:alert(1)) <img src=x> `code`\n# heading ‮"
        escaped = escape_markdown(malicious, "ja")
        # Ensure pipe, brackets, html tags, backticks, newlines, and bidi are escaped
        self.assertNotIn("|", escaped)
        self.assertNotIn("<", escaped)
        self.assertNotIn(">", escaped)
        self.assertNotIn("`", escaped)
        self.assertNotIn("\n", escaped)
        self.assertIn("&#124;", escaped)
        self.assertIn("&#60;", escaped)
        self.assertIn("&#62;", escaped)
        self.assertIn("&#96;", escaped)
        self.assertIn("↵", escaped)
        self.assertIn("\\u202E", escaped)

    def test_render_markdown_case03_structure(self) -> None:
        case03_path = Path("outputs/examples/evidence.case03.json")
        if not case03_path.exists():
            self.skipTest("evidence.case03.json not found")

        evidence = json.loads(case03_path.read_text(encoding="utf-8"))

        # Render JA
        ja_md = render_markdown(evidence, "ja")
        self.assertTrue(ja_md.startswith("# Trivy脆弱性比較の証拠\n\n比較状態&#58; 比較可能\n\n## 分類件数\n\n"))
        self.assertIn("## 分類件数\n\n| 分類 | 件数 |\n| --- | --- |\n| 新規 | 0 |\n| 継続 | 0 |\n| 今回未検出 | 1 |\n| 比較不可 | 0 |\n\nbefore観測数&#58; 1\nafter観測数&#58; 0\n\n", ja_md)
        self.assertIn("## 比較条件と理由\n\n| code | 説明 | 参照 |\n| --- | --- | --- |\n\n", ja_md)
        self.assertIn("## 入力の証拠\n\n| side | kind | sha256 | parseState |\n", ja_md)
        self.assertIn("## 実行の証拠\n\n### before\n\n| field | value |\n", ja_md)
        self.assertIn("### after\n\n| field | value |\n", ja_md)
        self.assertIn("## 検出項目\n\n| imageLogicalId | targetLogicalId | path | class | ecosystem | packageName | vulnerabilityId | 分類 | beforeVersion | afterVersion | beforeStatus | afterStatus | beforeFixedVersion | afterFixedVersion | Title | evidence | reasonCodes | remediationConclusion |\n", ja_md)
        self.assertIn("## 制約\n\n今回未検出は修正済みの証明ではありません。Status・FixedVersionは配布元の修正版情報です。\n\nこの比較は供給されたJSONとmanifestの記録に基づきます。manifestの正しさや実際の修正作業を独立に検証していません。\n", ja_md)
        self.assertTrue(ja_md.endswith("\n"))

        # Render EN
        en_md = render_markdown(evidence, "en")
        self.assertTrue(en_md.startswith("# Trivy vulnerability comparison evidence\n\nComparison&#58; Comparable\n\n## Classification counts\n\n"))
        self.assertIn("## Classification counts\n\n| Classification | Count |\n| --- | --- |\n| New | 0 |\n| Persistent | 0 |\n| Not detected in this scan | 1 |\n| Comparison unavailable | 0 |\n\nbefore observed count&#58; 1\nafter observed count&#58; 0\n\n", en_md)
        self.assertIn("## Comparison conditions and reasons\n\n| Code | Explanation | References |\n| --- | --- | --- |\n\n", en_md)
        self.assertIn("## Input evidence\n\n| side | kind | sha256 | parseState |\n", en_md)
        self.assertIn("## Findings\n\n| imageLogicalId | targetLogicalId | path | class | ecosystem | packageName | vulnerabilityId | Classification | beforeVersion | afterVersion | beforeStatus | afterStatus | beforeFixedVersion | afterFixedVersion | Title | evidence | reasonCodes | remediationConclusion |\n", en_md)
        self.assertIn("## Limitations\n\nNot detected in this scan does not prove remediation. Status and FixedVersion describe distributor fix information.\n\nThis comparison relies on the supplied JSON and manifest records. It does not independently verify manifest accuracy or remediation work.\n", en_md)
        self.assertTrue(en_md.endswith("\n"))

    def test_load_reason_catalog(self) -> None:
        cat = load_reason_catalog()
        self.assertIn("INPUT_INVALID_JSON", cat)
        self.assertIn("ja", cat["INPUT_INVALID_JSON"])
        self.assertIn("en", cat["INPUT_INVALID_JSON"])


if __name__ == "__main__":
    unittest.main()
