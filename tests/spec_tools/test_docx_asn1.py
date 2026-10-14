# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Trap tests for spec/tools/docx_asn1.py on synthetic WordprocessingML.

Every trap a real 3GPP .docx was seen (or is known) to contain gets a minimal
document here, so a regression in the extractor shows up without the 50 MB
specs. Run: python3 -m unittest discover -s tests/spec_tools
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "spec" / "tools"))
import docx_asn1 as dx  # noqa: E402

NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def run(text: str) -> str:
    return f'<w:r><w:t xml:space="preserve">{text}</w:t></w:r>'


def para(*runs: str) -> str:
    return "<w:p>" + "".join(runs) + "</w:p>"


def doc(*paras: str) -> bytes:
    return f'<w:document {NS}><w:body>{"".join(paras)}</w:body></w:document>'.encode()


START, STOP = para(run("-- ASN1START")), para(run("-- ASN1STOP"))


def lines(*inner: str, repairs=None) -> list[str]:
    return dx.asn1_lines(doc(*inner), repairs)


class Traps(unittest.TestCase):
    def test_tab_is_a_sibling_of_text(self):
        got = lines(START, para("<w:r><w:t>id</w:t><w:tab/><w:t>INTEGER</w:t></w:r>"), STOP)
        self.assertEqual(got, ["id\tINTEGER"])

    def test_br_is_a_newline(self):
        got = lines(START, para("<w:r><w:t>A ::= SEQUENCE {</w:t><w:br/><w:t>}</w:t></w:r>"), STOP)
        self.assertEqual(got, ["A ::= SEQUENCE {", "}"])

    def test_hyphens(self):
        got = lines(START, para("<w:r><w:t>max</w:t><w:noBreakHyphen/><w:t>Val</w:t>"
                                "<w:softHyphen/><w:t>ue</w:t></w:r>"), STOP)
        self.assertEqual(got, ["max-Value"])

    def test_deleted_text_and_field_codes_are_not_text(self):
        got = lines(START, para("<w:r><w:t>A</w:t></w:r>",
                                "<w:del><w:r><w:delText>GONE</w:delText></w:r></w:del>",
                                "<w:r><w:instrText> PAGEREF _Toc123 \\h </w:instrText></w:r>",
                                "<w:ins><w:r><w:t>B</w:t></w:r></w:ins>"), STOP)
        self.assertEqual(got, ["AB"])

    def test_text_boxes_are_not_part_of_the_paragraph(self):
        got = lines(START, para(run("X ::= BOOLEAN"),
                                "<w:r><w:drawing><w:txbxContent>" + para(run("FLOATING"))
                                + "</w:txbxContent></w:drawing></w:r>"), STOP)
        self.assertEqual(got, ["X ::= BOOLEAN"])

    def test_nbsp_quotes_and_dashes_become_ascii(self):
        got = lines(START, para(run("a b “q” ‘r’ –– c")), STOP)
        self.assertEqual(got, ['a b "q" \'r\' -- c'])

    def test_table_cell_paragraphs_are_read_in_order(self):
        tbl = ("<w:tbl><w:tr><w:tc>" + para(run("Row1")) + "</w:tc><w:tc>" + para(run("Row2"))
               + "</w:tc></w:tr></w:tbl>")
        self.assertEqual(lines(START, tbl, STOP), ["Row1", "Row2"])

    def test_marker_split_over_runs(self):
        got = lines(para(run("-- ASN1"), run("START")), para(run("Z ::= NULL")),
                    para(run("-- ASN1"), run("STOP")))
        self.assertEqual(got, ["Z ::= NULL"])

    def test_unbalanced_markers_raise(self):
        with self.assertRaises(dx.ExtractError):
            lines(START, para(run("A ::= NULL")))
        with self.assertRaises(dx.ExtractError):
            lines(STOP)
        with self.assertRaises(dx.ExtractError):
            lines(START, START, STOP)
        with self.assertRaises(dx.ExtractError):
            lines(para(run("prose only")))

    def test_prose_mentioning_the_marker_is_not_a_marker(self):
        got = lines(para(run("Text between ASN1START and ASN1STOP is normative.")), START,
                    para(run("A ::= NULL")), STOP)
        self.assertEqual(got, ["A ::= NULL"])

    def test_example_blocks_are_skipped(self):
        got = lines(para(run("-- /example/ ASN1START")), para(run("Bad ::= BOOLEAN")),
                    para(run("-- /example/ ASN1STOP")),
                    para(run("-- /bad example/ ASN1START")), para(run("}-- ASN1STOP")),
                    START, para(run("Good ::= NULL")), STOP)
        self.assertEqual(got, ["Good ::= NULL"])

    def test_stop_after_code_keeps_the_code(self):
        got = lines(START, para(run("A ::= SEQUENCE {")), para(run("}-- ASN1STOP")))
        self.assertEqual(got, ["A ::= SEQUENCE {", "}"])

    def test_stop_typo_needs_a_recorded_repair(self):
        body = (START, para(run("A ::= NULL")), para(run("-- ASN1STO")))
        with self.assertRaises(dx.ExtractError):
            lines(*body)
        self.assertEqual(lines(*body, repairs=["stop-typo:--ASN1STO"]), ["A ::= NULL"])

    def test_split_repair_inserts_the_missing_break_and_must_apply(self):
        body = (START, para(run("a INTEGER ::= 925b INTEGER ::= 926")), STOP)
        got = lines(*body, repairs=["split-after:INTEGER ::= 925"])
        self.assertEqual(got, ["a INTEGER ::= 925", "b INTEGER ::= 926"])
        with self.assertRaises(dx.ExtractError):
            lines(START, para(run("a INTEGER ::= 1")), STOP, repairs=["split-after:INTEGER ::= 925"])

    def test_symbol_font_glyph_inside_asn1_raises(self):
        with self.assertRaises(dx.ExtractError):
            lines(START, para('<w:r><w:sym w:font="Symbol" w:char="F0B3"/></w:r>'), STOP)


class Modules(unittest.TestCase):
    def test_multi_line_header_and_end(self):
        src = ["-- comment", "Mod-A  {", "itu-t (0) x (1)}", "", "DEFINITIONS AUTOMATIC TAGS ::=",
               "", "BEGIN", "A ::= NULL", "END", "", "Mod-B DEFINITIONS ::= BEGIN", "END"]
        mods = dx.split_modules(src)
        self.assertEqual([m.name for m in mods], ["Mod-A", "Mod-B"])
        self.assertEqual(mods[0].lines[0], "Mod-A  {")
        self.assertEqual(mods[0].lines[-1], "END")

    def test_text_outside_modules_and_missing_end_raise(self):
        with self.assertRaises(dx.ExtractError):
            dx.split_modules(["x ::= 1"])
        with self.assertRaises(dx.ExtractError):
            dx.split_modules(["M DEFINITIONS ::= BEGIN", "A ::= NULL"])
        with self.assertRaises(dx.ExtractError):
            dx.split_modules(["M DEFINITIONS ::= BEGIN", "END", "M DEFINITIONS ::= BEGIN", "END"])


if __name__ == "__main__":
    unittest.main()
