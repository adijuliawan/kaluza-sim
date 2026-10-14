# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Value-form tests for spec/tools/kat_extract.py and the bit tables of
spec/tools/docx_tables.py. Every form a pinned document uses has a case here,
including the traps: hex labels such as f1, right-aligned BEARER fields and
text-valued SUCIs."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "spec" / "tools"))
import docx_lib as dl  # noqa: E402
import docx_tables as dt  # noqa: E402
import kat_extract as ke  # noqa: E402


def vecs(lines, markers=None):
    return {v.field: v for v in ke.collect(lines, markers).vectors("1", "x")}


class Forms(unittest.TestCase):
    def test_colon_tab_hex_and_hex_looking_labels(self):
        v = vecs(["K:\t\t\tabababababababababababababababab", "f1:\t\t\tf9a54e6aeaa8618d",
                  "f5*:\t\te7af6b3d0e38"])
        self.assertEqual(v["K"].hex, "ab" * 16)
        self.assertEqual(v["f1"].hex, "f9a54e6aeaa8618d")     # 'f1' looks like hex but is a label
        self.assertEqual(v["f5*"].hex, "e7af6b3d0e38")

    def test_binary_block_marker_and_hex_twin(self):
        v = vecs(["Binary Format", "AMF:\t10111001 10111001", "Hexadecimal Format", "AMF:\tb9b9"],
                 {"Binary Format": "bin", "Hexadecimal Format": "hex"})
        self.assertEqual(v["AMF"].hex, "b9b9")
        self.assertEqual(v["AMF"].bits, 16)

    def test_hex_bin_twins_with_continuations(self):
        v = vecs(["Key        = (hex) d3c5d592 327fb11c",
                  "Key        = (bin) 11010011 11000101 11010101 10010010",
                  "                   00110010 01111111 10110001 00011100"])
        self.assertEqual(v["Key"].hex, "d3c5d592327fb11c")

    def test_right_aligned_bearer_twin_is_accepted(self):
        v = vecs(["Bearer     = (hex) 15", "Bearer     = (bin) 10101 "])
        self.assertEqual(v["Bearer"].hex, "15")
        self.assertEqual(v["Bearer"].bits, 5)

    def test_disagreeing_twins_raise(self):
        with self.assertRaises(dl.ExtractError):
            vecs(["X = (hex) ff", "X = (bin) 00000001"])

    def test_brace_value_over_lines_and_params(self):
        v = vecs(["Inputs: KEY_sz=32, RAND_sz=32, SQN_sz=12", "        OP = { c0 c1 c2 c3 ",
                  "               d0 d1 }", "       AMF = { b0 b1 }"])
        self.assertEqual(v["OP"].hex, "c0c1c2c3d0d1")
        self.assertEqual(v["AMF"].hex, "b0b1")
        self.assertEqual(v["KEY_sz"].hex, "20")

    def test_label_line_then_quoted_value_and_text_scheme_output(self):
        v = vecs(["Eph. Shared Key:", "'028ddf890ec83cdf'", "Scheme Output: useridverylongusername1"])
        self.assertEqual(v["Eph. Shared Key"].hex, "028ddf890ec83cdf")
        self.assertEqual(v["Scheme Output"].text, "useridverylongusername1")

    def test_label_then_hex_lines_and_blank_ends_value(self):
        v = vecs(["IN: ", "24 76 d2 da", "c5 9e", "", "48 81 FF 48"])
        self.assertEqual(v["IN"].hex, "2476d2dac59e")

    def test_length_in_bits(self):
        v = vecs(["Length     = 253 bits"])
        self.assertEqual(v["Length"].hex, "fd")

    def test_variable_value_table_rows(self):
        v = vecs([ke.TABLE_ROW + "Variable\tValue", ke.TABLE_ROW + "f2\ta54211d5 e3ba50bf"])
        self.assertEqual(v["f2"].hex, "a54211d5e3ba50bf")
        self.assertNotIn("Variable", v)


class BitTables(unittest.TestCase):
    def test_bit_rows(self):
        t = dl.Table([[dl.Cell(x) for x in r] for r in [
            ["8", "7", "6", "5", "4", "3", "2", "1", "", ""],
            ["0", "1", "0", "0", "0", "0", "0", "1", "", "Registration request"],
            ["0", "1", "-", "-", "-", "-", "-", "-", "", "5GS mobility management messages"]]])
        self.assertEqual(dt.bit_table(t), [(0x41, "Registration request")])


if __name__ == "__main__":
    unittest.main()
