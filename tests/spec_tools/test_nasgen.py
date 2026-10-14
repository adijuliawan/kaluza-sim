# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Tests for tools/nasgen.py (plan M11): the readings of the message-table
cells it relies on, and its must-fail check on an IE type used with two
lengths. Run: python3 -m unittest discover -s tests/spec_tools
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import nasgen  # noqa: E402


def row(message: str, iei: str, fmt: str, length: str, type_name: str = "Some IE", ref: str = "9.11.3.99") -> dict:
    return {"key": "8.2.99", "message": message, "seq": "1", "iei": iei, "ie_name": type_name,
            "type_name": type_name, "reference": ref, "presence": "O", "format": fmt, "length": length}


class Cells(unittest.TestCase):
    def test_lengths(self):
        self.assertEqual(nasgen.length("1/2"), (0, 0))
        self.assertEqual(nasgen.length("3-15"), (3, 15))
        self.assertEqual(nasgen.length("4-n"), (4, 0xFFFF))
        self.assertEqual(nasgen.length("4-65538"), (4, 0xFFFF))
        self.assertEqual(nasgen.length(" 7 "), (7, 7))
        with self.assertRaises(ValueError):
            nasgen.length("see 9.11")

    def test_ieis(self):
        self.assertEqual(nasgen.iei(""), (0, "none"))
        self.assertEqual(nasgen.iei("B-"), (0xB, "half"))
        self.assertEqual(nasgen.iei("7E"), (0x7E, "full"))
        with self.assertRaises(ValueError):
            nasgen.iei("7")

    def test_directions(self):
        # TS 24.501 spells a message's direction several ways
        for text, want in (("UE to network", "ul"), ("UE to AMF", "ul"), ("network to UE", "dl"),
                           ("Network to UE", "dl"), ("AMF to UE", "dl"), ("both", "both")):
            self.assertEqual(nasgen.direction(text), want, text)


class IeTypes(unittest.TestCase):
    def test_the_tables_have_no_problem(self):
        _, problems = nasgen.ie_types()
        self.assertEqual(problems, [])

    def test_a_type_with_two_fixed_lengths_is_a_problem(self):
        rows = [row("A", "52", "TV", "7"), row("B", "52", "TV", "6")]
        _, problems = nasgen.ie_types(rows)
        self.assertEqual(len(problems), 1)
        self.assertIn("TV", problems[0])

    def test_variable_formats_may_differ_in_range(self):
        rows = [row("A", "10", "TLV", "3-15"), row("B", "10", "TLV", "3-5")]
        self.assertEqual(nasgen.ie_types(rows)[1], [])


if __name__ == "__main__":
    unittest.main()
