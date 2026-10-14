#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: hand-written code never spells an asn1c container type whose name
encodes a line number of the .asn source (architecture.md §4.1).

asn1c names anonymous parameterized containers like
ProtocolExtensionContainer_<line>P<index>. Any edit to the .asn renumbers them,
so code that spells one breaks silently on the next spec update. Deduce the type
instead: std::remove_pointer_t<decltype(m->protocolIEs.list.array[0])>.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, read_text, repo_files, run_self_test, under  # noqa: E402

PATTERN = re.compile(r"\b[A-Za-z]\w*?_[0-9]+P[0-9]+(?![0-9])")
CODE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".ipp"}
SCANNED = ("src", "apps", "tests")
EXEMPT = ("tests/vectors",)


def check(root: Path) -> list[Violation]:
    out: list[Violation] = []
    for rel in repo_files(root):
        if rel.suffix not in CODE_SUFFIXES or not under(rel, *SCANNED) or under(rel, *EXEMPT):
            continue
        for n, line in enumerate(read_text(root, rel).splitlines(), start=1):
            m = PATTERN.search(line)
            if m:
                out.append(Violation(rel.as_posix(), n, "line-number-type",
                                     f"'{m.group(0)}' names a line-numbered asn1c type; deduce it"))
    return out


def self_test() -> int:
    clean = {
        "src/codec/asn1/ngap/ok.cpp":
            "using IeT = std::remove_pointer_t<decltype(m->protocolIEs.list.array[0])>;\n",
        "third_party/asn1c/gen/x.h": "typedef struct ProtocolIE_Container_123P4 {} T;\n",
    }
    dirty = {
        "src/codec/asn1/ngap/bad.cpp": "\n\nProtocolExtensionContainer_6155P12_t* ext = nullptr;\n",
    }
    expect = [("src/codec/asn1/ngap/bad.cpp", "line-number-type")]
    return run_self_test("linenum-types", check, clean, dirty, expect)


if __name__ == "__main__":
    main("linenum-types", check, self_test)
