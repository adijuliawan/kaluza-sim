#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: every hand-written source file starts with SPDX lines (ADR 0004).

Files that cannot carry a header (Markdown, JSON, TSV, extracted ASN.1) are
covered by REUSE.toml and checked by `reuse lint`. Third-party trees keep their
own headers and are covered by their REUSE annotations.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, read_text, repo_files, run_self_test, under  # noqa: E402

SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".ipp", ".py", ".sh", ".cmake", ".lua"}
SOURCE_NAMES = {"CMakeLists.txt"}
EXEMPT = ("third_party", "tests/vectors", "spec/asn1", "spec/nas", "spec/kat", "LICENSES")
HEAD_LINES = 12


def is_source(p: Path) -> bool:
    return p.suffix in SOURCE_SUFFIXES or p.name in SOURCE_NAMES or p.name.endswith(".hpp.in")


def check(root: Path) -> list[Violation]:
    out: list[Violation] = []
    for rel in repo_files(root):
        if not is_source(rel) or under(rel, *EXEMPT):
            continue
        head = read_text(root, rel).splitlines()[:HEAD_LINES]
        text = "\n".join(head)
        if "SPDX-License-Identifier:" not in text:
            out.append(Violation(rel.as_posix(), 1, "spdx-license",
                                 f"no SPDX-License-Identifier in the first {HEAD_LINES} lines"))
        if "SPDX-FileCopyrightText:" not in text:
            out.append(Violation(rel.as_posix(), 1, "spdx-copyright",
                                 f"no SPDX-FileCopyrightText in the first {HEAD_LINES} lines"))
    return out


HDR = "// SPDX-FileCopyrightText: 2026 T\n// SPDX-License-Identifier: LicenseRef-x\n"


def self_test() -> int:
    clean = {
        "src/platform/ok.cpp": HDR + "int f() { return 0; }\n",
        "tools/ok.py": "#!/usr/bin/env python3\n# SPDX-FileCopyrightText: 2026 T\n"
                       "# SPDX-License-Identifier: LicenseRef-x\n",
        "docs/readme.md": "no header needed\n",
        "third_party/x/y.c": "/* upstream file, REUSE-annotated */\n",
    }
    dirty = {
        "src/codec/bad.cpp": "int g() { return 1; }\n",
        "tools/half.sh": "#!/bin/sh\n# SPDX-License-Identifier: LicenseRef-x\n",
    }
    expect = [("src/codec/bad.cpp", "spdx-license"), ("src/codec/bad.cpp", "spdx-copyright"),
              ("tools/half.sh", "spdx-copyright")]
    return run_self_test("spdx", check, clean, dirty, expect)


if __name__ == "__main__":
    main("spdx", check, self_test)
