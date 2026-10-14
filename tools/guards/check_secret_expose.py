#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: SecretBytes::expose()/expose_mut() appear only in allowlisted files.

The allowlist is tools/guards/secret_expose_allowlist.txt (globs). Everything
else must keep keys inside SecretBytes (requirements.md §3.6).
"""

from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, read_text, repo_files, run_self_test, under  # noqa: E402

CALL = re.compile(r"\bexpose(_mut)?\s*\(")
CODE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".ipp"}
SCANNED = ("src", "apps", "tests")
ALLOWLIST = Path("tools/guards/secret_expose_allowlist.txt")


def load_allowlist(root: Path) -> list[str]:
    path = root / ALLOWLIST
    if not path.is_file():
        return []
    globs = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            globs.append(line)
    return globs


def allowed(rel: str, globs: list[str]) -> bool:
    for g in globs:
        if g.endswith("/**"):
            if rel.startswith(g[:-2]):
                return True
        elif fnmatch.fnmatchcase(rel, g):
            return True
    return False


def check(root: Path) -> list[Violation]:
    globs = load_allowlist(root)
    out: list[Violation] = []
    for rel in repo_files(root):
        if rel.suffix not in CODE_SUFFIXES or not under(rel, *SCANNED):
            continue
        rp = rel.as_posix()
        if allowed(rp, globs):
            continue
        for n, line in enumerate(read_text(root, rel).splitlines(), start=1):
            code = line.split("//", 1)[0]
            if CALL.search(code):
                out.append(Violation(rp, n, "secret-expose",
                                     "expose() outside the allowlist "
                                     "(tools/guards/secret_expose_allowlist.txt)"))
    return out


HDR = "// SPDX-FileCopyrightText: 2026 T\n// SPDX-License-Identifier: LicenseRef-x\n"


def self_test() -> int:
    clean = {
        str(ALLOWLIST): "src/crypto/**   # crypto\nsrc/platform/secret.cpp\n",
        "src/crypto/milenage.cpp": HDR + "auto k = key.expose();\n",
        "src/platform/secret.cpp": HDR + "return copy_of(expose());\n",
        "src/proc/ue/ok.cpp": HDR + "// key.expose() is not allowed here, but this is a comment\n",
    }
    dirty = {
        "src/proc/ue/nas_sec.cpp": HDR + "log(k.expose());\n",
        "src/codec/x.cpp": HDR + "auto m = s.expose_mut ();\n",
    }
    expect = [("src/proc/ue/nas_sec.cpp", "secret-expose"), ("src/codec/x.cpp", "secret-expose")]
    return run_self_test("secret-expose", check, clean, dirty, expect)


if __name__ == "__main__":
    main("secret-expose", check, self_test)
