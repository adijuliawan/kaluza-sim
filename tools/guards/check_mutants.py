#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: the sim's mutants and their register agree (P1 N1, ADR 0009 point 6;
verification.md §1, "every scenario row has a sim mutant").

A mutant is a switch, `KSIM_MUTANT("name")` in src/ or apps/, compiled in only
in the `mutants` preset, that makes the sim misbehave the way one scenario row
exists to catch. tests/mutants.tsv lists each with that row and a description.
This guard requires:

- each name used in the code is registered, and each registered name is used;
- names are lower-case identifiers, registered once;
- the row a mutant targets exists in a phase's row set, gates/rows/p1.tsv or
  gates/rows/p2.tsv ('-' for a mutant that only a procedure test kills);
- KSIM_MUTANT is always given a literal.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, read_text, repo_files, run_self_test, under  # noqa: E402

REGISTRY = Path("tests/mutants.tsv")
ROWS = (Path("gates/rows/p1.tsv"), Path("gates/rows/p2.tsv"))
CODE_SUFFIXES = {".cpp", ".hpp", ".h", ".cc", ".ipp"}
SCANNED = ("src", "apps")
EXEMPT = ("src/platform/mutation.hpp", "src/platform/mutation.cpp")
NAME = re.compile(r"^[a-z][a-z0-9_]*$")
USE_LITERAL = re.compile(r"\bKSIM_MUTANT\s*\(\s*\"([^\"\\]*)\"\s*\)")
USE_ANY = re.compile(r"\bKSIM_MUTANT\s*\(\s*([^\s)])")


def row_ids(root: Path) -> set[str]:
    out: set[str] = set()
    for rel in ROWS:
        path = root / rel
        if path.is_file():
            out |= {ln.split("\t", 1)[0] for ln in path.read_text().splitlines() if ln and not ln.startswith("#")}
    return out


def check(root: Path) -> list[Violation]:
    out: list[Violation] = []
    rows = row_ids(root)
    registered: dict[str, int] = {}
    path = root / REGISTRY
    if path.is_file():
        for n, line in enumerate(path.read_text().splitlines(), start=1):
            if not line.strip() or line.startswith("#"):
                continue
            cols = line.split("\t")
            if cols[0] == "name":
                continue
            name = cols[0]
            if len(cols) < 3 or not cols[2].strip():
                out.append(Violation(REGISTRY.as_posix(), n, "mutant-registry",
                                     f"'{name}' needs a row (or '-') and a description"))
            elif cols[1] != "-" and cols[1] not in rows:
                out.append(Violation(REGISTRY.as_posix(), n, "mutant-row",
                                     f"'{name}' targets row '{cols[1]}', which is in no row set ({', '.join(r.as_posix() for r in ROWS)})"))
            if not NAME.match(name):
                out.append(Violation(REGISTRY.as_posix(), n, "mutant-name", f"'{name}' is not a lower-case identifier"))
            if name in registered:
                out.append(Violation(REGISTRY.as_posix(), n, "mutant-registry", f"'{name}' is registered twice"))
            registered[name] = n
    used: set[str] = set()
    for rel in repo_files(root):
        if rel.suffix not in CODE_SUFFIXES or not under(rel, *SCANNED) or under(rel, *EXEMPT):
            continue
        for n, line in enumerate(read_text(root, rel).splitlines(), start=1):
            code = line.split("//", 1)[0]
            for m in USE_LITERAL.finditer(code):
                used.add(m.group(1))
                if m.group(1) not in registered:
                    out.append(Violation(rel.as_posix(), n, "mutant-unregistered",
                                         f"'{m.group(1)}' is used but not in {REGISTRY.as_posix()}"))
            for m in USE_ANY.finditer(code):
                if m.group(1) != '"':
                    out.append(Violation(rel.as_posix(), n, "mutant-literal", "KSIM_MUTANT takes a string literal"))
    for name, line in sorted(registered.items()):
        if name not in used:
            out.append(Violation(REGISTRY.as_posix(), line, "mutant-unused", f"'{name}' is registered but never used"))
    return out


def self_test() -> int:
    rows = "# the P1 row set\nid\tgate\nksim-p1.reg-null-suci\tkaluza-sim\n"
    reg = "name\trow\tdescription\nnull_suci_full_imsi\tksim-p1.reg-null-suci\tthe whole IMSI in a null SUCI\n"
    clean = {
        "gates/rows/p1.tsv": rows,
        "tests/mutants.tsv": reg,
        "src/proc/ue/nas_mm/suci.cpp": 'if (KSIM_MUTANT("null_suci_full_imsi")) { out = imsi; }\n',
    }
    dirty = {
        "gates/rows/p1.tsv": rows,
        "tests/mutants.tsv": reg + "ghost\tno.such.row\tnever used, wrong row\n",
        "src/proc/ue/nas_mm/suci.cpp": 'if (KSIM_MUTANT("null_suci_full_imsi")) { out = imsi; }\n'
                                       'if (KSIM_MUTANT("unlisted")) {}\nif (KSIM_MUTANT(kName)) {}\n',
    }
    expect = [("src/proc/ue/nas_mm/suci.cpp", "mutant-unregistered"),
              ("src/proc/ue/nas_mm/suci.cpp", "mutant-literal"),
              ("tests/mutants.tsv", "mutant-row"),
              ("tests/mutants.tsv", "mutant-unused")]
    return run_self_test("mutants", check, clean, dirty, expect)


if __name__ == "__main__":
    main("mutants", check, self_test)
