#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: every IE type of P1's NAS messages is accounted for (P1 N4; KS-NAS-G1).

src/codec/nas/ie/p1_ies.tsv names the P1 messages (a "# messages:" line) and
gives each IE type they use (by its TS 24.501 clause) a status:

- header: framed by the generic codec (nas.cpp);
- typed: the struct named in `cxx` exists in src/codec/nas/ie/ie.hpp;
- raw: its contents stay octets, and `reason` says why.

The guard checks the file against spec/nas/24501/message_ies.tsv (the
extracted message tables): no type is missing, none is listed that the
messages do not use, a typed row's struct exists, a raw row has a reason.
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, run_self_test  # noqa: E402

REGISTRY = Path("src/codec/nas/ie/p1_ies.tsv")
TABLES = Path("spec/nas/24501/message_ies.tsv")
HEADER = Path("src/codec/nas/ie/ie.hpp")


def check(root: Path) -> list[Violation]:
    out: list[Violation] = []
    reg = root / REGISTRY
    if not reg.is_file():
        return [Violation(REGISTRY.as_posix(), 0, "nas-ies", "the registry is missing")]
    lines = reg.read_text().splitlines()
    messages: list[str] = []
    for ln in lines:
        if ln.startswith("# messages:"):
            messages = ln.split(":", 1)[1].split()
    if not messages:
        out.append(Violation(REGISTRY.as_posix(), 0, "nas-ies", "no '# messages:' line"))
    used: dict[str, str] = {}
    with (root / TABLES).open() as f:
        for r in csv.DictReader((ln for ln in f if not ln.startswith("#")), delimiter="\t"):
            if r["key"] in messages:
                used.setdefault(r["reference"], r["type_name"])
    header = (root / HEADER).read_text() if (root / HEADER).is_file() else ""
    seen: set[str] = set()
    for n, ln in enumerate(lines, start=1):
        if not ln.strip() or ln.startswith("#") or ln.startswith("reference\t"):
            continue
        cols = ln.split("\t")
        if len(cols) != 5:
            out.append(Violation(REGISTRY.as_posix(), n, "nas-ies", "five columns: reference type_name status cxx reason"))
            continue
        ref, _name, status, cxx, reason = cols
        if ref in seen:
            out.append(Violation(REGISTRY.as_posix(), n, "nas-ies", f"{ref} is listed twice"))
        seen.add(ref)
        if ref not in used:
            out.append(Violation(REGISTRY.as_posix(), n, "nas-ies-stale", f"{ref} is not used by the P1 messages"))
        if status == "typed":
            if not re.search(r"\bstruct\s+" + re.escape(cxx) + r"\s*\{", header):
                out.append(Violation(REGISTRY.as_posix(), n, "nas-ies-typed", f"{ref}: no struct {cxx} in {HEADER.as_posix()}"))
        elif status in ("raw", "header"):
            if not reason.strip() or reason.strip() in ("-", "None"):
                out.append(Violation(REGISTRY.as_posix(), n, "nas-ies-raw", f"{ref}: a raw type needs its reason"))
        else:
            out.append(Violation(REGISTRY.as_posix(), n, "nas-ies", f"{ref}: status is header, typed or raw"))
    for ref in sorted(set(used) - seen):
        out.append(Violation(REGISTRY.as_posix(), 0, "nas-ies-missing", f"{ref} ({used[ref]}) is used by a P1 message but not listed"))
    return out


def self_test() -> int:
    tables = ("# t\nkey\tmessage\tseq\tiei\tie_name\ttype_name\treference\tpresence\tformat\tlength\n"
              "8.2.1\tAUTHENTICATION REQUEST\t1\t\tExtended protocol discriminator\tExtended protocol discriminator\t9.2\tM\tV\t1\n"
              "8.2.1\tAUTHENTICATION REQUEST\t5\t21\tAuthentication parameter RAND\tAuthentication parameter RAND\t9.11.3.16\tO\tTV\t17\n"
              "8.2.1\tAUTHENTICATION REQUEST\t6\t20\tAuthentication parameter AUTN\tAuthentication parameter AUTN\t9.11.3.15\tO\tTLV\t18\n")
    header = "struct Rand {\n};\nstruct Autn {\n};\n"
    reg = ("# messages: 8.2.1\nreference\ttype_name\tstatus\tcxx\treason\n"
           "9.2\tExtended protocol discriminator\theader\t-\tframed\n"
           "9.11.3.16\tAuthentication parameter RAND\ttyped\tRand\t-\n"
           "9.11.3.15\tAuthentication parameter AUTN\ttyped\tAutn\t-\n")
    clean = {"spec/nas/24501/message_ies.tsv": tables, "src/codec/nas/ie/ie.hpp": header, "src/codec/nas/ie/p1_ies.tsv": reg}
    bad = ("# messages: 8.2.1\nreference\ttype_name\tstatus\tcxx\treason\n"
           "9.2\tExtended protocol discriminator\theader\t-\tframed\n"
           "9.11.3.16\tAuthentication parameter RAND\ttyped\tRandom\t-\n"
           "9.11.3.99\tSomething else\traw\t-\t\n")
    dirty = {"spec/nas/24501/message_ies.tsv": tables, "src/codec/nas/ie/ie.hpp": header, "src/codec/nas/ie/p1_ies.tsv": bad}
    expect = [("src/codec/nas/ie/p1_ies.tsv", "nas-ies-typed"), ("src/codec/nas/ie/p1_ies.tsv", "nas-ies-stale"),
              ("src/codec/nas/ie/p1_ies.tsv", "nas-ies-raw"), ("src/codec/nas/ie/p1_ies.tsv", "nas-ies-missing")]
    return run_self_test("nas-ies", check, clean, dirty, expect)


if __name__ == "__main__":
    main("nas-ies", check, self_test)
