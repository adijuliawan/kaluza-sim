#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Derive spec/asn1/constructs.tsv: how often each ASN.1 construct that stresses
a PER codec occurs in each extracted protocol (plan M5).

The table is the checklist for M10: every row with a non-zero count must name
how the codec handles it and at least one test vector that exercises it. The
counts are derived from the extracted text, never typed by hand.
    spec/tools/asn1_constructs.py           write spec/asn1/constructs.tsv
    spec/tools/asn1_constructs.py --check   fail if the committed table is stale
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROTOS = ["rrc", "ngap", "f1ap", "e1ap", "xnap"]
OUT = ROOT / "spec" / "asn1" / "constructs.tsv"
U32_MAX = 2**32 - 1
FRAGMENT_AT = 16384  # X.691 §11.9: lengths of 16K and more are fragmented

NUM = r"(-?\d+|[A-Za-z][\w-]*)"


def strip_comments(text: str) -> str:
    out = []
    for ln in text.split("\n"):
        # ASN.1 comments run from "--" to end of line or to the next "--".
        out.append(re.sub(r"--.*?(--|$)", " ", ln))
    return "\n".join(out)


def load(proto: str) -> str:
    return "\n".join(strip_comments(p.read_text())
                     for p in sorted((ROOT / "spec" / "asn1" / proto).glob("*.asn")))


def constants(text: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"^\s*([a-z][\w-]*)\s+INTEGER\s*::=\s*(-?\d+)", text, re.M)}


def value(tok: str, consts: dict[str, int]) -> int | None:
    if re.fullmatch(r"-?\d+", tok):
        return int(tok)
    return consts.get(tok)


def ranges(text: str, consts: dict[str, int], head: str):
    """(lo, hi, extensible) for every '<head> (lo..hi[, ...])'."""
    for m in re.finditer(head + r"\s*\(\s*" + NUM + r"\s*\.\.\s*" + NUM + r"\s*(,\s*\.\.\.)?\s*\)",
                         text):
        yield value(m.group(1), consts), value(m.group(2), consts), bool(m.group(3))


def size_bounds(text: str, consts: dict[str, int], head: str):
    """(lo, hi, extensible) for '<head> (SIZE (lo..hi[, ...]))' and fixed SIZE(n)."""
    pat = head + r"\s*\(\s*SIZE\s*\(\s*" + NUM + r"(?:\s*\.\.\s*" + NUM + r")?\s*(,\s*\.\.\.)?\s*\)\s*\)"
    for m in re.finditer(pat, text):
        lo = value(m.group(1), consts)
        hi = value(m.group(2), consts) if m.group(2) else lo
        yield lo, hi, bool(m.group(3))


def count(proto: str) -> dict[str, int]:
    t = load(proto)
    c = constants(t)
    ints = list(ranges(t, c, r"\bINTEGER"))
    sizes_any = [b for h in (r"OCTET STRING", r"BIT STRING", r"SEQUENCE", r"PrintableString",
                             r"VisibleString", r"UTF8String", r"IA5String")
                 for b in size_bounds(t, c, h)]
    seqof = [b for b in re.finditer(r"SEQUENCE\s*\(\s*SIZE\s*\(\s*" + NUM + r"\s*\.\.\s*" + NUM, t)]
    seqof_hi = [value(m.group(2), c) for m in seqof]
    return {
        "type-assignments": len(re.findall(r"^\s*[A-Z][\w-]*\s*(\{[^}]*\})?\s*::=", t, re.M)),
        "parameterized-types": len(re.findall(r"^\s*[A-Z][\w-]*\s*\{[^}]*\}\s*::=", t, re.M)),
        "information-object-classes": len(re.findall(r"::=\s*CLASS\b", t)),
        "information-object-sets": len(re.findall(r"^\s*[A-Za-z][\w-]*\s+[A-Z][A-Z0-9-]+\s*::=\s*\{",
                                                  t, re.M)),
        "open-type-fields": len(re.findall(r"\.&[A-Z][\w]*", t)),
        "extension-markers": len(re.findall(r"\.\.\.", t)) - len(re.findall(r"\.\.\.\s*\)", t)),
        "extension-addition-groups": len(re.findall(r"\[\[", t)),
        "choice": len(re.findall(r"\bCHOICE\b", t)),
        "enumerated": len(re.findall(r"\bENUMERATED\b", t)),
        "optional": len(re.findall(r"\bOPTIONAL\b", t)),
        "default": len(re.findall(r"\bDEFAULT\b", t)),
        "containing": len(re.findall(r"\bCONTAINING\b", t)),
        "integer-constrained": len(ints),
        "integer-extensible": sum(1 for lo, hi, ext in ints if ext),
        "integer-negative-lower-bound": sum(1 for lo, hi, ext in ints if lo is not None and lo < 0),
        "integer-range-over-2^32": sum(1 for lo, hi, ext in ints
                                       if lo is not None and hi is not None and hi - lo > U32_MAX),
        "integer-unresolved-bound": sum(1 for lo, hi, ext in ints if lo is None or hi is None),
        "size-constrained": len(sizes_any),
        "size-extensible": sum(1 for lo, hi, ext in sizes_any if ext),
        "size-upper-16K-or-more": sum(1 for lo, hi, ext in sizes_any if hi is not None and hi >= FRAGMENT_AT),
        "octet-string-unbounded": len(re.findall(r"OCTET STRING(?!\s*\(\s*SIZE)(?!\s*\(\s*CONTAINING)", t)),
        "bit-string-unbounded": len(re.findall(r"BIT STRING(?!\s*\(\s*SIZE)(?!\s*\{)", t)),
        "sequence-of-upper-16K-or-more": sum(1 for h in seqof_hi if h is not None and h >= FRAGMENT_AT),
        "printable-string": len(re.findall(r"\bPrintableString\b", t)),
        "visible-string": len(re.findall(r"\bVisibleString\b", t)),
        "utf8-string": len(re.findall(r"\bUTF8String\b", t)),
        "ia5-string": len(re.findall(r"\bIA5String\b", t)),
        "boolean": len(re.findall(r"\bBOOLEAN\b", t)),
        "null": len(re.findall(r"\bNULL\b", t)),
        "real": len(re.findall(r"\bREAL\b", t)),
        "object-identifier": len(re.findall(r"\bOBJECT IDENTIFIER\b", t)),
    }


DESCRIPTIONS = {
    "type-assignments": "type assignments (scale)",
    "parameterized-types": "parameterized type definitions (asn1c specializes each use)",
    "information-object-classes": "information object classes (CLASS)",
    "information-object-sets": "information object sets (IE / procedure tables)",
    "open-type-fields": "references to class type fields (open types: &Value, &InitiatingMessage)",
    "extension-markers": "extension markers ... in SEQUENCE/CHOICE/ENUMERATED",
    "extension-addition-groups": "extension addition groups [[ ]] (Rel-16+ CHOICE brackets)",
    "choice": "CHOICE types",
    "enumerated": "ENUMERATED types",
    "optional": "OPTIONAL components (presence bitmap)",
    "default": "DEFAULT components (encoder must omit default values in canonical PER)",
    "containing": "CONTAINING (an octet/bit string carrying another PDU)",
    "integer-constrained": "constrained INTEGER ranges",
    "integer-extensible": "extensible INTEGER ranges (...) (the SRBID-width class)",
    "integer-negative-lower-bound": "INTEGER ranges with a negative lower bound",
    "integer-range-over-2^32": "INTEGER ranges wider than 2^32 (e.g. BitRate)",
    "integer-unresolved-bound": "INTEGER bounds naming a value this tool did not resolve",
    "size-constrained": "SIZE-constrained strings and SEQUENCE OF",
    "size-extensible": "extensible SIZE constraints",
    "size-upper-16K-or-more": "SIZE upper bound of 16K or more (PER fragmentation)",
    "octet-string-unbounded": "OCTET STRING without SIZE (length may reach 16K: fragmentation)",
    "bit-string-unbounded": "BIT STRING without SIZE",
    "sequence-of-upper-16K-or-more": "SEQUENCE OF with an upper bound of 16K or more",
    "printable-string": "PrintableString (APER character width)",
    "visible-string": "VisibleString",
    "utf8-string": "UTF8String",
    "ia5-string": "IA5String",
    "boolean": "BOOLEAN",
    "null": "NULL",
    "real": "REAL (asn1c PER support is limited)",
    "object-identifier": "OBJECT IDENTIFIER",
}


def table() -> str:
    counts = {p: count(p) for p in PROTOS}
    buf = io.StringIO()
    w = csv.writer(buf, delimiter="\t", lineterminator="\n")
    w.writerow(["construct", *PROTOS, "description", "handling", "vector"])
    for k in DESCRIPTIONS:
        w.writerow([k, *(counts[p][k] for p in PROTOS), DESCRIPTIONS[k], "-", "-"])
    return buf.getvalue()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    fresh = table()
    if args.check:
        old = OUT.read_text() if OUT.is_file() else ""
        # M10 fills the handling/vector columns; only the counts must stay derived.
        strip = lambda s: "\n".join("\t".join(r.split("\t")[:6]) for r in s.splitlines())  # noqa: E731
        if strip(old) != strip(fresh):
            print("CONSTRUCTS=STALE (run spec/tools/asn1_constructs.py)")
            sys.exit(1)
        print("CONSTRUCTS=CURRENT")
        return
    OUT.write_text(fresh)
    print(fresh, end="")


if __name__ == "__main__":
    main()
