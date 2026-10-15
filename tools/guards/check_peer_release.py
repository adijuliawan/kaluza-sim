#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: every protocol IE and procedure our F1AP, E1AP and NGAP builders use
exists in Rel-18, the release of our interop peer (ADR 0012, P2 Q4).

OCUDU d9d2263f4d decodes F1AP v18.8.0, E1AP v18.5.0 and NGAP v18.8.0. An IE
it does not know, sent with criticality reject, fails the whole message, so a
builder that starts using a Rel-19 IE must leave it out towards a Rel-18 peer
(the topology's peer_release) and be listed in ALLOWED with how. The 3GPP
constants allocate IDs in increasing order, so a constant above the highest
Rel-18 ID is Rel-19. The maxima were read from OCUDU's ASN.1 ID tables
(include/ocudu/asn1/<p>/common.h) on 2026-10-16; no OCUDU tree is needed here.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, read_text, run_self_test  # noqa: E402

REL18_MAX = {"f1ap": 919, "e1ap": 219, "ngap": 443}
# "<protocol>:<constant>": how a Rel-18 peer is spared it. Empty in P2 Q4.
ALLOWED: dict[str, str] = {}
CONSTANT = re.compile(r"constexpr int (k\w+) = ([0-9]+);")


def check(root: Path) -> list[Violation]:
    out: list[Violation] = []
    for proto, top in REL18_MAX.items():
        rel = Path("src/codec/asn1/msg") / f"{proto}.cpp"
        if not (root / rel).is_file():
            out.append(Violation(rel.as_posix(), 0, "missing", "the builder file is gone; update the guard"))
            continue
        for n, line in enumerate(read_text(root, rel).splitlines(), start=1):
            m = CONSTANT.search(line)
            if m and int(m.group(2)) > top and f"{proto}:{m.group(1)}" not in ALLOWED:
                out.append(Violation(rel.as_posix(), n, "rel19-ie",
                                     f"{m.group(1)} = {m.group(2)} is above Rel-18's {top}: leave it out "
                                     "towards a Rel-18 peer and list it in ALLOWED"))
    return out


def self_test() -> int:
    base = {
        "src/codec/asn1/msg/f1ap.cpp": "constexpr int kDlPdcpSnLength = 161;\n",
        "src/codec/asn1/msg/e1ap.cpp": "constexpr int kUeInactivityTimer = 59;\n",
        "src/codec/asn1/msg/ngap.cpp": "constexpr int kRanUeNgapId = 85;\n",
    }
    dirty = {"src/codec/asn1/msg/e1ap.cpp": "constexpr int kUeInactivityTimer = 59;\nconstexpr int kNewRel19 = 230;\n"}
    expect = [("src/codec/asn1/msg/e1ap.cpp", "rel19-ie")]
    return run_self_test("peer-release", check, base, dirty, expect)


if __name__ == "__main__":
    main("peer-release", check, self_test)
