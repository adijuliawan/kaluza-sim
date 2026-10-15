#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: the phases' row sets agree (P2 Q0; verification.md §3.2, ADR 0011).

gates/rows/p2.tsv carries every P1 row (p1.tsv, p1=yes) for scoring per mode.
The row text is kaluza-core's, verbatim: the UE_IMPL parity contract. This
guard requires:

- every P1 row with p1=yes is in p2.tsv, with the same gate, number and text;
- p2.tsv has no other row outside kaluza-sim's own ksim-p2.* names;
- row ids are unique;
- each row's modes are from aio, split, C3, C4, C5 (or '-'), and its cores
  from stub, open5gs, kaluza, uesim, card (open5gs=allow after a ';').
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, run_self_test  # noqa: E402

P1 = Path("gates/rows/p1.tsv")
P2 = Path("gates/rows/p2.tsv")
MODES = {"aio", "split", "C3", "C4", "C5"}
CORES = {"stub", "open5gs", "kaluza", "uesim", "card"}


def rows(root: Path, rel: Path) -> tuple[list[str], list[tuple[int, dict[str, str]]]]:
    path = root / rel
    if not path.is_file():
        return [], []
    head: list[str] = []
    out: list[tuple[int, dict[str, str]]] = []
    for n, line in enumerate(path.read_text().splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if not head:
            head = cols
            continue
        out.append((n, dict(zip(head, cols))))
    return head, out


def check(root: Path) -> list[Violation]:
    out: list[Violation] = []
    _, p1 = rows(root, P1)
    head, p2 = rows(root, P2)
    if not head:
        return out
    for col in ("id", "gate", "n", "text", "cores", "modes"):
        if col not in head:
            out.append(Violation(P2.as_posix(), 1, "rows-columns", f"no column '{col}'"))
    if out:
        return out
    seen: dict[str, int] = {}
    by_id: dict[str, tuple[int, dict[str, str]]] = {}
    for n, r in p2:
        if r["id"] in seen:
            out.append(Violation(P2.as_posix(), n, "rows-duplicate", f"'{r['id']}' also on line {seen[r['id']]}"))
        seen[r["id"]] = n
        by_id[r["id"]] = (n, r)
        modes = r.get("modes", "")
        if modes != "-" and not set(modes.split(",")) <= MODES:
            out.append(Violation(P2.as_posix(), n, "rows-modes", f"'{r['id']}' has modes '{modes}'"))
        cores = r.get("cores", "").split(";", 1)[0]
        if not set(cores.split(",")) <= CORES:
            out.append(Violation(P2.as_posix(), n, "rows-cores", f"'{r['id']}' has cores '{r.get('cores')}'"))
    wanted = {r["id"]: r for _, r in p1 if r.get("p1") == "yes"}
    for rid, r in wanted.items():
        if rid not in by_id:
            out.append(Violation(P2.as_posix(), 1, "rows-p1-missing", f"P1 row '{rid}' is not carried"))
            continue
        n, q = by_id[rid]
        for col in ("gate", "n", "text"):
            if q.get(col) != r.get(col):
                out.append(Violation(P2.as_posix(), n, "rows-p1-text",
                                     f"'{rid}' {col} differs from {P1.as_posix()} (the parity contract)"))
    for rid, (n, _) in by_id.items():
        if rid not in wanted and not rid.startswith("ksim-p2."):
            out.append(Violation(P2.as_posix(), n, "rows-foreign", f"'{rid}' is neither a P1 row nor ksim-p2.*"))
    return out


def self_test() -> int:
    p1 = ("id\tgate\tn\ttext\tp1\n"
          "amf-ueransim.006\tkaluza-amf-ueransim\t6\tthe UE completed Initial Registration\tyes\n"
          "amf-ueransim.007\tkaluza-amf-ueransim\t7\tthe AUSF ran exactly one authentication\tno:core\n")
    head = "id\tgate\tn\ttext\tcores\tmodes\n"
    good = ("amf-ueransim.006\tkaluza-amf-ueransim\t6\tthe UE completed Initial Registration\tstub,kaluza\taio,split\n"
            "ksim-p2.f1-setup-sctp\tkaluza-sim\t-\tthe DU completed F1 Setup\tstub\tsplit,C3\n")
    clean = {"gates/rows/p1.tsv": p1, "gates/rows/p2.tsv": head + good}
    dirty = {"gates/rows/p1.tsv": p1 + "ksim-p1.imeisv\tkaluza-sim\t-\tthe UE returned its IMEISV\tyes\n",
             "gates/rows/p2.tsv": head + good.replace("Initial Registration", "Initial registration")
             + "other.001\tx\t1\tforeign\tstub\tsplit\n"
             + "ksim-p2.f1-setup-sctp\tkaluza-sim\t-\ttwice\tstub\tC9\n"}
    expect = [("gates/rows/p2.tsv", "rows-p1-missing"), ("gates/rows/p2.tsv", "rows-p1-text"),
              ("gates/rows/p2.tsv", "rows-foreign"), ("gates/rows/p2.tsv", "rows-duplicate"),
              ("gates/rows/p2.tsv", "rows-modes")]
    return run_self_test("rows", check, clean, dirty, expect)


if __name__ == "__main__":
    main("rows", check, self_test)
