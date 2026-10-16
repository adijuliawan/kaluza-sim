#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The compliance registers (plan M15, verification.md §5): one per area under
docs/compliance/<area>/README.md, and docs/compliance/deviations.md.

    tools/registers.py              write them
    tools/registers.py --check      they are current (guard check_registers)
    tools/registers.py --self-test  its must-fail cases

Each register has a header (what it is, the specs it reads, the row legend), a
coverage table derived from committed data (the spec-derived tables, the v1
PDU list, the corpus indexes, the KAT index), never typed by hand, the
requirements built so far (docs/compliance/built.tsv names them, with the
evidence that verifies them against running code), the typed rows of
docs/compliance/rows.tsv, and a count of the requirements not built yet.
Nothing in a register depends on the commit or the machine, so it regenerates
identically.
"""

from __future__ import annotations

import csv
import io
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / "docs" / "compliance"

# area -> (title, requirement prefixes, specs it reads)
AREAS = {
    "nas": ("5GS NAS (5GMM and 5GSM)", ["MM", "SM"], ["24.501", "24.007", "24.008"]),
    "sms": ("SMS over NAS", ["SMS"], ["24.011", "23.040", "23.038"]),
    "uicc": ("UICC, USIM and the card interface", ["UICC"], ["102.221", "31.101", "31.102"]),
    "sec": ("Security: key hierarchy and algorithms", ["SEC"], ["33.501", "35.206", "35.208", "35.231", "33.220"]),
    "rrc": ("NR RRC (UE and CU)", ["RRCU", "RRCC"], ["38.331"]),
    "ngap": ("NGAP", ["NGAP"], ["38.413"]),
    "f1ap": ("F1AP", ["F1AP"], ["38.473"]),
    "e1ap": ("E1AP", ["E1AP"], ["37.483"]),
    "xnap": ("XnAP", ["XNAP"], ["38.423"]),
    "gtpu": ("GTP-U, the PDU Session Container and NR-U", ["GTPU"], ["29.281", "38.415", "38.425"]),
    "platform": ("Platform, tooling and guards", ["CTL", "SCN"], []),
}
LEGEND = ("Row suffixes (requirements.md): -D defect in the sim, -B a choice the spec leaves open, -G declared "
          "gap, -V deviation from a \"shall\", -S spec contradiction and the reading chosen, -M mutant, -T T0 "
          "reading or measurement, -F a kaluza-core defect the sim found, -X retired. Verification: U unit, KAT "
          "or oracle test; F fuzz or property test; I interop; L lab; G gate row; A real-device comparison.")


def tsv(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader((ln for ln in f if not ln.startswith("#")), delimiter="\t"))


def requirements() -> list[dict]:
    """The KS-<AREA>-nnn rows of requirements.md: id, text, clause, priority, verification."""
    out = []
    for line in (ROOT / "docs" / "requirements.md").read_text().splitlines():
        m = re.match(r"^\|\s*(KS-([A-Z0-9]+)-\d+)\s*\|(.*)\|\s*$", line)
        if not m:
            continue
        cells = [c.strip() for c in m.group(3).split(" | ")]
        if len(cells) == 4:
            text, clause, prio, ver = cells
        elif len(cells) == 3:
            text, prio, ver = cells
            clause = ""
        else:
            continue
        out.append({"id": m.group(1), "area": m.group(2), "text": text, "clause": clause, "priority": prio,
                    "verification": ver})
    return out


def spec_versions() -> dict[str, str]:
    out = {}
    for r in tsv(ROOT / "spec" / "INDEX.tsv"):
        doc = next(iter(r.values()))
        out[doc] = r.get("version", "")
    return out


def v1_types() -> Counter:
    return Counter(r["protocol"] for r in tsv(ROOT / "spec" / "v1-pdus.tsv"))


def corpus(proto: str) -> tuple[int, int]:
    """(committed vectors, PDU types they cover) for a protocol's index."""
    p = ROOT / "tests" / "vectors" / proto / "index.tsv"
    if not p.is_file():
        return 0, 0
    rows = tsv(p)
    return len(rows), len({r["pdu"] for r in rows if r["pdu"] and not r["pdu"].startswith("(")})


def local_corpus(proto: str) -> int:
    p = ROOT / "tests" / "vectors" / "local-manifest.tsv"
    return sum(1 for r in tsv(p) if r.get("proto") == proto) if p.is_file() else 0


def coverage(area: str) -> list[tuple[str, str]]:
    """Counts derived from committed data, never typed by hand."""
    v1 = v1_types()
    rows: list[tuple[str, str]] = []
    if area == "nas":
        msgs = tsv(ROOT / "spec" / "nas" / "24501" / "messages.tsv")
        ies = tsv(ROOT / "spec" / "nas" / "24501" / "message_ies.tsv")
        types = tsv(ROOT / "spec" / "nas" / "24501" / "ie_types.tsv")
        epco = tsv(ROOT / "spec" / "nas" / "24008" / "epco_containers.tsv")
        n, t = corpus("nas")
        rows += [("Message tables in TS 24.501 clause 8 (all decoded by the table-driven codec)", str(len(msgs))),
                 ("of them 5GMM / 5GSM", f"{sum(m['protocol'] == '5GMM' for m in msgs)} / "
                                          f"{sum(m['protocol'] == '5GSM' for m in msgs)}"),
                 ("v1 5GMM / 5GSM message types (spec/v1-pdus.tsv)", f"{v1['5gmm']} / {v1['5gsm']}"),
                 ("IE rows in the message tables / IE types", f"{len(ies)} / {len(types)}"),
                 ("ePCO container identifiers (TS 24.008 10.5.6.3), both directions", str(len(epco))),
                 ("5GMM / 5GSM causes", f"{len(tsv(ROOT / 'spec' / 'nas' / '24501' / 'causes_5gmm.tsv'))} / "
                                        f"{len(tsv(ROOT / 'spec' / 'nas' / '24501' / 'causes_5gsm.tsv'))}"),
                 ("Committed corpus vectors (types)", f"{n} ({t})"),
                 ("Local-only corpus vectors (hash manifest)", str(local_corpus("nas")))]
    elif area == "sms":
        rows += [("CP / RP message types (TS 24.011)",
                  f"{len(tsv(ROOT / 'spec' / 'nas' / '24011' / 'cp_message_types.tsv'))} / "
                  f"{len(tsv(ROOT / 'spec' / 'nas' / '24011' / 'rp_message_types.tsv'))}"),
                 ("GSM 7-bit default alphabet and extension table rows (TS 23.038)",
                  str(len(tsv(ROOT / "spec" / "nas" / "23038" / "gsm7_alphabet.tsv")))),
                 ("v1 SMS types (CP, RP, TPDU)", str(v1["sms"])),
                 ("Local-only corpus vectors (hash manifest)", str(local_corpus("sms")))]
    elif area == "uicc":
        rows += [("v1 APDU commands", str(v1["apdu"]))]
    elif area == "sec":
        kat = sorted((ROOT / "spec" / "kat").glob("*.tsv"))
        total = 0
        for k in kat:
            n = len({r["set"] for r in tsv(k)})
            total += n
            rows.append((f"KAT test sets in spec/kat/{k.name}", str(n)))
        rows.append(("KAT test sets in all (each checked by tests/unit/crypto)", str(total)))
    elif area in ("rrc", "ngap", "f1ap", "e1ap", "xnap"):
        cons = [r for r in tsv(ROOT / "spec" / "asn1" / "constructs.tsv") if int(r.get(area) or 0) > 0]
        n, t = corpus(area)
        rows += [(f"v1 {area.upper()} types (spec/v1-pdus.tsv)", str(v1[area]))]
        rows += [(f"ASN.1 construct classes present in the {area.upper()} modules (spec/asn1/constructs.tsv)",
                  str(len(cons))),
                 ("of them with a recorded handling and vector",
                  str(sum(1 for r in cons if r.get("handling") and r.get("vector"))))]
        rows += [(f"{r['description']}", r[area]) for r in cons]
        rows += [("Committed corpus vectors (types)", f"{n} ({t})"),
                 ("Local-only corpus vectors (hash manifest)", str(local_corpus(area)))]
    elif area == "gtpu":
        for proto, what in (("gtpu", "GTP-U"), ("psc", "PDU Session Container"), ("nru", "NR-U")):
            n, t = corpus(proto)
            rows.append((f"v1 {what} types; committed corpus vectors (types)", f"{v1[proto]}; {n} ({t})"))
    elif area == "platform":
        guards = sorted(p.stem for p in (ROOT / "tools" / "guards").glob("check_*.py"))
        hooks = sorted(p.stem for p in (ROOT / "tools" / "ci.d").glob("*.sh"))
        rows += [("Guards (tools/guards), each with a must-fail self-test", f"{len(guards)}: {', '.join(guards)}"),
                 ("CI hooks (tools/ci.d)", f"{len(hooks)}: {', '.join(hooks)}"),
                 ("Unit test sources (tests/unit)", str(len(list((ROOT / "tests" / "unit").rglob("*_test.cpp"))))),
                 ("Fuzz targets (tests/fuzz)", str(len(list((ROOT / "tests" / "fuzz").glob("fuzz_*.cpp")))))]
    return rows


def esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def register(area: str, reqs: list[dict], rows: list[dict], built: dict[str, dict], versions: dict) -> str:
    title, prefixes, specs = AREAS[area]
    mine = [r for r in reqs if r["area"] in prefixes]
    out = io.StringIO()
    w = out.write
    w(f"<!-- Generated by tools/registers.py from docs/requirements.md, docs/compliance/rows.tsv, "
      f"docs/compliance/built.tsv and committed spec data. Do not edit. -->\n\n")
    w(f"# {title}: compliance register\n\n")
    w("What this is: the requirements of this area that are built and verified against running code, the typed "
      "rows recorded while building them, and coverage counts derived from the specs (verification.md §5). "
      "Requirements are in [`requirements.md`](../../requirements.md); deviations in "
      "[`deviations.md`](../deviations.md).\n\n")
    if specs:
        w("Specs read: " + ", ".join(f"TS {s} {versions.get(s, '(not fetched)')}" for s in specs) + ".\n\n")
    w(LEGEND + "\n\n")
    cov = coverage(area)
    w("## Coverage (derived)\n\n| What | Count |\n|---|---|\n")
    for what, n in cov:
        w(f"| {esc(what)} | {esc(n)} |\n")
    if not cov:
        w("| (no spec-derived table for this area yet) | |\n")
    built_here = [r for r in mine if r["id"] in built]
    w("\n## Requirements built\n\n")
    if built_here:
        w("| Row | What | Clause | Verified by | Status |\n|---|---|---|---|---|\n")
        for r in built_here:
            b = built[r["id"]]
            w(f"| {r['id']} | {esc(r['text'])} | {esc(r['clause'])} | {esc(b['evidence'])} | {esc(b['status'])} |\n")
    else:
        w("None yet.\n")
    typed = [r for r in rows if r["area"] == area]
    w("\n## Typed rows\n\n")
    if typed:
        w("| Row | Date | What | Evidence |\n|---|---|---|---|\n")
        for r in typed:
            w(f"| {r['id']} | {r['date']} | {esc(r['summary'])} | {esc(r['evidence'])} |\n")
    else:
        w("None yet.\n")
    rest = [r for r in mine if r["id"] not in built]
    w("\n## Not built yet\n\n")
    by_prio = Counter(re.sub(r"\s*\(.*\)", "", r["priority"]) for r in rest)
    if rest:
        w(", ".join(f"{n} {p}" for p, n in sorted(by_prio.items())) + " requirement(s): "
          + ", ".join(r["id"] for r in rest) + ".\n")
    else:
        w("None.\n")
    return out.getvalue()


def deviations(rows: list[dict]) -> str:
    v = [r for r in rows if r["kind"] == "V"]
    out = io.StringIO()
    out.write("<!-- Generated by tools/registers.py from docs/compliance/rows.tsv. Do not edit. -->\n\n")
    out.write("# Deviations\n\nThe -V rows of every register: places where the sim departs from a \"shall\". "
              "The ideal RLC/MAC is a declared abstraction (-G rows and abstraction-ledger.md), not a deviation.\n\n")
    if v:
        out.write("| Row | Area | Date | What | Evidence |\n|---|---|---|---|---|\n")
        for r in v:
            out.write(f"| {r['id']} | {r['area']} | {r['date']} | {esc(r['summary'])} | {esc(r['evidence'])} |\n")
    else:
        out.write("None.\n")
    return out.getvalue()


class RegisterError(Exception):
    pass


def documents(rows: list[dict] | None = None, built_rows: list[dict] | None = None) -> dict[Path, str]:
    reqs = requirements()
    rows = tsv(COMP / "rows.tsv") if rows is None else rows
    built = {r["id"]: r for r in (tsv(COMP / "built.tsv") if built_rows is None else built_rows)}
    known = {r["id"] for r in reqs}
    unknown = [b for b in built if b not in known]
    if unknown:
        raise RegisterError(f"built.tsv names requirements that do not exist: {unknown}")
    homeless = sorted({r["area"] for r in rows} - set(AREAS))
    if homeless:
        raise RegisterError(f"rows.tsv has rows of areas with no register: {homeless}")
    # P2 Q7: an ID is one row (KS-PLAT-D8 was given twice and the registers took both).
    ids = [r["id"] for r in rows]
    twice = sorted({i for i in ids if ids.count(i) > 1})
    if twice:
        raise RegisterError(f"rows.tsv gives these IDs to more than one row: {twice}")
    versions = spec_versions()
    docs = {COMP / area / "README.md": register(area, reqs, rows, built, versions) for area in AREAS}
    docs[COMP / "deviations.md"] = deviations(rows)
    return docs


def stale(docs: dict[Path, str], read) -> list[str]:
    return [p.relative_to(ROOT).as_posix() for p, text in docs.items() if read(p) != text]


def on_disk(p: Path) -> str | None:
    return p.read_text() if p.is_file() else None


def self_test() -> int:
    """Must-fail cases: a hand-edited register, a built requirement that does
    not exist, a row of an area with no register and an ID given to two rows
    are each caught."""
    docs = documents()
    results = []
    first = next(iter(docs))
    results.append(("a register edited by hand is stale",
                    stale(docs, lambda p: docs[p] + "edited\n" if p == first else docs[p]) == [
                        first.relative_to(ROOT).as_posix()]))
    results.append(("the generated registers compare equal to themselves", stale(docs, docs.get) == []))
    try:
        documents(built_rows=[{"id": "KS-MM-999", "status": "built", "evidence": "-"}])
        results.append(("an unknown requirement in built.tsv fails", False))
    except RegisterError:
        results.append(("an unknown requirement in built.tsv fails", True))
    try:
        documents(rows=tsv(COMP / "rows.tsv") + [{"id": "KS-ZZ-T1", "kind": "T", "area": "zz", "date": "",
                                                    "summary": "", "evidence": ""}])
        results.append(("a row of an area with no register fails", False))
    except RegisterError:
        results.append(("a row of an area with no register fails", True))
    try:
        first_row = tsv(COMP / "rows.tsv")[0]
        documents(rows=tsv(COMP / "rows.tsv") + [dict(first_row)])
        results.append(("an ID given to two rows fails", False))
    except RegisterError:
        results.append(("an ID given to two rows fails", True))
    for name, ok in results:
        print(f"REGISTERS_SELFTEST {'CAUGHT' if ok else 'MISSED'} {name}")
    ok = all(c for _, c in results)
    print(f"REGISTERS_SELFTEST={'PASS' if ok else 'FAIL'} cases={len(results)}")
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    check = "--check" in sys.argv[1:]
    try:
        docs = documents()
    except RegisterError as e:
        print(f"REGISTERS=FAIL {e}")
        return 1
    late = stale(docs, on_disk) if check else []
    if not check:
        for path, text in docs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    if check:
        for s in late:
            print(f"REGISTERS_STALE {s} (run tools/registers.py)")
        print(f"REGISTERS={'CURRENT' if not late else 'STALE'} documents={len(AREAS) + 1}")
        return 1 if late else 0
    print(f"REGISTERS=WRITTEN documents={len(AREAS) + 1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
