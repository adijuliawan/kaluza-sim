#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Derive spec/v1-pdus.tsv: every PDU type v1 must encode and decode (plan M7).

It is the denominator of P0's exit criterion ("every v1 PDU type round-trips and
matches tshark and pycrate"), so it is derived, never typed:

  1. read every v1 row of docs/requirements.md §2 (KS-*), with the spec clauses
     its "Spec" column cites (a bare "§" means the section's own spec);
  2. build each protocol's universe of PDU types from the extracted material:
       NGAP/F1AP/E1AP/XnAP  the elementary procedures in *-PDU-Descriptions.asn
                            (initiating, successful and unsuccessful messages)
       RRC                  the message CHOICE arms of NR-RRC-Definitions and the
                            top-level types of NR-InterNodeDefinitions
       NAS 5GMM/5GSM        spec/nas/24501/messages.tsv
       SMS CP/RP            spec/nas/24011/*.tsv; TPDUs from TS 23.040 §9.2.2
       GTP-U                TS 29.281 Table 6.1-1 (the GTP-U rows)
       PSC, NR-U            the PDU type clauses of 38.415 and 38.425
       APDU                 ETSI TS 102 221 Table 10.5 (commands)
  3. a PDU type is v1 when a v1 row names it in its own text, or in the text of
     a clause the row cites specifically. A whole-document citation counts only
     for names in the row's own text.

    spec/tools/v1_pdus.py           write spec/v1-pdus.tsv
    spec/tools/v1_pdus.py --check   fail if the committed table is stale
"""

from __future__ import annotations

import argparse
import io
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docx_lib as dl  # noqa: E402

ROOT = dl.ROOT
OUT = ROOT / "spec" / "v1-pdus.tsv"
REQ = ROOT / "docs" / "requirements.md"

# The spec a bare "§" refers to, per requirements.md §2 section.
SECTION_DOC = {"2.1": "102.221", "2.2": "24.501", "2.3": "24.501", "2.4": "24.011", "2.5": "38.331",
               "2.6": "38.331", "2.7": "38.323", "2.9": "38.413", "2.10": "38.423", "2.11": "29.281"}
DOC_VERSION = {"38.413": "j40", "38.473": "j40", "37.483": "j40", "38.423": "j40", "38.331": "j40",
               "24.501": "j80", "24.011": "j00", "23.040": "j00", "29.281": "j20", "38.415": "j10",
               "38.425": "j10", "38.300": "j40", "38.304": "j30", "24.008": "j50", "24.007": "j50",
               "23.122": "j70", "33.501": "j70", "31.102": "j60"}
AP = {"38.413": "ngap", "38.473": "f1ap", "37.483": "e1ap", "38.423": "xnap"}


# ---- requirement rows ---------------------------------------------------------------

def v1_rows() -> list[dict]:
    rows, section = [], ""
    for line in REQ.read_text().splitlines():
        m = re.match(r"^### (2\.\d+) ", line)
        if m:
            section = m.group(1)
            continue
        if not line.startswith("| KS-"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        rid, text, spec, prio = cells[0], cells[1], cells[2], cells[3]
        if not re.match(r"^v1\b(?!\.x)", prio):
            continue
        rows.append({"id": rid, "text": text, "spec": spec, "section": section,
                     "citations": parse_citations(spec, SECTION_DOC.get(section, ""))})
    return rows


_DOC = re.compile(r"^(?:TS\s*)?(\d{2}\.\d{3}(?:-\d)?|102 221|RFC \d+)")


def parse_citations(spec: str, default_doc: str) -> list[tuple[str, str | None]]:
    """'38.331 §5.3.3; 33.501 A.8' -> [('38.331','5.3.3'), ('33.501','A.8')].
    A clause of None means the whole document."""
    out = []
    for group in spec.split(";"):
        g = re.sub(r"\((T0|T0 reading|semantics)[^)]*\)", "", group).strip()
        m = _DOC.match(g)
        doc = default_doc
        if m:
            doc = m.group(1).replace("102 221", "102.221")
            g = g[m.end():]
        clauses = re.findall(r"(?:§|Annex\s+)?((?:[A-Z]\.)?\d+(?:\.\d+)*[A-Z]?(?:\s*[–-]\s*(?:[A-Z]\.)?(?:\d+)?(?:\.\d+)*)?|(?<=Annex )[A-Z]\b)", g)
        clauses = [c for c in clauses if re.search(r"\d", c) and not re.fullmatch(r"j\d+", c)]
        if not clauses:
            if doc:
                out.append((doc, None))
            continue
        for c in clauses:
            for one in expand_range(c.replace(" ", "")):
                out.append((doc, one))
    return out


def expand_range(c: str) -> list[str]:
    m = re.match(r"^((?:[A-Z]\.)?[\d.]*?)(\d+)[–-](.+)$", c)
    if not m:
        return [c]
    prefix, lo, hi = m.group(1), int(m.group(2)), m.group(3)
    hi = re.sub(r"^[A-Z]\.", "", hi).lstrip(".")
    hi_last = int(hi.split(".")[-1]) if re.match(r"^[\d.]+$", hi) else lo
    if hi.count(".") >= 1 and not hi.startswith(prefix.rstrip(".")):
        return [prefix + str(lo)]
    return [f"{prefix}{n}" for n in range(lo, hi_last + 1)]


# ---- clause text from the documents -------------------------------------------------------

_clause_cache: dict[str, dict[str, str]] = {}


def clause_texts(doc: str) -> dict[str, str]:
    """clause number -> its own text plus the text of every sub-clause."""
    if doc in _clause_cache:
        return _clause_cache[doc]
    path, _ = dl.source(doc, DOC_VERSION[doc])
    own: dict[str, list[str]] = {}
    cur = ""
    for it in dl.body_items(path):
        if isinstance(it, dl.Para) and it.style.startswith("Heading"):
            num = it.text.strip().split("\t", 1)[0].strip()
            if re.match(r"^[A-Z]?\d+(\.\d+)*[A-Z]?$", num):
                cur = num
            own.setdefault(cur, []).append(it.text)
            continue
        txt = it.text if isinstance(it, dl.Para) else "\n".join("\t".join(r) for r in it.texts())
        own.setdefault(cur, []).append(txt)
    full = {}
    for k in own:
        full[k] = "\n".join(t for c, ts in own.items() if c == k or c.startswith(k + ".")
                            for t in ts)
    _clause_cache[doc] = full
    return full


def heading_titles(doc: str) -> dict[str, str]:
    path, _ = dl.source(doc, DOC_VERSION[doc])
    out = {}
    for it in dl.body_items(path):
        if isinstance(it, dl.Para) and it.style.startswith("Heading"):
            num, _, title = it.text.strip().partition("\t")
            out[num.strip()] = title.strip()
    return out


# ---- universes ------------------------------------------------------------------------------

def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def procedure_title(title: str) -> str:
    """A clause title as its procedure is named in the ASN.1 (P3 R0): the initiator in
    parentheses dropped ("UE Context Modification (gNB-CU initiated)") and the -ation
    nouns of NGAP's handover clauses ("Handover Cancellation") as the procedure's verb."""
    t = re.sub(r"\s*\([^)]*\)\s*$", "", title)
    return re.sub(r"\bCancellation\b", "Cancel", t)


def ap_procedures(proto: str) -> list[dict]:
    """Elementary procedures of an AP protocol's PDU-Descriptions module."""
    text = next((ROOT / "spec" / "asn1" / proto).glob("*-PDU-Descriptions.asn")).read_text()
    out = []
    for m in re.finditer(r"^(\w+)\s+\S+-ELEMENTARY-PROCEDURE\s*::=\s*\{(.*?)\}", text, re.S | re.M):
        body = m.group(2)
        msgs = {k: v for k, v in re.findall(
            r"(INITIATING MESSAGE|SUCCESSFUL OUTCOME|UNSUCCESSFUL OUTCOME)\s+([\w-]+)", body)}
        out.append({"procedure": m.group(1), "messages": msgs})
    return out


def rrc_messages() -> list[str]:
    text = (ROOT / "spec" / "asn1" / "rrc" / "NR-RRC-Definitions.asn").read_text()
    names = set()
    for m in re.finditer(r"^([A-Z][\w-]*-MessageType)\s*::=\s*CHOICE\s*\{(.*?)\n\}", text, re.S | re.M):
        c1 = re.search(r"c1\s+CHOICE\s*\{(.*?)\}", m.group(2), re.S)
        body = c1.group(1) if c1 else m.group(2)
        for arm in re.findall(r"^\s*\w+\s+([A-Z][\w-]+)\s*,?\s*$", body, re.M):
            if not arm.startswith("Spare") and arm != "NULL":
                names.add(arm)
    names |= {"MIB", "SIB1"}  # BCCH-BCH carries MIB; BCCH-DL-SCH carries SIB1 directly
    return sorted(names)


def rrc_internode() -> list[str]:
    text = (ROOT / "spec" / "asn1" / "rrc" / "NR-InterNodeDefinitions.asn").read_text()
    return sorted(set(re.findall(r"^([A-Z][\w-]+)\s*::=\s*SEQUENCE\s*\{\s*\n\s*criticalExtensions",
                                 text, re.M)))


def nas_messages() -> list[dict]:
    return dl.read_tsv(ROOT / "spec" / "nas" / "24501" / "messages.tsv")


def sms_messages() -> list[str]:
    cp = [r["name"] for r in dl.read_tsv(ROOT / "spec" / "nas" / "24011" / "cp_message_types.tsv")]
    rp = sorted({r["name"] for r in dl.read_tsv(ROOT / "spec" / "nas" / "24011" / "rp_message_types.tsv")})
    tpdu = []
    for num, title in heading_titles("23.040").items():
        m = re.match(r"^9\.2\.2\.\d+[a-z]?$", num)
        if m:
            t = re.match(r"^(SMS-[A-Z-]+)", title)
            if t:
                tpdu.append(t.group(1))
    return cp + rp + sorted(set(tpdu))


def titled_types(doc: str, clause_prefix: str, pattern: str) -> list[str]:
    out = []
    for num, title in heading_titles(doc).items():
        if num.startswith(clause_prefix):
            m = re.match(pattern, title)
            if m:
                out.append(m.group(1).strip())
    return sorted(set(out))


def gtpu_messages() -> list[str]:
    """GTP-U message types: the rows of TS 29.281 Table 6.1-1 marked for GTP-U."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import docx_tables as dt
    path, _ = dl.source("29.281", DOC_VERSION["29.281"])
    rows = dt.find_caption(dl.body_items(path), "Table 6.1-1").texts()
    return sorted(r[1].strip() for r in rows[1:]
                  if len(r) >= 5 and r[0].strip().isdigit() and r[4].strip().upper() == "X")


def apdu_commands() -> list[str]:
    """UICC commands: the rows of ETSI TS 102 221 Table 10.5 (the PDF, read with pdftotext)."""
    import subprocess
    row = next(r for r in dl.read_tsv(ROOT / "spec" / "INDEX.tsv") if r["doc"] == "102.221")
    text = subprocess.run(["pdftotext", "-layout", str(ROOT / row["file"]), "-"], capture_output=True,
                          text=True, check=True).stdout
    start = text.index("Table 10.5: Coding of Instruction Byte of the Commands", text.index("Table 10.5 depicts"))
    end = text.index("10.1.3", start)
    names = re.findall(r"^\s+([A-Z][A-Z ]+?)\s{2,}'[0-9A-FX]{2}'.*'([0-9A-F]{2})'", text[start:end], re.M)
    return sorted({n.strip() for n, _ in names})


def apdu_v1(rows: list[dict]) -> dict[str, set[str]]:
    """A command is v1 when a v1 UICC row (§2.1) names it: its first word in
    capitals ("SELECT", "VERIFY"), its other words anywhere ("file", "PIN")."""
    out: dict[str, set[str]] = {}
    for r in rows:
        if r["section"] != "2.1":
            continue
        tokens = set(re.findall(r"[A-Za-z0-9]+", r["text"]))
        lower = {t.lower() for t in tokens}
        lower |= {t.lower() for t in re.findall(r"[A-Za-z]+(?=\d)", r["text"])}   # PIN1 -> pin
        for cmd in apdu_commands():
            first, *rest = cmd.split()
            if first in tokens and all(w.lower() in lower for w in rest):
                out.setdefault(cmd, set()).add(r["id"])
    return out


# ---- derivation ----------------------------------------------------------------------------

def mentioned(name: str, text: str) -> bool:
    return re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", text) is not None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    rows = v1_rows()
    hits: dict[tuple[str, str], dict] = {}

    def add(proto: str, pdu: str, rid: str, how: str, extra: str = "") -> None:
        h = hits.setdefault((proto, pdu), {"rows": set(), "how": set(), "extra": extra})
        h["rows"].add(rid)
        h["how"].add(how)

    def texts_for(r: dict, doc: str) -> list[tuple[str, str]]:
        """(where, text): the row's own text, plus each specifically cited clause of doc."""
        out = [("row", r["text"])]
        clauses = clause_texts(doc) if doc in DOC_VERSION else {}
        for d, c in r["citations"]:
            if d == doc and c is not None and c in clauses:
                out.append((f"{doc} {c}", clauses[c]))
        return out

    # AP protocols: a cited clause whose title is a procedure brings that procedure in.
    for doc, proto in AP.items():
        procs = {norm(p["procedure"]): p for p in ap_procedures(proto)}
        titles = heading_titles(doc)
        for r in rows:
            for d, c in r["citations"]:
                if d != doc:
                    continue
                cands = [n for n in titles if c is None or n == c or n.startswith(c + ".")]
                if c is None:
                    continue           # a whole-document citation of an AP spec: no procedures
                for n in cands:
                    p = procs.get(norm(titles[n])) or procs.get(norm(procedure_title(titles[n])))
                    if p:
                        for kind, msg in p["messages"].items():
                            add(proto, msg, r["id"], f"{doc} {n} {p['procedure']}", kind)
    # RRC messages and inter-node containers: named in the row or its cited 38.331/AP clauses.
    rrc_names = rrc_messages() + rrc_internode()
    for r in rows:
        sources = texts_for(r, "38.331")
        for doc in AP:
            sources += texts_for(r, doc)[1:]
        for name in rrc_names:
            for where, text in sources:
                if mentioned(name, text):
                    add("rrc", name, r["id"], where)
                    break
    # NAS: upper-case message names in the row's 24.501 clauses (or its own text).
    nas = nas_messages()
    for r in rows:
        for where, text in texts_for(r, "24.501"):
            for m in nas:
                if mentioned(m["message"], text):
                    add(m["protocol"].lower(), f"{m['message']} ({m['clause']})"
                        if sum(x["message"] == m["message"] for x in nas) > 1 else m["message"],
                        r["id"], where)
    # SMS, GTP-U, PSC, NR-U: names in the row's text or its specific clauses.
    families = [("sms", sms_messages(), ["24.011", "23.040"]),
                ("gtpu", gtpu_messages(), ["29.281"]),
                ("psc", titled_types("38.415", "5.5.2", r"^(DL PDU SESSION INFORMATION|"
                                     r"UL PDU SESSION INFORMATION)"), ["38.415"]),
                ("nru", titled_types("38.425", "5.5.2", r"^(DL USER DATA|DL DATA DELIVERY STATUS|"
                                     r"ASSISTANCE INFORMATION DATA)"), ["38.425"])]
    for proto, names, docs in families:
        for r in rows:
            sources = [("row", r["text"])]
            for doc in docs:
                sources += texts_for(r, doc)[1:]
            for name in names:
                for where, text in sources:
                    if mentioned(name, text) or (where == "row" and mentioned(name.lower(), text.lower())):
                        add(proto, name, r["id"], where)
                        break

    for cmd, rids in apdu_v1(rows).items():
        for rid in rids:
            add("apdu", cmd, rid, "102 221 Table 10.5")

    buf = io.StringIO()
    w = csv.writer(buf, delimiter="\t", lineterminator="\n")
    w.writerow(["# Derived by spec/tools/v1_pdus.py from docs/requirements.md (v1 rows) and the extracted "
                "spec material. Do not edit."])
    w.writerow(["protocol", "pdu", "kind", "ks_rows", "derived_from"])
    for (proto, pdu), h in sorted(hits.items()):
        w.writerow([proto, pdu, h["extra"], ",".join(sorted(h["rows"])),
                    "; ".join(sorted(h["how"]))[:300]])
    fresh = buf.getvalue()
    counts: dict[str, int] = {}
    for proto, _ in hits:
        counts[proto] = counts.get(proto, 0) + 1
    summary = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    if args.check:
        if not OUT.is_file() or OUT.read_text() != fresh:
            print("V1_PDUS=STALE (run spec/tools/v1_pdus.py)")
            sys.exit(1)
        print(f"V1_PDUS=CURRENT total={len(hits)} {summary}")
        return
    OUT.write_text(fresh)
    print(f"V1_PDUS total={len(hits)} {summary}")


if __name__ == "__main__":
    main()
