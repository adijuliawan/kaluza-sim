#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Extract the NAS and SMS tables kaluza-sim's codecs are generated from
(plan M7, architecture.md §4.2). Clean-room, standard library only.

    spec/tools/docx_tables.py 24501      TS 24.501 j80 -> spec/nas/24501/*.tsv
    spec/tools/docx_tables.py 24008      TS 24.008 j50 ePCO container IDs -> spec/nas/24008/
    spec/tools/docx_tables.py 24011      TS 24.011 j00 CP/RP message types -> spec/nas/24011/
    spec/tools/docx_tables.py all [--out DIR]

TS 24.501 outputs:
  messages.tsv        every message of §8.2 (5GMM) and §8.3 (5GSM): clause,
                      table, name, message type value, significance, direction
  message_ies.tsv     every row of every message content table
  message_types.tsv   Tables 9.7.1 and 9.7.2
  causes_5gmm.tsv     Table 9.11.3.2.1
  causes_5gsm.tsv     Table 9.11.4.2.1
  clauses.tsv         clause number -> title for §9 (references resolve here)
  mm_states_ue.tsv    the UE's 5GMM main states and substates (§5.1.3.2.1.2-4),
                      which the 5GMM entity's state table is checked against

Every run checks the extraction against the spec's own structure and fails
on a mismatch (see check_24501): message counts equal Tables 9.7.1/9.7.2 with
names matched one to one, every same-spec reference resolves, IEIs are unique
per message, presence is M/O/C, and format and length agree.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docx_lib as dl  # noqa: E402

TOOL_VERSION = "1.2"
NBSP = " "


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace(NBSP, " ")).strip()


def bits_value(cells: list[str]) -> int | None:
    """Value of a row whose first eight cells are the bits 8..1 of a bit table."""
    bits = [c.strip() for c in cells[:8]]
    if len(bits) == 8 and all(b in ("0", "1") for b in bits):
        return int("".join(bits), 2)
    return None


def bit_table(t: dl.Table) -> list[tuple[int, str]]:
    out = []
    for r in t.texts():
        v = bits_value(r)
        if v is None:
            continue
        name = next((norm(c) for c in reversed(r[8:]) if norm(c)), "")
        out.append((v, name))
    return out


def find_caption(items, prefix: str) -> dl.Table:
    """The table after the caption 'Table N: ...' (24.501) or 'Table N/3GPP TS x: ...' (24.011)."""
    pat = re.compile(re.escape(prefix) + r"(/3GPP TS [\d.]+)?:")
    for i, it in enumerate(items):
        if isinstance(it, dl.Para) and pat.match(norm(it.text)):
            for nxt in items[i + 1:i + 4]:
                if isinstance(nxt, dl.Table):
                    return nxt
    raise dl.ExtractError(f"table '{prefix}' not found")


# ---- TS 24.501 ------------------------------------------------------------------

_MSG_CAPTION = re.compile(r"^Table (8\.[23](?:\.\d+)+): (.+?) message content$", re.I)
_CLAUSE_HEAD = re.compile(r"^(9(?:\.\d+)+[A-Z]?)\t(.+)$")
_SAME_SPEC_REF = re.compile(r"^(\d+(?:\.\d+)*[A-Z]?)$")


_MSG_CLAUSE_HEAD = re.compile(r"^(8\.[23]\.\d+)\t(.+)$")
_TYPE_CLAUSE = re.compile(r"as specified in clause (8\.[23]\.\d+)", re.I)

# Caption typos in the pinned document, repaired by exact match (each a -S row).
CAPTION_TYPOS = {
    "8.2.2341.1": "8.2.24.1.1",   # TS 24.501 j80, NOTIFICATION RESPONSE; row KS-NAS-S1
}

# Message content tables with no message type: the security-protected container
# is recognised by its security header type (§9.3), not by a message type.
NO_MESSAGE_TYPE = {"8.2.28"}


_UE_STATE_HEAD = re.compile(r"^(5\.1\.3\.2\.1\.([234])\.\d+)\s+(5GMM-[A-Za-z0-9.-]+)$")


def extract_24501(items) -> dict[str, list[dict]]:
    messages, ies, clauses, ue_states = [], [], [], []
    meta: dict[str, str] = {}
    msg_clause, msg_title = "", ""
    for i, it in enumerate(items):
        if not isinstance(it, dl.Para):
            continue
        text = it.text.replace(NBSP, " ")
        if it.style.startswith("Heading"):
            meta = {}
            m = _UE_STATE_HEAD.match(norm(text))
            if m:
                kind = "main" if m.group(2) == "2" else "substate"
                state = m.group(3)
                parent = state.split(".", 1)[0] if kind == "substate" else ""
                ue_states.append({"clause": m.group(1), "kind": kind, "state": state, "parent": parent})
            m = _CLAUSE_HEAD.match(text)
            if m:
                clauses.append({"clause": m.group(1), "title": norm(m.group(2))})
            m = _MSG_CLAUSE_HEAD.match(text)
            if m:
                msg_clause, msg_title = m.group(1), norm(m.group(2))
        for key in ("Message type", "Significance", "Direction"):
            if text.startswith(key + ":"):
                meta[key] = norm(text.split(":", 1)[1])
        m = _MSG_CAPTION.match(norm(text))
        if not m:
            continue
        table_no, name = m.group(1), norm(m.group(2)).upper()
        table_no = CAPTION_TYPOS.get(table_no, table_no)
        if not table_no.startswith(msg_clause + "."):
            raise dl.ExtractError(f"table {table_no} outside its clause {msg_clause}")
        tbl = next((x for x in items[i + 1:i + 4] if isinstance(x, dl.Table)), None)
        if tbl is None:
            raise dl.ExtractError(f"no table after caption {table_no}")
        proto = "5GMM" if table_no.startswith("8.2") else "5GSM"
        # The message key is its clause: 24.501 reuses one caption for distinct
        # messages (DEREGISTRATION REQUEST in 8.2.12 and 8.2.14).
        messages.append({"key": msg_clause, "protocol": proto, "clause": msg_clause,
                         "title": msg_title, "table": table_no, "message": name,
                         "significance": meta.get("Significance", ""),
                         "direction": meta.get("Direction", "")})
        rows = tbl.texts()
        if [norm(c) for c in rows[0][:6]] != ["IEI", "Information Element",
                                              "Type/Reference", "Presence", "Format", "Length"]:
            raise dl.ExtractError(f"{table_no}: unexpected header {rows[0]}")
        for seq, r in enumerate(rows[1:], start=1):
            if len(r) < 6:
                raise dl.ExtractError(f"{table_no} row {seq}: {len(r)} cells: {r}")
            tr = [x for x in r[2].split("\n") if x.strip()]
            ref = norm(tr[-1]) if len(tr) > 1 else ""
            ies.append({"key": msg_clause, "message": name, "seq": seq, "iei": norm(r[0]),
                        "ie_name": norm(r[1]),
                        "type_name": norm(" ".join(tr[:-1]) if len(tr) > 1 else r[2]),
                        "reference": ref, "presence": norm(r[3]),
                        "format": norm(r[4]), "length": norm(r[5])})
    mm = [{"protocol": "5GMM", "value_hex": f"{v:02X}", "value": v, "name": n}
          for v, n in bit_table(find_caption(items, "Table 9.7.1")) if v & 0x3F]
    sm = [{"protocol": "5GSM", "value_hex": f"{v:02X}", "value": v, "name": n}
          for v, n in bit_table(find_caption(items, "Table 9.7.2")) if v & 0x3F]
    causes_mm = [{"value": v, "value_hex": f"{v:02X}", "name": n}
                 for v, n in bit_table(find_caption(items, "Table 9.11.3.2.1"))]
    causes_sm = [{"value": v, "value_hex": f"{v:02X}", "name": n}
                 for v, n in bit_table(find_caption(items, "Table 9.11.4.2.1"))]
    types = mm + sm
    # Match each message type to its message: by the clause the type table names
    # ("... as specified in clause 8.2.12"), else by name.
    by_clause = {msg["clause"]: msg for msg in messages}
    by_name: dict[tuple[str, str], list[dict]] = {}
    for msg in messages:
        by_name.setdefault((msg["protocol"], msg["message"]), []).append(msg)
    for t in types:
        m = _TYPE_CLAUSE.search(t["name"])
        cands = [by_clause[m.group(1)]] if m and m.group(1) in by_clause else \
            by_name.get((t["protocol"], t["name"].upper()), [])
        t["message_clause"] = cands[0]["clause"] if len(cands) == 1 else ""
        if len(cands) == 1:
            cands[0]["message_type_hex"] = t["value_hex"]
    for msg in messages:
        msg.setdefault("message_type_hex", "")
    seen = set()
    uniq_clauses = []
    for c in clauses:
        if c["clause"] not in seen:
            seen.add(c["clause"])
            uniq_clauses.append(c)
    return {"messages": messages, "message_ies": ies, "message_types": types,
            "causes_5gmm": causes_mm, "causes_5gsm": causes_sm, "clauses": uniq_clauses,
            "mm_states_ue": ue_states}


_LEN = re.compile(r"^(1/2|\d+)")


def min_length(length: str) -> float | None:
    m = _LEN.match(length.replace(" ", ""))
    if not m:
        return None
    return 0.5 if m.group(1) == "1/2" else float(m.group(1))


def check_24501(d: dict[str, list[dict]]) -> list[str]:
    problems = []
    for t in d["message_types"]:
        if not t["message_clause"]:
            problems.append(f"{t['protocol']}: message type {t['value_hex']} '{t['name']}' "
                            f"matches no message content table")
    for msg in d["messages"]:
        if not msg["message_type_hex"] and msg["clause"] not in NO_MESSAGE_TYPE:
            problems.append(f"{msg['clause']} {msg['message']}: no message type in Table 9.7.x")
    matched = [t["message_clause"] for t in d["message_types"] if t["message_clause"]]
    if len(set(matched)) != len(matched):
        problems.append("a message content table matches two message types")
    clauses = {c["clause"] for c in d["clauses"]}
    per_msg: dict[str, set[str]] = {}
    for r in d["message_ies"]:
        where = f"{r['key']} {r['message']} row {r['seq']}"
        if r["presence"] not in ("M", "O", "C"):
            problems.append(f"{where}: presence '{r['presence']}'")
        ref = r["reference"]
        if _SAME_SPEC_REF.match(ref) and ref not in clauses:
            problems.append(f"{where}: reference {ref} does not resolve to a clause")
        if not ref:
            problems.append(f"{where}: no reference")
        iei = r["iei"]
        if iei:
            seen = per_msg.setdefault(r["key"], set())
            if iei in seen:
                problems.append(f"{where}: duplicate IEI {iei}")
            seen.add(iei)
        fmt, ml = r["format"], min_length(r["length"])
        if ml is None:
            problems.append(f"{where}: unreadable length '{r['length']}'")
            continue
        half_octet_iei = bool(re.fullmatch(r"[0-9A-F]-", iei))
        expect = {"V": None, "LV": 1, "LV-E": 2, "TV": 1, "TLV": 2, "TLV-E": 3, "T": 1}
        if fmt not in expect:
            problems.append(f"{where}: format '{fmt}'")
        elif fmt.startswith("T") and not iei:
            problems.append(f"{where}: format {fmt} without IEI")
        elif not fmt.startswith("T") and iei:
            problems.append(f"{where}: format {fmt} with IEI {iei}")
        elif expect[fmt] is not None and not half_octet_iei and ml < expect[fmt]:
            problems.append(f"{where}: format {fmt} but length {r['length']}")
    return problems


# ---- TS 24.008 (ePCO container identifiers) ----------------------------------------

_CONTAINER = re.compile(r"^\s*-?\s*([0-9A-F]{4})H\s*\((.*)\)$")


def _trim(text: str) -> str:
    """'-\t0051H (SDNAEPC EAP message ...);or' -> '-\t0051H (SDNAEPC EAP message ...)'."""
    t = text.replace(NBSP, " ").strip()
    t = re.sub(r"\s*(;\s*(or|and)?|\.)\s*$", "", t)
    return t


def extract_24008(items) -> dict[str, list[dict]]:
    """Container identifiers listed in §10.5.6.3 (Protocol configuration options),
    which §10.5.6.3A (ePCO) uses unchanged. In j50 the list sits as lines inside
    a one-cell table of §10.5.6.3.1; the direction comes from the list headings."""
    lines: list[str] = []
    in_clause = False
    for it in items:
        if isinstance(it, dl.Para) and it.style.startswith("Heading"):
            h = it.text.split("\t", 1)[0]
            in_clause = h == "10.5.6.3" or h.startswith("10.5.6.3.")
            continue
        if not in_clause:
            continue
        if isinstance(it, dl.Para):
            lines += it.text.replace(NBSP, " ").split("\n")
        else:
            for row in it.rows:
                for c in row:
                    lines += c.text.replace(NBSP, " ").split("\n")
    # The NOTE to figure 10.5.136 names, per direction, the containers whose
    # length field is two octets (octets z+3, z+4) instead of one: a list after
    # "If the container ID is:", closed by "for network to MS direction" or "for
    # MS to network direction". The names do not decide it: "QoS rules with the
    # length of two octets support indicator" (MS to network) has a one-octet length.
    two_octet: dict[str, set[str]] = {"UE-to-network": set(), "network-to-UE": set()}
    pending: set[str] | None = None
    for text in lines:
        t = text.strip()
        if "If the container ID is" in t:
            pending = set()
            continue
        if pending is None:
            continue
        if "for network to MS direction" in t or "for MS to network direction" in t:
            two_octet["network-to-UE" if "network to MS" in t else "UE-to-network"] |= pending
            pending = None
            continue
        m = re.match(r"-?\s*([0-9A-Fa-f]{4})H\b", t)
        if m:
            pending.add(m.group(1).upper())
    if not all(two_octet.values()):
        raise dl.ExtractError("24.008: the two-octet length NOTE of 10.5.6.3 not found for both directions")
    rows, direction = [], ""
    for text in lines:
        head = text.strip().lower()
        if head in ("ms to network direction:", "ue to network direction:"):
            direction = "UE-to-network"
            continue
        if head in ("network to ms direction:", "network to ue direction:"):
            direction = "network-to-UE"
            continue
        if not direction:
            continue          # before the two authoritative lists
        m = _CONTAINER.match(_trim(text))
        if m:
            rows.append({"direction": direction, "id_hex": m.group(1), "name": norm(m.group(2)),
                         "length_octets": 2 if m.group(1).upper() in two_octet[direction] else 1})
    if not rows:
        raise dl.ExtractError("24.008: no container identifiers found in 10.5.6.3")
    return {"epco_containers": rows}


# ---- TS 24.011 (CP and RP message types) ----------------------------------------------

def extract_24011(items) -> dict[str, list[dict]]:
    """Table 8.1 (CP message types) is one cell of tab-separated lines; Table 8.3
    (RP message type indicator) is 3-bit values with a direction column."""
    cp = []
    for t in find_caption(items, "Table 8.1").texts():
        for cell in t:
            for line in cell.split("\n"):
                tok = [x.strip() for x in line.split("\t") if x.strip()]
                if len(tok) == 9 and all(b in ("0", "1") for b in tok[:8]):
                    cp.append({"value_hex": f"{int(''.join(tok[:8]), 2):02X}", "name": tok[8]})
    rp = []
    for r in find_caption(items, "Table 8.3").texts():
        bits = r[0].split() if r else []
        if len(r) >= 3 and len(bits) == 3 and all(b in ("0", "1") for b in bits):
            name = norm(r[2])
            if name.lower() != "reserved":
                rp.append({"mti": int("".join(bits), 2), "direction": norm(r[1]), "name": name})
    if not cp or not rp:
        raise dl.ExtractError("24.011: CP or RP message type table empty")
    return {"cp_message_types": cp, "rp_message_types": rp}


# ---- TS 23.038 (GSM 7 bit default alphabet and its extension table) ----------------

# Cell names and footnote marks the tables use instead of a glyph, per table.
# "ESC" is not a character: in the default table 0x1B escapes to the extension
# table (note 1); in the extension table it is reserved for a further table.
_NAMED = {
    "default": {"SP": ("U+0020", ""), "LF": ("U+000A", ""), "CR": ("U+000D", ""),
                "1)": ("ESC", "escape to the extension table (6.2.1 note 1)")},
    "extension": {"1)": ("ESC", "reserved escape to another extension table (6.2.1.1 note 1)"),
                  "3)": ("U+000C", "page break (6.2.1.1 note 3)")},
}


def _alphabet(t: dl.Table, which: str) -> list[dict]:
    rows = t.texts()
    out = []
    for r in rows:
        if len(r) < 13 or not re.fullmatch(r"[0-9]|1[0-5]", r[4].strip()):
            continue
        row = int(r[4].strip())
        for col in range(8):
            cell = r[5 + col].strip()
            if not cell:
                continue
            code = col * 16 + row
            if cell in _NAMED[which]:
                uni, note = _NAMED[which][cell]
            elif len(cell) == 1:
                uni, note = f"U+{ord(cell):04X}", ""
            else:
                raise dl.ExtractError(f"23.038 {which} table: cell 0x{code:02X} is {cell!r}")
            out.append({"table": which, "code_hex": f"{code:02X}", "unicode": uni,
                        "cell": cell, "note": note})
    return out


def extract_23038(items) -> dict[str, list[dict]]:
    tables = []
    for i, it in enumerate(items):
        if isinstance(it, dl.Para) and it.style.startswith("Heading"):
            h = it.text.split("\t", 1)[0]
            if h in ("6.2.1", "6.2.1.1"):
                tbl = next((x for x in items[i + 1:i + 6] if isinstance(x, dl.Table)), None)
                if tbl is None:
                    raise dl.ExtractError(f"23.038: no table under {h}")
                tables.append((h, tbl))
    if [h for h, _ in tables] != ["6.2.1", "6.2.1.1"]:
        raise dl.ExtractError(f"23.038: alphabet tables not found ({[h for h, _ in tables]})")
    default = _alphabet(tables[0][1], "default")
    extension = _alphabet(tables[1][1], "extension")
    if len(default) != 128:
        raise dl.ExtractError(f"23.038: default alphabet has {len(default)} of 128 characters")
    return {"gsm7_alphabet": default + extension}


# ---- driver ---------------------------------------------------------------------------

SPECS = {
    "24501": ("24.501", "j80", extract_24501, check_24501),
    "24008": ("24.008", "j50", extract_24008, None),
    "24011": ("24.011", "j00", extract_24011, None),
    "23038": ("23.038", "j00", extract_23038, None),
}


def run(key: str, out_root: Path) -> list[str]:
    doc, ver, extract, check = SPECS[key]
    path, row = dl.source(doc, ver)
    data = extract(dl.body_items(path))
    problems = check(data) if check else []
    header = dl.header_lines("docx_tables.py", TOOL_VERSION, doc, ver, row)
    for name, rows in data.items():
        fields = list(rows[0].keys()) if rows else ["empty"]
        dl.write_tsv(out_root / key / f"{name}.tsv", header, fields, rows)
    summary = " ".join(f"{k}={len(v)}" for k, v in data.items())
    print(f"NAS_TABLES spec={doc} {ver} {summary} problems={len(problems)}")
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec", choices=[*SPECS, "all"])
    ap.add_argument("--out", type=Path, default=dl.ROOT / "spec" / "nas")
    args = ap.parse_args()
    keys = list(SPECS) if args.spec == "all" else [args.spec]
    problems = []
    for k in keys:
        try:
            problems += run(k, args.out)
        except dl.ExtractError as e:
            print(f"NAS_TABLES spec={k} FAIL: {e}", file=sys.stderr)
            sys.exit(1)
    for p in problems:
        print(f"CHECK {p}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
