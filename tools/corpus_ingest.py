#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Build the external-origin test corpus (plan M8, ADR 0005).

    .venv/bin/python -I tools/corpus_ingest.py          write tests/vectors/<proto>/index.tsv
    .venv/bin/python -I tools/corpus_ingest.py --check  fail if the committed corpus is stale

Every candidate octet string is matched against tests/vectors/rules.tsv. The
first rule whose source path and glob match decides: in or out. Each vector
records its producer, source file and sha256, locator (file name, or file:line
for C++ byte arrays), direction, licence, the same-compiler flag and, for the AP
protocols, the PDU type pycrate reads in it. Excluded candidates are listed
too, with the reason, in tests/vectors/excluded.tsv, so every exclusion stays
visible.

Personal data: the sources ingested here are synthetic (OCUDU unit tests) or
lab captures under the test PLMNs 001/01 and 999/70 (the testkit). Phone
captures carry device identities and stay local-only (M10).
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import io
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASES = {
    "testkit": Path("/home/amadeus/Development/kaluza-core/testkit/kaluza-testkit-vectors/src/main/resources/vectors"),
    "ocudu": Path("/home/amadeus/Development/ran/ocudu"),
    "kaluza-sim": ROOT,
}
LICENCE = {"testkit": "kaluza-core testkit (external-origin octets, the user's own repo)",
           "ocudu": "BSD-3-Clause-Open-MPI (OCUDU unit tests)",
           "kaluza-sim": "BSD-3-Clause-Open-MPI (OCUDU's builders and encoder, run by tools/ocudu_vectors)"}
FIELDS = ["id", "proto", "pdu", "octets", "sha256", "producer", "direction", "same_compiler", "source",
          "locator", "licence", "hex"]


def load_rules() -> list[dict]:
    lines = [ln for ln in (ROOT / "tests" / "vectors" / "rules.tsv").open() if not ln.startswith("#") and ln.strip()]
    return list(csv.DictReader(lines, delimiter="\t"))


def rule_for(rules: list[dict], base: str, rel: str) -> dict | None:
    for r in rules:
        b, _, sub = r["path"].partition("/")
        if b != base:
            continue
        if rel.startswith(sub + "/") and fnmatch.fnmatch(rel[len(sub) + 1:], r["glob"]):
            return r
    return None


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments, keeping every newline (so line numbers hold)."""
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


_BRACES = re.compile(r"\{([^{}]*)\}")
_HEXSTR = re.compile(r"make_byte_buffer\(\s*((?:\"[0-9a-fA-F\s]*\"\s*)+)\)")


def ocudu_arrays(path: Path):
    """Byte vectors in an OCUDU C++ test: brace lists of 0x.. literals (named arrays,
    byte_buffer::create({...}), inline initialisers) and make_byte_buffer("hex")."""
    text = _strip_comments(path.read_text(errors="replace"))
    for m in _BRACES.finditer(text):
        tokens = [t.strip() for t in m.group(1).split(",") if t.strip()]
        if len(tokens) >= 4 and all(re.fullmatch(r"0x[0-9a-fA-F]{1,2}", t) for t in tokens):
            line = text.count("\n", 0, m.start()) + 1
            yield f"{path.name}:{line}", bytes(int(t, 16) for t in tokens)
    for m in _HEXSTR.finditer(text):
        hexes = "".join(re.findall(r"[0-9a-fA-F]", "".join(re.findall(r'"([^"]*)"', m.group(1)))))
        if len(hexes) >= 8 and len(hexes) % 2 == 0:
            line = text.count("\n", 0, m.start()) + 1
            yield f"{path.name}:{line}", bytes.fromhex(hexes)


ROW_PROTO: dict[tuple[str, str], str] = {}   # (file, locator) -> protocol named in a tsv source


def candidates(rules: list[dict]):
    """(base, rel, locator, bytes) for every file the rules reach."""
    seen_paths = set()
    for r in rules:
        base, _, sub = r["path"].partition("/")
        root = BASES[base] / sub
        if not root.exists():
            continue
        if r["kind"] == "bin":
            for p in sorted(root.glob("*.bin")):
                key = (base, str(p))
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                yield base, f"{sub}/{p.name}", p.name, p.read_bytes(), p
        elif r["kind"] == "tsv":                  # protocol, builder, hex (tools/ocudu_vectors)
            p = root / r["glob"]
            if not p.is_file() or (base, str(p)) in seen_paths:
                continue
            seen_paths.add((base, str(p)))
            lines = [ln.rstrip("\n") for ln in p.open() if not ln.startswith("#")]
            for row in csv.DictReader(lines, delimiter="\t"):
                ROW_PROTO[(f"{sub}/{r['glob']}", row["builder"])] = row["protocol"]
                yield base, f"{sub}/{r['glob']}", row["builder"], bytes.fromhex(row["hex"]), p
        elif r["kind"] == "ocudu-cpp":
            p = root / r["glob"]
            if not p.is_file() or (base, str(p)) in seen_paths:
                continue
            seen_paths.add((base, str(p)))
            for loc, data in ocudu_arrays(p):
                yield base, f"{sub}/{r['glob']}", loc, data, p


RRC_CLASSES = ["UL_CCCH_Message", "UL_CCCH1_Message", "DL_CCCH_Message", "UL_DCCH_Message", "DL_DCCH_Message",
               "PCCH_Message", "BCCH_BCH_Message", "BCCH_DL_SCH_Message"]


def rrc_name(data: bytes) -> str:
    """'<Class>.<message>' when exactly the bytes decode and re-encode as an RRC
    message class, else '(not a top-level RRC message)'."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import asn
    for cls in RRC_CLASSES:
        o = asn.obj("rrc", "NR_RRC_Definitions", cls)
        try:
            o.from_uper(data)
            if o.to_uper() != data:
                continue
            v = o.get_val()["message"]
            name = v[1][0] if v[0] == "c1" else v[0]
            return f"{cls}.{name}"
        except Exception:  # noqa: BLE001
            continue
    return "(not a top-level RRC message)"


def auto_proto(data: bytes) -> str | None:
    """The protocol whose top-level PDU decodes and re-encodes these exact bytes."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import asn
    for proto in ("ngap", "f1ap", "e1ap", "xnap"):
        o, enc = asn.top(proto)
        try:
            asn.decode(o, data, enc)
            if (o.to_aper() if enc == "aper" else o.to_uper()) == data:
                return proto
        except Exception:  # noqa: BLE001
            pass
    return "rrc" if not rrc_name(data).startswith("(") else None


def pdu_name(proto: str, data: bytes) -> str:
    """The message type pycrate reads, or '' when it cannot tell."""
    if proto == "rrc":
        return rrc_name(data)
    if proto not in ("ngap", "f1ap", "e1ap", "xnap"):
        return ""
    try:
        sys.path.insert(0, str(ROOT / "tests" / "oracles"))
        from ksimoracle import asn
        o, enc = asn.top(proto)
        asn.decode(o, data, enc)
        kind, body = o.get_val()
        return body["value"][0]
    except Exception:  # noqa: BLE001 - an undecodable candidate is recorded as such
        return "(undecodable)"


def build() -> tuple[dict[str, list[dict]], list[dict]]:
    rules = load_rules()
    by_proto: dict[str, list[dict]] = {}
    excluded = []
    for base, rel, loc, data, path in candidates(rules):
        r = rule_for(rules, base, rel if rules and rel.count("/") else rel)
        if r is None and base == "testkit":
            r = rule_for(rules, base, rel)
        if r is None:
            excluded.append({"source": f"{base}:{rel}", "locator": loc, "reason": "no rule matches"})
            continue
        if r["decision"] != "in":
            excluded.append({"source": f"{base}:{rel}", "locator": loc, "reason": f"{r['source']}: {r['reason']}"})
            continue
        proto = r["proto"]
        if proto == "row":
            proto = ROW_PROTO[(rel, loc)]
        if proto == "auto":
            proto = auto_proto(data)
            if proto is None:
                excluded.append({"source": f"{base}:{rel}", "locator": loc,
                                 "reason": f"{r['source']}: not a whole PDU of any known protocol"})
                continue
        rows = by_proto.setdefault(proto, [])
        rows.append({
            "id": f"{proto}-{r['source']}-{len(rows) + 1:03d}", "proto": proto, "pdu": pdu_name(proto, data),
            "octets": len(data), "sha256": hashlib.sha256(data).hexdigest(), "producer": r["producer"],
            "direction": r["direction"], "same_compiler": r["same_compiler"],
            "source": f"{base}:{rel}", "locator": loc, "licence": LICENCE[base], "hex": data.hex()})
    return by_proto, excluded


# Local-only sources (plan M8): the user's phone captures carry device
# identities, so their octets stay under tests/vectors/local/ (git-ignored) and
# only a hash manifest is committed. NR RRC only for now: the uplink is the
# phone's modem, the downlink the network's gNB (the lab's OCUDU or an
# operator's); NAS waits for M11, where the direction rules (kaluza-core's
# downlink NAS is out) need the NAS header.
LOCAL_BASES = {"kaluza-ue": Path("/home/amadeus/Development/ran/kaluza-ue/captures")}
LOCAL_CAP_PER_TYPE = 12
RRC_TAG_CLASS = {
    "nr-rrc.ul.ccch": "UL_CCCH_Message", "nr-rrc.ul.ccch1": "UL_CCCH1_Message",
    "nr-rrc.dl.ccch": "DL_CCCH_Message", "nr-rrc.ul.dcch": "UL_DCCH_Message",
    "nr-rrc.dl.dcch": "DL_DCCH_Message", "nr-rrc.pcch": "PCCH_Message",
    "nr-rrc.bcch.bch": "BCCH_BCH_Message", "nr-rrc.bcch.dl.sch": "BCCH_DL_SCH_Message",
}
LOCAL_FIELDS = ["id", "proto", "pdu", "octets", "sha256", "producer", "direction", "source", "locator"]


def _rrc_exact(cls: str, data: bytes) -> tuple[str, bytes, str] | None:
    """('<Class>.<message>', octets, note) if the octets are one encoding of the
    class, possibly followed by zero octets of transport-block padding (SIB1 and
    Paging arrive in a whole MAC transport block), which are removed."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import asn
    o = asn.obj("rrc", "NR_RRC_Definitions", cls)
    try:
        o.from_uper(data)
        again = o.to_uper()
    except Exception:  # noqa: BLE001
        return None
    note = ""
    if again != data:
        if not data.startswith(again) or any(data[len(again):]):
            return None
        note = f" (transport-block padding removed: {len(data) - len(again)} zero octets)"
    v = o.get_val()["message"]
    name = v[1][0] if v[0] == "c1" else v[0]
    return f"{cls.replace('_', '-')}.{name}", again, note


def build_local() -> tuple[list[dict], list[dict], Counter]:
    """(rows with hex, manifest rows, exclusion reasons) over the local captures."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import pcap
    rows, seen, per_type, skipped = [], set(), Counter(), Counter()
    for base, root in LOCAL_BASES.items():
        if not root.is_dir():
            continue
        for f in sorted(root.rglob("*_l3.pcap")):
            rel = f.relative_to(root).as_posix()
            run = f.parent.relative_to(root).as_posix()
            for frame, tag, data in pcap.read_exported_pdu(f.read_bytes()):
                cls = RRC_TAG_CLASS.get(tag)
                if cls is None:
                    continue
                h = hashlib.sha256(data).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                got = _rrc_exact(cls, data)
                if got is None:
                    skipped[f"{tag}: not one {cls} encoding (+ zero padding)"] += 1
                    continue
                name, data, note = got
                if per_type[name] >= LOCAL_CAP_PER_TYPE:
                    continue
                per_type[name] += 1
                ul = ".ul." in tag
                rows.append({
                    "id": f"rrc-local-{len(rows) + 1:04d}", "proto": "rrc", "pdu": name, "octets": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(), "direction": "uplink" if ul else "downlink",
                    "producer": (f"UE modem ({run})" if ul else f"network gNB ({run})"),
                    "source": f"{base}:{rel}", "locator": f"frame {frame}{note}", "hex": data.hex()})
    manifest = [{k: r[k] for k in LOCAL_FIELDS} for r in rows]
    return rows, manifest, skipped


def render(rows: list[dict], fields: list[str], header: str) -> str:
    buf = io.StringIO()
    buf.write(header + "\n")
    w = csv.DictWriter(buf, fieldnames=fields, delimiter="\t", lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    by_proto, excluded = build()
    files = {}
    for proto, rows in by_proto.items():
        files[ROOT / "tests" / "vectors" / proto / "index.tsv"] = render(
            rows, FIELDS, "# External-origin vectors (tools/corpus_ingest.py, rules in tests/vectors/rules.tsv). "
                          "Do not edit.")
    files[ROOT / "tests" / "vectors" / "excluded.tsv"] = render(
        sorted(excluded, key=lambda x: (x["source"], x["locator"])), ["source", "locator", "reason"],
        "# Candidates the sender rules exclude (tools/corpus_ingest.py). Do not edit.")
    local_rows, manifest, skipped = build_local()
    local_files = {}
    if local_rows:
        files[ROOT / "tests" / "vectors" / "local-manifest.tsv"] = render(
            manifest, LOCAL_FIELDS, "# Local-only vectors (tools/corpus_ingest.py): the octets stay under "
                                    "tests/vectors/local/ (git-ignored; device identities). Do not edit.")
        local_files[ROOT / "tests" / "vectors" / "local" / "rrc" / "index.tsv"] = render(
            local_rows, LOCAL_FIELDS + ["hex"], "# Local-only vectors. Never commit. Do not edit.")
    stale = [p for p, text in files.items() if not p.is_file() or p.read_text() != text]
    if a.check:
        for p in stale:
            print(f"CORPUS=STALE {p.relative_to(ROOT)}")
        print(f"CORPUS={'STALE' if stale else 'CURRENT'}")
        sys.exit(1 if stale else 0)
    for p, text in {**files, **local_files}.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    if local_rows:
        types = Counter(r["pdu"] for r in local_rows)
        print(f"CORPUS_LOCAL proto=rrc vectors={len(local_rows)} pdu_types={len(types)} "
              f"skipped={sum(skipped.values())} ({'; '.join(f'{k} x{n}' for k, n in skipped.most_common(4))})")
    for proto, rows in sorted(by_proto.items()):
        types = {r["pdu"] for r in rows if r["pdu"]}
        print(f"CORPUS proto={proto} vectors={len(rows)} pdu_types={len(types)}")
    print(f"CORPUS excluded={len(excluded)}")


if __name__ == "__main__":
    main()
