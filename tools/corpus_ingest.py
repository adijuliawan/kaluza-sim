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
from functools import lru_cache
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


_TEST = re.compile(r"\bTEST(?:_F|_P)?\(\s*\w+\s*,\s*(\w+)\s*\)")
_REFUSES = re.compile(r"\b(?:EXPECT|ASSERT)_FALSE\(\s*[\w.>-]*unpack\w*\(")


def ocudu_arrays(path: Path):
    """Byte vectors in an OCUDU C++ test: brace lists of 0x.. literals (named arrays,
    byte_buffer::create({...}), inline initialisers) and make_byte_buffer("hex")."""
    text = _strip_comments(path.read_text(errors="replace"))
    tests = [(m.start(), m.group(1)) for m in _TEST.finditer(text)]
    ends = [s for s, _ in tests[1:]] + [len(text)]

    def where(at: int) -> str:
        """file:line, with the enclosing test's name, and a mark when that test
        asserts its own unpacker refuses the vector (the producer's word that
        it is malformed)."""
        line = text.count("\n", 0, at) + 1
        for (start, name), end in zip(reversed(tests), reversed(ends)):
            if start < at:
                negative = _REFUSES.search(text, start, end) is not None
                return f"{path.name}:{line} ({name}{'; its test expects refusal' if negative else ''})"
        return f"{path.name}:{line}"

    for m in _BRACES.finditer(text):
        tokens = [t.strip() for t in m.group(1).split(",") if t.strip()]
        if len(tokens) >= 4 and all(re.fullmatch(r"0x[0-9a-fA-F]{1,2}", t) for t in tokens):
            yield where(m.start()), bytes(int(t, 16) for t in tokens)
    for m in _HEXSTR.finditer(text):
        hexes = "".join(re.findall(r"[0-9a-fA-F]", "".join(re.findall(r'"([^"]*)"', m.group(1)))))
        if len(hexes) >= 8 and len(hexes) % 2 == 0:
            yield where(m.start()), bytes.fromhex(hexes)


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


GTPU_TYPES = {1: "Echo Request", 2: "Echo Response", 26: "Error Indication",
              31: "Supported Extension Headers Notification", 253: "Tunnel Status", 254: "End Marker", 255: "G-PDU"}
FRAME_TYPES = {"psc": {0: "DL PDU SESSION INFORMATION", 1: "UL PDU SESSION INFORMATION"},
               "nru": {0: "DL USER DATA", 1: "DL DATA DELIVERY STATUS", 2: "ASSISTANCE INFORMATION DATA"}}


def gtpu_shape(data: bytes) -> str | None:
    """Why the octets are not one GTP-U PDU (TS 29.281 5.1), or None if they are:
    version 1, PT 1, and a Length that covers exactly the rest."""
    if len(data) < 8:
        return "shorter than a GTP-U header"
    if data[0] >> 4 not in (0x3,):
        return f"first octet {data[0]:#04x} is not version 1, PT 1"
    if int.from_bytes(data[2:4], "big") != len(data) - 8:
        return "the Length field does not cover the rest"
    return None


def pdu_name(proto: str, data: bytes) -> str:
    """The message type pycrate reads, or '' when it cannot tell."""
    if proto == "rrc":
        return rrc_name(data)
    if proto == "gtpu":
        return GTPU_TYPES.get(data[1], f"(message type {data[1]})")
    if proto in FRAME_TYPES:
        return FRAME_TYPES[proto].get(data[0] >> 4, f"(PDU type {data[0] >> 4})") if data else ""
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
        if proto == "gtpu" and (why := gtpu_shape(data)) is not None:
            excluded.append({"source": f"{base}:{rel}", "locator": loc, "reason": f"{r['source']}: not a GTP-U PDU ({why})"})
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


# ---- NAS and SMS (plan M11) ------------------------------------------------------------

LAB_PLMNS = {"00101", "99970"}   # the lab's test PLMNs: downlink there is kaluza-core's (ADR 0005)


def nas_messages() -> dict[tuple[str, int], dict]:
    lines = [ln for ln in (ROOT / "spec" / "nas" / "24501" / "messages.tsv").open() if not ln.startswith("#")]
    rows = list(csv.DictReader(lines, delimiter="\t"))
    names = Counter(r["message"] for r in rows)
    out = {}
    for r in rows:
        if r["message_type_hex"]:
            name = r["message"] if names[r["message"]] == 1 else f"{r['message']} ({r['key']})"
            out[(r["protocol"], int(r["message_type_hex"], 16))] = {**r, "v1_name": name,
                                                                     "direction": nas_direction(r["direction"])}
    return out


def nas_direction(text: str) -> str:
    """uplink, downlink or unknown from a message table's 'Direction:' line, which
    TS 24.501 spells several ways (UE to network, UE to AMF, Network to UE, both)."""
    t = text.strip().lower()
    if t.startswith("ue to "):
        return "uplink"
    if t.endswith(" to ue"):
        return "downlink"
    return "unknown"


@lru_cache(maxsize=None)
def nas_min_octets() -> dict[str, int]:
    """Message key -> octets of its mandatory part (TS 24.501 clause 8 tables)."""
    lines = [ln for ln in (ROOT / "spec" / "nas" / "24501" / "message_ies.tsv").open() if not ln.startswith("#")]
    halves: Counter = Counter()
    for r in csv.DictReader(lines, delimiter="\t"):
        if r["presence"].startswith("M"):
            t = r["length"].replace(" ", "")
            halves[r["key"]] += 1 if t == "1/2" else 2 * int(t.split("-")[0])
    return {k: (h + 1) // 2 for k, h in halves.items()}


def nas_name(data: bytes) -> tuple[str, str] | None:
    """(v1 name, direction) of a NAS PDU from its header octets alone. A security
    protected message takes the direction of its plain inner message when the
    protection is integrity only (security header type 1 or 3), else 'both'."""
    msgs = nas_messages()
    if len(data) >= 3 and data[0] == 0x7E:
        if data[1] & 0x0F:
            inner = nas_name(data[7:]) if (data[1] & 0x0F) in (1, 3) and not (data[8:9] and data[8] & 0x0F) else None
            return "SECURITY PROTECTED 5GS NAS MESSAGE", inner[1] if inner else "unknown"
        r = msgs.get(("5GMM", data[2]))
    elif len(data) >= 4 and data[0] == 0x2E:
        r = msgs.get(("5GSM", data[3]))
    else:
        return None
    return (r["v1_name"], r["direction"]) if r else None


def _walk_nas(o, v, out: list[bytes]) -> None:
    """Every NAS-PDU octet string in a pycrate NGAP value."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle.jer import _types
    from ksimoracle.valuegen import type_name
    t = o.TYPE
    if t == "OCTET STRING" and type_name(o) == "NAS-PDU" and isinstance(v, (bytes, bytearray)):
        out.append(bytes(v))
    elif t == "OPEN_TYPE" and isinstance(v, tuple) and len(v) == 2:
        if v[0] == "NAS-PDU" and isinstance(v[1], (bytes, bytearray)):
            out.append(bytes(v[1]))
        else:
            sub = _types("ngap").get(v[0])
            if sub is not None:
                _walk_nas(sub, v[1], out)
    elif t == "SEQUENCE" and isinstance(v, dict):
        for k, x in v.items():
            if k in o._cont:
                _walk_nas(o._cont[k], x, out)
    elif t == "CHOICE" and isinstance(v, tuple) and v[0] in o._cont:
        _walk_nas(o._cont[v[0]], v[1], out)
    elif t in ("SEQUENCE OF", "SET OF") and isinstance(v, list):
        for x in v:
            _walk_nas(o._cont, x, out)


def nas_from_ngap(ngap_rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """NAS-PDUs carried in the NGAP corpus: their producer is the NGAP vector's.
    A NAS-PDU shorter than its message's mandatory part is a test filler (free5gc
    puts a bare header in its NGAP tests) and is excluded."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import asn
    o, enc = asn.top("ngap")
    rows, excluded, seen = [], [], set()
    keys = {r["v1_name"]: r["key"] for r in nas_messages().values()}
    keys["SECURITY PROTECTED 5GS NAS MESSAGE"] = "8.2.28"
    mins = nas_min_octets()
    for r in ngap_rows:
        try:
            v = asn.decode(o, bytes.fromhex(r["hex"]), enc)
        except Exception:  # noqa: BLE001
            continue
        found: list[bytes] = []
        _walk_nas(o, v, found)
        for nas in found:
            named = nas_name(nas)
            if named is None or nas in seen:
                continue
            seen.add(nas)
            need = mins.get(keys.get(named[0], ""), 0)
            if len(nas) < need:
                excluded.append({"source": f"{r['source']} (NAS-PDU in {r['id']})", "locator": r["locator"],
                                 "reason": f"NAS-PDU of {len(nas)} octets, under the {need} of the mandatory part "
                                           f"of {named[0]} (a test filler)"})
                continue
            rows.append({
                "id": f"nas-{r['id']}-{len(rows) + 1:03d}", "proto": "nas", "pdu": named[0], "octets": len(nas),
                "sha256": hashlib.sha256(nas).hexdigest(), "producer": r["producer"],
                "direction": named[1], "same_compiler": "no",
                "source": f"{r['source']} (NAS-PDU in {r['id']})", "locator": r["locator"],
                "licence": r["licence"], "hex": nas.hex()})
    return rows, excluded


def _capture_plmn(recs) -> str | None:
    """The first PLMN a capture's SIB1 broadcasts (MCC+MNC digits), or None."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import asn
    o = asn.obj("rrc", "NR_RRC_Definitions", "BCCH_DL_SCH_Message")
    for _, tag, data in recs:
        if tag != "nr-rrc.bcch.dl.sch":
            continue
        try:
            o.from_uper(data)
            v = o.get_val()["message"]
            sib1 = v[1][1]
            pid = sib1["cellAccessRelatedInfo"]["plmn-IdentityInfoList"][0]["plmn-IdentityList"][0]
            return "".join(str(d) for d in pid.get("mcc", [])) + "".join(str(d) for d in pid["mnc"])
        except Exception:  # noqa: BLE001
            continue
    return None


def _sms_layers(payload: bytes) -> list[tuple[str, bytes, str]]:
    """(v1 name, octets, layer) for the CP, RP and TPDU inside an SMS payload container."""
    out = []
    if len(payload) < 2 or (payload[0] & 0x0F) != 0x9:
        return out
    cp_type = {0x01: "CP-DATA", 0x04: "CP-ACK", 0x10: "CP-ERROR"}.get(payload[1])
    if cp_type is None:
        return out
    out.append((cp_type, payload, "cp"))
    if cp_type != "CP-DATA" or len(payload) < 3:
        return out
    rp = payload[3:3 + payload[2]]
    if not rp:
        return out
    mti = rp[0] & 0x07
    rp_name = {0: "RP-DATA", 1: "RP-DATA", 2: "RP-ACK", 3: "RP-ACK", 4: "RP-ERROR", 5: "RP-ERROR", 6: "RP-SMMA"}.get(mti)
    if rp_name is None:
        return out
    out.append((rp_name, rp, "rp"))
    if mti in (0, 1) and len(rp) > 2:
        pos = 2
        for _ in range(2):                       # originator, destination address (LV)
            pos += 1 + rp[pos] if pos < len(rp) else 0
        if pos < len(rp):
            tpdu = rp[pos + 1:pos + 1 + rp[pos]]
            if tpdu:
                tp_mti = tpdu[0] & 0x03
                name = ({0: "SMS-DELIVER", 1: "SMS-SUBMIT-REPORT", 2: "SMS-STATUS-REPORT"} if mti == 1 else
                        {0: "SMS-DELIVER-REPORT", 1: "SMS-SUBMIT", 2: "SMS-COMMAND"}).get(tp_mti)
                if name:
                    out.append((name, tpdu, "tpdu"))
    return out


def build_local_l3() -> tuple[list[dict], list[dict], Counter]:
    """NAS and SMS from the phone captures: uplink always (the phone's modem);
    downlink only where SIB1 shows an operator PLMN (the lab's is kaluza-core's)."""
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import pcap
    nas_rows, sms_rows, skipped, seen = [], [], Counter(), set()
    for base, root in LOCAL_BASES.items():
        if not root.is_dir():
            continue
        for f in sorted(root.rglob("*_l3.pcap")):
            rel = f.relative_to(root).as_posix()
            run = f.parent.relative_to(root).as_posix()
            recs = pcap.read_exported_pdu(f.read_bytes())
            plmn = _capture_plmn(recs)
            lab = plmn is None or plmn in LAB_PLMNS
            for frame, tag, data in recs:
                if tag != "nas-5gs" or data in seen:
                    continue
                seen.add(data)
                named = nas_name(data)
                if named is None:
                    skipped["nas: not a 5GMM or 5GSM message type in TS 24.501"] += 1
                    continue
                name, direction = named
                ul = direction == "uplink"
                if not ul and lab:
                    skipped["nas: downlink or two-way message in a lab capture (kaluza-core's)"] += 1
                    continue
                if sum(1 for r in nas_rows if r["pdu"] == name) >= LOCAL_CAP_PER_TYPE:
                    continue
                producer = (f"UE modem ({run})" if ul else f"operator core, PLMN {plmn} ({run})" if direction != "unknown"
                            else f"UE modem or operator core, PLMN {plmn} ({run}); the capture has no direction")
                nas_rows.append({"id": f"nas-local-{len(nas_rows) + 1:04d}", "proto": "nas", "pdu": name,
                                 "octets": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                 "producer": producer, "direction": direction,
                                 "source": f"{base}:{rel}", "locator": f"frame {frame}", "hex": data.hex()})
                # SMS in an UL/DL NAS TRANSPORT payload container of type SMS (2)
                if name in ("UL NAS TRANSPORT", "DL NAS TRANSPORT") and len(data) > 6 and (data[3] & 0x0F) == 0x2:
                    plen = (data[4] << 8) | data[5]
                    for sms_name, octets, layer in _sms_layers(data[6:6 + plen]):
                        if sum(1 for r in sms_rows if r["pdu"] == sms_name) >= LOCAL_CAP_PER_TYPE:
                            continue
                        sms_rows.append({"id": f"sms-local-{len(sms_rows) + 1:04d}", "proto": "sms",
                                         "pdu": sms_name, "octets": len(octets),
                                         "sha256": hashlib.sha256(octets).hexdigest(), "producer": producer,
                                         "direction": "uplink" if ul else "downlink", "source": f"{base}:{rel}",
                                         "locator": f"frame {frame} ({layer} in the SMS payload container)",
                                         "hex": octets.hex()})
    return nas_rows, sms_rows, skipped


def open5gs_nas() -> list[dict]:
    """P1 N19: downlink NAS the Open5GS fork encoded in kaluza-sim's control runs
    (tests/vectors/sources/open5gs-nas.tsv, written by tools/open5gs_vectors.py)."""
    src = ROOT / "tests" / "vectors" / "sources" / "open5gs-nas.tsv"
    if not src.is_file():
        return []
    lines = [ln for ln in src.open() if not ln.startswith("#") and ln.strip()]
    out = []
    for r in csv.DictReader(lines, delimiter="\t"):
        out.append({"id": r["id"], "proto": "nas", "pdu": r["pdu"], "octets": r["octets"], "sha256": r["sha256"],
                    "producer": f"Open5GS fork 741c29d8d, its AMF or SMF ({r['run']})", "direction": r["direction"],
                    "same_compiler": "no", "source": f"kaluza-sim:{r['run']}/uu.pcapng (sha256 {r['capture_sha256'][:16]})",
                    "locator": r["locator"],
                    "licence": "protocol data captured from an Open5GS run (the fork is AGPL-3.0; none of its code is copied)",
                    "hex": r["hex"]})
    return out


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
    if "ngap" in by_proto:
        by_proto["nas"], nas_excluded = nas_from_ngap(by_proto["ngap"])
        excluded += nas_excluded
        by_proto["nas"] += open5gs_nas()
        files[ROOT / "tests" / "vectors" / "nas" / "index.tsv"] = render(
            by_proto["nas"], FIELDS, "# NAS-PDUs carried in the NGAP corpus (tools/corpus_ingest.py); the producer "
                                     "is the NGAP vector's. Do not edit.")
    files[ROOT / "tests" / "vectors" / "excluded.tsv"] = render(
        sorted(excluded, key=lambda x: (x["source"], x["locator"])), ["source", "locator", "reason"],
        "# Candidates the sender rules exclude (tools/corpus_ingest.py). Do not edit.")
    local_rows, manifest, skipped = build_local()
    nas_local, sms_local, l3_skipped = build_local_l3()
    local_rows_all = local_rows + nas_local + sms_local
    manifest = [{k: r[k] for k in LOCAL_FIELDS} for r in local_rows_all]
    local_files = {}
    if nas_local:
        local_files[ROOT / "tests" / "vectors" / "local" / "nas" / "index.tsv"] = render(
            nas_local, LOCAL_FIELDS + ["hex"], "# Local-only vectors. Never commit. Do not edit.")
    if sms_local:
        local_files[ROOT / "tests" / "vectors" / "local" / "sms" / "index.tsv"] = render(
            sms_local, LOCAL_FIELDS + ["hex"], "# Local-only vectors. Never commit. Do not edit.")
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
    if nas_local or sms_local:
        print(f"CORPUS_LOCAL proto=nas vectors={len(nas_local)} pdu_types={len({r['pdu'] for r in nas_local})} "
              f"proto=sms vectors={len(sms_local)} pdu_types={len({r['pdu'] for r in sms_local})} "
              f"skipped: {'; '.join(f'{k} x{n}' for k, n in l3_skipped.most_common(3))}")
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
