# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The M11 check for 5GS NAS and SMS: our codecs against pycrate and tshark.

    ours     ksim-codec decodes the octets and re-encodes them byte for byte;
    pycrate  decodes them (pycrate_mobile) and re-encodes them byte for byte, and
             for NAS each IE (IEI, value) it reads equals ours;
    tshark   finds nothing wrong (nas-5gs; SMS through the RP layer, which tells
             the TPDU dissector the direction).

Generated values are pycrate's own messages: its defaults (min) and, for NAS,
every optional IE switched on with its default contents (max); and for NAS a
third, table-max, built from the Rel-19 tables with every IE at its minimum
length, which carries the IEs newer than pycrate and is checked by our round
trip and tshark only. Those contents
are often semantically empty, so a tshark complaint inside an IE of a
generated value is GENERATED_CONTENT, not a failure; corpus vectors carry the
full tshark check.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from . import pcap, tshark
from .codec import Codec

ROOT = Path(__file__).resolve().parents[3]

SMS_CLASSES = {   # v1 SMS type -> (ksim-codec proto, pycrate module, class, direction)
    "CP-DATA": ("sms-cp", "PP", "CP_DATA", None), "CP-ACK": ("sms-cp", "PP", "CP_ACK", None),
    "CP-ERROR": ("sms-cp", "PP", "CP_ERROR", None),
    "RP-DATA": ("sms-rp", "PP", "RP_DATA_MO", None), "RP-ACK": ("sms-rp", "PP", "RP_ACK_MO", None),
    "RP-ERROR": ("sms-rp", "PP", "RP_ERROR_MO", None), "RP-SMMA": ("sms-rp", "PP", "RP_SMMA", None),
    "SMS-SUBMIT": ("sms-tpdu-mo", "TP", "SMS_SUBMIT", "mo"), "SMS-COMMAND": ("sms-tpdu-mo", "TP", "SMS_COMMAND", "mo"),
    "SMS-DELIVER-REPORT": ("sms-tpdu-mo", "TP", "SMS_DELIVER_REPORT_RP_ACK", "mo"),
    "SMS-DELIVER": ("sms-tpdu-mt", "TP", "SMS_DELIVER", "mt"),
    "SMS-SUBMIT-REPORT": ("sms-tpdu-mt", "TP", "SMS_SUBMIT_REPORT_RP_ACK", "mt"),
    "SMS-STATUS-REPORT": ("sms-tpdu-mt", "TP", "SMS_STATUS_REPORT", "mt"),
}

# RP message types carrying a TPDU, by TPDU type (TS 24.011 7.3): RP-DATA MO/MT, RP-ACK MO/MT.
_RP_WRAP = {"SMS-SUBMIT": 0x00, "SMS-COMMAND": 0x00, "SMS-DELIVER": 0x01, "SMS-STATUS-REPORT": 0x01,
            "SMS-DELIVER-REPORT": 0x02, "SMS-SUBMIT-REPORT": 0x03}


class _NotConsulted(Exception):
    pass


@dataclass
class L3Result:
    status: str = "FAIL"
    ours_roundtrip: bool = False
    pycrate_ok: bool = False
    ies_match: bool | None = None
    tshark_clean: bool = False
    tshark_ies: bool | None = None
    tshark_ie_count: int = 0          # IEs tshark marked where ours start, with the same IEI
    field_count: int = 0              # SMS: pycrate elements compared with ours
    epco_count: int = 0               # ePCO units tshark shows where ours start
    notes: list[str] = field(default_factory=list)


@lru_cache(maxsize=None)
def _messages() -> dict[str, dict]:
    lines = [ln for ln in (ROOT / "spec" / "nas" / "24501" / "messages.tsv").open() if not ln.startswith("#")]
    rows = list(csv.DictReader(lines, delimiter="\t"))
    out = {}
    for r in rows:
        out.setdefault(r["message"], r)
        out[f"{r['message']} ({r['key']})"] = r
    return out


def _pycrate():
    from pycrate_mobile import NAS5G, TS23040_SMS as TP, TS24011_PPSMS as PP  # noqa: N814
    return NAS5G, PP, TP


def nas_class(name: str):
    NAS5G, _, _ = _pycrate()
    r = _messages()[name]
    if r["key"] == "8.2.28":
        return None
    table = NAS5G.FGMMTypeClasses if r["protocol"] == "5GMM" else NAS5G.FGSMTypeClasses
    return table[int(r["message_type_hex"], 16)]


def table_max(name: str) -> bytes:
    """Every IE of the Rel-19 table (spec/nas/24501) at its minimum length with
    zero contents: the mandatory part (EPD and message type set), then each
    optional IE in table order. It carries the IEs newer than pycrate, which
    tshark alone checks (KS-NAS-T2)."""
    r = _messages()[name]
    key = r["key"]
    with (ROOT / "spec" / "nas" / "24501" / "message_ies.tsv").open() as f:
        rows = [x for x in csv.DictReader((ln for ln in f if not ln.startswith("#")), delimiter="\t")
                if x["key"] == key]
    out, half, v_seen = bytearray(), None, 0
    epd = 0x7E if r["protocol"] == "5GMM" else 0x2E
    for x in sorted(rows, key=lambda x: int(x["seq"])):
        lo = int(x["length"].replace(" ", "").split("-")[0]) if x["length"].strip() != "1/2" else 0
        fmt, iei = x["format"], x["iei"].strip()
        if not iei:
            if x["length"].strip() == "1/2":
                half = 0 if half is None else None
                if half is None:
                    out.append(0)
                continue
            if fmt == "V":
                val = bytearray(lo)
                if v_seen == 0:
                    val[0] = epd
                elif x["type_name"] == "Message type":
                    val[0] = int(r["message_type_hex"], 16)
                v_seen += 1
                out += val
            elif fmt == "LV":
                out += bytes([lo - 1]) + bytes(lo - 1)
            else:
                out += (lo - 2).to_bytes(2, "big") + bytes(lo - 2)
            continue
        if iei.endswith("-"):
            out.append(int(iei[0], 16) << 4)
        elif fmt == "T":
            out.append(int(iei, 16))
        elif fmt == "TV":
            out += bytes([int(iei, 16)]) + bytes(lo - 1)
        elif fmt == "TLV":
            out += bytes([int(iei, 16), lo - 2]) + bytes(lo - 2)
        else:
            out += bytes([int(iei, 16)]) + (lo - 3).to_bytes(2, "big") + bytes(lo - 3)
    return bytes(out)


def generate(kind: str, name: str, mode: str) -> bytes:
    """pycrate's encoding of a v1 NAS or SMS type: defaults (min) or, for NAS,
    every optional IE on (max). SMS max carries user data where the type has it."""
    NAS5G, PP, TP = _pycrate()
    if kind == "nas" and mode == "table":
        return table_max(name)
    if kind == "nas":
        if name == "SECURITY PROTECTED 5GS NAS MESSAGE":
            inner = generate("nas", "REGISTRATION REQUEST", mode)
            return bytes.fromhex("7e0100000000" + ("00" if mode == "min" else "ff")) + inner
        m = nas_class(name)()
        _fit_mandatory(m, name)
        for e in m._content[1:]:
            v = _VALID_CONTENT.get((name, e._name), _VALID_CONTENT.get(("*", e._name)))
            if v is not None:   # the whole LV or LV-E element, so pycrate sizes V by L
                e.from_bytes((len(v).to_bytes(2 if type(e).__name__ == "Type6LVE" else 1, "big")) + v)
        if mode == "max":
            # every optional IE that pycrate encodes in the format the Rel-19
            # table gives and whose default contents pycrate itself reads back
            table = _table_formats(name)
            for e in m._content:
                if not e.get_trans():
                    continue
                e.set_trans(False)
                if not _agrees_with_table(e, table) or not _pycrate_reads_back(m.to_bytes()):
                    e.set_trans(True)
        data = m.to_bytes()
        _GENERATED[data] = m
        return data
    _, mod, cls, _ = SMS_CLASSES[name]
    obj = getattr(PP if mod == "PP" else TP, cls)()
    data = obj.to_bytes()
    if mode == "max":
        data = _sms_max(name, data)
    return data


# Mandatory IE contents written from the IE clause, by (message or "*", pycrate
# element), where pycrate's default is not a valid value: a type whose
# generated values are its only vectors still gets one tshark reads cleanly.
_VALID_CONTENT = {
    # 9.11.2.10: service-level device ID "ABC" (10), payload type 01 (40), payload 0xABCD (70, type 6)
    ("*", "ServiceLevelAAContainer"): bytes.fromhex("1003414243" "400101" "700002abcd"),
    # 9.11.2.2, an EAP packet (RFC 3748 4): Success; Request/Identity; Response/Identity "user"
    ("AUTHENTICATION RESULT", "EAPMsg"): bytes.fromhex("03010004"),
    ("PDU SESSION AUTHENTICATION COMMAND", "EAPMsg"): bytes.fromhex("0101000501"),
    ("PDU SESSION AUTHENTICATION COMPLETE", "EAPMsg"): bytes.fromhex("020100090175736572"),
}

# The pycrate object behind each generated NAS value, for when pycrate cannot
# read back its own encoding (SERVICE-LEVEL AUTHENTICATION's empty container).
_GENERATED: dict[bytes, object] = {}


@lru_cache(maxsize=None)
def _mandatory_lengths(name: str) -> list[tuple[str, int]]:
    """(format, minimum total octets) of the message's LV and LV-E IEs, in table order."""
    key = _messages()[name]["key"]
    lines = [ln for ln in (ROOT / "spec" / "nas" / "24501" / "message_ies.tsv").open() if not ln.startswith("#")]
    out = []
    for r in csv.DictReader(lines, delimiter="\t"):
        if r["key"] == key and not r["iei"] and r["format"] in ("LV", "LV-E"):
            out.append((r["format"], int(r["length"].split("-")[0])))
    return out


def _fit_mandatory(m, name: str) -> None:
    """Give an LV/LV-E mandatory IE whose pycrate default is shorter than the
    Rel-19 table allows zero octets of the table's minimum length (pycrate's
    default 5GS mobile identity is 4 octets where SERVICE REQUEST's 5G-S-TMSI
    is 7): generated values must be valid at least in their framing."""
    lv = [e for e in m._content[1:] if type(e).__name__ in ("Type4LV", "Type6LVE")]
    for e, (fmt, total) in zip(lv, _mandatory_lengths(name)):
        hdr = 1 if fmt == "LV" else 2
        if len(e.to_bytes()) - hdr >= total - hdr:
            continue
        try:
            e["V"].set_val(bytes(total - hdr))
            e["L"].set_val(total - hdr)
        except Exception:  # noqa: BLE001
            pass


_PYCRATE_FORMAT = {"Type1TV": "TV", "Type2": "T", "Type3TV": "TV", "Type4TLV": "TLV", "Type6TLVE": "TLV-E"}


@lru_cache(maxsize=None)
def _table_formats(name: str) -> dict:
    """IEI (full octet, or the type 1 nibble shifted to bits 8-5) -> format, from the Rel-19 table."""
    key = _messages()[name]["key"]
    lines = [ln for ln in (ROOT / "spec" / "nas" / "24501" / "message_ies.tsv").open() if not ln.startswith("#")]
    out = {}
    for r in csv.DictReader(lines, delimiter="\t"):
        if r["key"] != key or not r["iei"]:
            continue
        t = r["iei"]
        iei = int(t[0], 16) << 4 if t.endswith("-") else int(t, 16)
        out[iei] = r["format"]
    return out


def _agrees_with_table(e, table: dict) -> bool:
    """pycrate's IE has the IEI and format the Rel-19 table gives (pycrate 0.8.1
    lags some: N5GC indication as a type 2 IE with IEI 0x0A, KS-NAS-T3)."""
    cls = type(e).__name__
    names = [c._name for c in e._content] if isinstance(getattr(e, "_content", None), list) else []
    if "T" not in names:
        return True
    iei = e["T"].get_val()
    if cls == "Type1TV":
        iei <<= 4
    return table.get(iei) == _PYCRATE_FORMAT.get(cls)


def _pycrate_reads_back(data: bytes) -> bool:
    import io
    import contextlib
    NAS5G, _, _ = _pycrate()
    with contextlib.redirect_stdout(io.StringIO()):
        m, err = NAS5G.parse_NAS5G(data, inner=False)
    return not err and m.to_bytes() == data


def _sms_max(name: str, base: bytes) -> bytes:
    """A fuller SMS value, written from the TS 24.011 / 23.040 layouts."""
    hello = bytes.fromhex("e8329bfd06")   # "hello" in packed GSM 7-bit
    tpdu = {
        "SMS-SUBMIT": "11" + "2a" + "0b91" + "1032547698f0" + "00" + "00" + "a7" + "05" + hello.hex(),
        "SMS-DELIVER": "04" + "0b91" + "1032547698f0" + "00" + "00" + "62014141423200" + "05" + hello.hex(),
        "SMS-STATUS-REPORT": "06" + "2a" + "0b91" + "1032547698f0" + "62014141423200" + "62014141423200" + "00",
        "SMS-COMMAND": "02" + "2a" + "00" + "01" + "2a" + "0b91" + "1032547698f0" + "00",
        "SMS-DELIVER-REPORT": "00" + "07" + "00" + "00" + "05" + hello.hex(),
        "SMS-SUBMIT-REPORT": "01" + "07" + "62014141423200" + "00" + "00" + "05" + hello.hex(),
    }
    if name in tpdu:
        return bytes.fromhex(tpdu[name])
    if name == "CP-DATA":
        rp = _sms_max("RP-DATA", b"")
        return bytes([0x09, 0x01, len(rp)]) + rp
    if name == "CP-ERROR":
        return bytes.fromhex("091051")
    if name == "RP-DATA":
        t = bytes.fromhex(tpdu["SMS-SUBMIT"])
        return bytes([0x00, 0x2a, 0x00, 0x07, 0x91]) + bytes.fromhex("448720010010") + bytes([len(t)]) + t
    if name == "RP-ACK":
        t = bytes.fromhex(tpdu["SMS-DELIVER-REPORT"])
        return bytes([0x02, 0x2a, 0x41, len(t)]) + t
    if name == "RP-ERROR":
        return bytes([0x04, 0x2a, 0x01, 0x6f])
    return base


def _nas_pycrate_ies(m) -> list[tuple]:
    """(iei or None, value) for each present element after the header; half-octet
    values as ints, the rest as the octets after IEI and length."""
    out = []
    for e in m._content[1:]:
        if e.get_trans():
            continue
        cls = type(e).__name__
        names = [c._name for c in e._content] if isinstance(getattr(e, "_content", None), list) else []
        if "spare" in e._name.lower():
            continue
        if cls == "Type1V":
            out.append((None, e.to_uint()))
            continue
        if cls == "Type1TV":
            u = e.to_uint()
            out.append((u & 0xF0, u & 0x0F))
            continue
        b = e.to_bytes()
        iei = e["T"].get_val() if "T" in names else None
        hdr = (1 if iei is not None else 0) + (1 if cls.startswith("Type4") else 2 if cls.startswith("Type6") else 0)
        out.append((iei, b[hdr:]))
    return out


def _nas_ours_ies(j: dict) -> list[tuple]:
    out = []
    ies = j.get("ies", [])
    for ie in ies[4:]:   # the header rows: EPD, then SHT and spare or PDU session ID and PTI, then type
        if "unknown" in ie:
            out.append(("unknown", bytes.fromhex(ie["unknown"])))
            continue
        if ie["ie"].lower().startswith("spare"):
            continue
        v = bytes.fromhex(ie["value"])
        iei = ie["iei"] or None
        if iei is not None and iei >= 0x80 and len(v) == 1 and v[0] < 16:
            out.append((iei & 0xF0, v[0]))      # type 1 TV: IEI nibble, value nibble
        elif ie.get("half", False):
            out.append((None, v[0]))
        else:
            out.append((iei, v))
    return out


def _sms_expected(j: dict) -> dict:
    """pycrate SMS element name -> the octets our decode says it holds."""
    h = bytes.fromhex
    if j["layer"] == "CP":
        e = {"CPHeader": bytes([(j["ti"] << 4) | 0x9, j["type"]])}
        if "user_data" in j:
            e["CPUserData"] = bytes([len(h(j["user_data"]))]) + h(j["user_data"])
        if "cause" in j:
            e["CPCause"] = bytes([j["cause"]])
        return e
    if j["layer"] == "RP":
        e = {"Ref": bytes([j["mr"]]), "MTI": j["mti"]}
        if j["mti"] in (0, 1):
            for k, n in (("originator", "RPOriginatorAddress"), ("destination", "RPDestinationAddress")):
                e[n] = bytes([len(h(j[k]))]) + h(j[k])
        if j["cause"]:
            e["RPCause"] = bytes([len(h(j["cause"]))]) + h(j["cause"])
        if "user_data" in j:
            ud = h(j["user_data"])
            e["RPUserData"] = (bytes([len(ud)]) if j["mti"] in (0, 1) else bytes([0x41, len(ud)])) + ud
        return e
    addr = bytes([j["address_len"], j["toa"]]) + h(j["address"])
    e = {"TP_MTI": j["first"] & 0x03, "TP_DA": addr, "TP_OA": addr, "TP_RA": addr, "TP_MR": bytes([j["mr"]]),
         "TP_SCTS": h(j["scts"]), "TP_DT": h(j["dt"]), "TP_ST": bytes([j["st"]]), "TP_VP": h(j["vp"]),
         "TP_CT": bytes([j["ct"]]), "TP_MN": bytes([j["mn"]])}
    if j["has_pid"]:
        e["TP_PID"] = bytes([j["pid"]])
    if j["has_dcs"]:
        e["TP_DCS"] = bytes([j["dcs"]])
    if j["has_ud"] or j["type"] in ("SMS-SUBMIT", "SMS-DELIVER", "SMS-COMMAND"):
        e["TP_UD"] = e["TP_CD"] = bytes([j["udl"]]) + h(j["ud"])
    if "fcs" in j:
        e["TP_FCS"] = bytes([j["fcs"]])
    if "pi" in j:
        e["TP_PI"] = bytes([j["pi"]])
    return e


def _sms_fields_agree(obj, ours: dict) -> tuple[bool, str, int]:
    """Each present octet-aligned pycrate element (and the MTI bit field) holds what ours says."""
    want = _sms_expected(ours)
    n = 0
    for x in obj._content:
        if x.get_trans() or x._name not in want:
            continue
        got = x.get_val() if x._name in ("MTI", "TP_MTI") else x.to_bytes()
        if got != want[x._name]:
            w = want[x._name]
            return False, (f"{x._name}: pycrate {got if isinstance(got, int) else got.hex()}, "
                           f"ours {w if isinstance(w, int) else w.hex()}"), n
        n += 1
    return True, "", n


def _normalize(ies: list[tuple]) -> list[tuple]:
    """Half-octet values as one-octet strings; each run of consecutive half-octet
    mandatory values sorted (pycrate lists the high nibble first, the tables the
    low nibble first)."""
    out, run = [], []
    for iei, v in ies + [("end", b"")]:
        if iei is None and isinstance(v, int):
            run.append((None, bytes([v])))
            continue
        out += sorted(run)
        run = []
        if iei != "end":
            out.append((iei, bytes([v]) if isinstance(v, int) else v))
    return out


def _tshark_ies_agree(pkt, ours: dict) -> tuple[bool, str, int]:
    """Each IE tshark marks with an element ID (nas-5gs.mm/sm.elem_id) at the top
    level of the message starts where one of ours starts, with the same IEI.
    Elements inside one of our IEs (a NAS message or payload container) are the
    inner message's and are skipped."""
    starts = [lf.pos for lf in pkt.leaves if lf.name == "nas-5gs.epd" and lf.pos >= 0]
    if not starts:
        return True, "", 0
    base = starts[0]
    at = {ie["at"]: ie.get("iei", 0) for ie in ours["ies"] if "at" in ie}
    marks = sorted(set(at)) + [1 << 30]
    spans = list(zip(marks, marks[1:]))   # each IE runs to where the next starts
    matched = 0
    for lf in pkt.leaves:
        if lf.name not in ("nas-5gs.mm.elem_id", "nas-5gs.sm.elem_id") or lf.pos < 0:
            continue
        off = lf.pos - base
        if off in at:
            t = int(lf.show, 16) if lf.show.startswith("0x") else int(lf.show)
            if t != at[off] and (t << 4) != (at[off] & 0xF0) and t != (at[off] & 0xF0):
                return False, f"tshark IE 0x{t:02x} at octet {off}, ours 0x{at[off]:02x}", matched
            matched += 1
            continue
        if not any(a < off < b for a, b in spans):
            return False, f"tshark IE {lf.show} at octet {off}, where none of ours starts", matched
    return True, "", matched


def _tshark_epco_agree(pkt, ours: dict) -> tuple[bool, str, int]:
    """Each ePCO unit tshark shows (gsm_a.gm.sm.pco_pid and its pco.length) inside
    one of our top-level ePCO IEs starts where one of our units starts, with the
    same identifier and length; and where tshark found nothing wrong, it shows
    every unit of ours."""
    starts = [lf.pos for lf in pkt.leaves if lf.name == "nas-5gs.epd" and lf.pos >= 0]
    if not starts:
        return True, "", 0
    base = starts[0]
    units, spans = {}, []
    for ie in ours["ies"]:
        if "epco_error" in ie:
            return False, f"our ePCO decode failed: {ie['epco_error']}", 0
        if "epco" in ie:
            spans.append((ie["at"], ie["at"] + 3 + len(ie["value"]) // 2))
            units.update({u["at"]: u for u in ie["epco"]})
    if not spans:
        return True, "", 0
    leaves = pkt.leaves
    seen = 0
    for i, lf in enumerate(leaves):
        if lf.name != "gsm_a.gm.sm.pco_pid" or lf.pos < 0:
            continue
        off = lf.pos - base
        if not any(a <= off < b for a, b in spans):
            continue
        u = units.get(off)
        pid = int(lf.show, 16)
        if u is None or u["id"] != pid:
            return False, f"tshark ePCO unit {pid:04x} at octet {off}, ours {u and hex(u['id'])}", seen
        ln = next((x for x in leaves[i + 1:] if x.name == "gsm_a.gm.sm.pco.length"), None)
        if ln is not None and int(ln.show, 16) != u["len"]:
            return False, f"ePCO unit {pid:04x}: tshark length {int(ln.show, 16)}, ours {u['len']}", seen
        seen += 1
    if seen != len(units) and not tshark.errors(pkt):
        return False, f"tshark shows {seen} ePCO units, ours {len(units)}", seen
    return True, "", seen


def _tshark_layer(kind: str, name: str, data: bytes) -> tuple[str, bytes]:
    if kind == "nas":
        return "nas-5gs", data
    if kind == "sms-cp":
        return "gsm_a_dtap", data
    if kind == "sms-rp":
        return "gsm_a_rp", data
    mti = _RP_WRAP[name]
    if mti in (0x00, 0x01):   # RP-DATA: originator, destination (one of them the SC address), user data
        sc = bytes.fromhex("0791448720010010")
        oa, da = (b"\x00", sc) if mti == 0x00 else (sc, b"\x00")
        return "gsm_a_rp", bytes([mti, 0x2a]) + oa + da + bytes([len(data)]) + data
    return "gsm_a_rp", bytes([mti, 0x2a, 0x41, len(data)]) + data


def check(codec: Codec, kind: str, name: str, data: bytes, generated: bool, use_pycrate: bool = True) -> L3Result:
    """use_pycrate=False for table-max values: their newer IEs are not pycrate's (KS-NAS-T2)."""
    r = L3Result()
    import json
    NAS5G, PP, TP = _pycrate()
    a = codec._ask("dec", kind, "-", data.hex())
    ours = None
    if not a.ok:
        r.notes.append(f"ours {a.stage}: {a.error[:160]}")
    else:
        r.ours_roundtrip = a.data == data
        if not r.ours_roundtrip:
            r.notes.append(f"our re-encode differs: {a.hex[:60]}")
        ours = json.loads(a.jer)
    # pycrate
    try:
        if not use_pycrate:
            raise _NotConsulted
        if kind == "nas":
            m, err = NAS5G.parse_NAS5G(data, inner=False)
            if err:
                raise ValueError(f"parse_NAS5G error {err}")
            again = m.to_bytes()
        else:
            _, mod, cls, _ = SMS_CLASSES[name]
            m = getattr(PP if mod == "PP" else TP, cls)()
            m.from_bytes(data)
            again = m.to_bytes()
        r.pycrate_ok = again == data
        if not r.pycrate_ok:
            r.notes.append(f"pycrate re-encode differs: {again.hex()[:60]}")
        if kind != "nas" and ours is not None:
            r.ies_match, why, r.field_count = _sms_fields_agree(m, ours)
            if not r.ies_match:
                r.notes.append("fields differ: " + why)
        if kind == "nas" and ours is not None and "ies" in ours:
            theirs = _normalize(_nas_pycrate_ies(m))
            mine = _normalize(_nas_ours_ies(ours))
            r.ies_match = theirs == mine
            if not r.ies_match:
                r.notes.append(f"IEs differ: ours {[(i, v.hex()) for i, v in mine][:6]} "
                               f"pycrate {[(i, v.hex()) for i, v in theirs][:6]}")
    except _NotConsulted:
        r.pycrate_ok = True
        r.notes.append("pycrate not consulted (a table-max value: IEs newer than pycrate 0.8.1)")
    except Exception as e:  # noqa: BLE001
        r.notes.append(f"pycrate: {type(e).__name__}: {str(e)[:160]}")
    lag = False
    if kind == "nas" and generated and not r.pycrate_ok and data in _GENERATED and ours is not None:
        # pycrate cannot read back its own value: compare with the object it was made from
        mine = _normalize(_nas_ours_ies(ours))
        theirs = _normalize(_nas_pycrate_ies(_GENERATED[data]))
        r.ies_match = mine == theirs
        lag = r.ies_match and r.ours_roundtrip
        r.notes.append("oracle-lag: pycrate cannot read back its own encoding; ours matches the value it encoded"
                       if lag else "IEs differ from the value pycrate encoded")
    # tshark
    layer, framed = _tshark_layer(kind, name, data)
    pkt = tshark.decode(pcap.exported_pdu([(layer, framed)]))[0]
    errs = tshark.errors(pkt)
    r.tshark_clean = not errs
    for e in sorted(set(errs)):
        r.notes.append(("generated-content: " if generated else "tshark: ") + e)
    if kind == "nas" and ours is not None and "ies" in ours:
        r.tshark_ies, why, r.tshark_ie_count = _tshark_ies_agree(pkt, ours)
        if not r.tshark_ies:
            r.notes.append(why)
        epco_ok, why, r.epco_count = _tshark_epco_agree(pkt, ours)
        if not epco_ok:
            r.tshark_ies = False
            r.notes.append(why)
    # A NAS message container (IEI 0x71) in REGISTRATION or SERVICE REQUEST holds
    # the whole message ciphered (TS 24.501 4.4.6); tshark reads it as a NAS PDU.
    ciphered = ours is not None and any(
        ie.get("iei") == 0x71 and ie.get("value", "")[:2] not in ("7e", "2e", "") for ie in ours.get("ies", []))
    if errs and ciphered and not generated and all(e.startswith("Not a NAS 5GS PD") for e in errs):
        r.notes = [n for n in r.notes if not n.startswith(("tshark: ", "generated-content: "))]
        r.notes.append("ciphered-container: tshark reads the ciphered NAS message container as a NAS PDU")
        errs = []
        r.status = "CIPHERED_CONTAINER"
    ok = r.ours_roundtrip and r.pycrate_ok and r.ies_match is not False and r.tshark_ies is not False
    if r.status == "CIPHERED_CONTAINER" and ok:
        return r
    if lag:
        r.status = "ORACLE_LAG"
    elif not ok:
        r.status = "FAIL"
    elif not errs:
        r.status = "PASS"
    else:
        r.status = "GENERATED_CONTENT" if generated else "FAIL"
    return r


def selftest(codec: Codec) -> list[tuple[str, bool]]:
    """Must-fail cases: each mutation has to be caught. (name, caught)."""
    import json
    out = []
    reg = generate("nas", "REGISTRATION REQUEST", "max")
    a = codec._ask("dec", "nas", "-", reg.hex())
    ours = json.loads(a.jer)
    tlv = next(ie for ie in ours["ies"] if ie.get("iei", 0) and ie["iei"] < 0x80 and len(ie["value"]) >= 2
               and ie["iei"] not in (0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C,
                                     0x7D, 0x7E, 0x7F))
    bad = bytearray(reg)
    bad[tlv["at"] + 1] += 1          # a TLV length one too long: the rest of the message shifts
    out.append(("nas: a TLV length one octet too long", check(codec, "nas", "REGISTRATION REQUEST", bytes(bad),
                                                              True).status == "FAIL"))
    pkt = tshark.decode(pcap.exported_pdu([("nas-5gs", reg)]))[0]
    shifted = {"ies": [{**ie, "at": ie["at"] + 1} for ie in ours["ies"]]}
    out.append(("nas: our IE offsets one octet off against tshark", not _tshark_ies_agree(pkt, shifted)[0]))
    out.append(("nas: tshark IE positions checked at all", _tshark_ies_agree(pkt, ours)[2] >= 5))
    NAS5G, _, _ = _pycrate()
    m, _ = NAS5G.parse_NAS5G(reg, inner=False)
    changed = {"ies": [dict(ie) for ie in ours["ies"]]}
    tgt = next(ie for ie in changed["ies"][4:] if ie.get("iei") and len(ie.get("value", "")) >= 2)
    tgt["value"] = ("%02x" % (int(tgt["value"][:2], 16) ^ 1)) + tgt["value"][2:]
    out.append(("nas: one IE value differing from pycrate's",
                _normalize(_nas_ours_ies(changed)) != _normalize(_nas_pycrate_ies(m))))
    # ePCO (UE to network): IPCP, then 0023H, whose length is one octet in this
    # direction though "two octets" is in its name; reading it as two must be caught
    pdu = bytes.fromhex("2e0114c1ffff917b000e80" "80210410010000" "002300" "000d00")
    a = codec._ask("dec", "nas", "-", pdu.hex())
    good = json.loads(a.jer)
    pkt = tshark.decode(pcap.exported_pdu([("nas-5gs", pdu)]))[0]
    out.append(("nas: ePCO units compared at all", _tshark_epco_agree(pkt, good)[2] == 3))
    wrong = json.loads(a.jer)
    for ie in wrong["ies"]:
        if "epco" in ie:
            ie["epco"] = [u for u in ie["epco"] if u["id"] != 0x0D]   # as if 0023H had swallowed 000DH
    out.append(("nas: an ePCO unit length read with the wrong size", not _tshark_epco_agree(pkt, wrong)[0]))
    sub0 = generate("sms-tpdu-mo", "SMS-SUBMIT", "max")
    j = json.loads(codec._ask("dec", "sms-tpdu-mo", "-", sub0.hex()).jer)
    o = _pycrate()[2].SMS_SUBMIT()
    o.from_bytes(sub0)
    out.append(("sms: TP fields compared at all", _sms_fields_agree(o, j)[2] >= 6))
    out.append(("sms: one TP field differing from pycrate's", not _sms_fields_agree(o, {**j, "mr": j["mr"] ^ 1})[0]))
    sub = bytearray(sub0)
    sub[-6] += 3                      # TP-UDL: three septets more than TP-UD holds
    out.append(("sms: TP-UDL beyond the user data", check(codec, "sms-tpdu-mo", "SMS-SUBMIT", bytes(sub),
                                                          False).status == "FAIL"))
    rp = bytearray(generate("sms-rp", "RP-DATA", "max"))
    rp[2] = 0x05                      # RP-Originator Address length past its contents
    out.append(("sms: an RP address length out of step", check(codec, "sms-rp", "RP-DATA", bytes(rp),
                                                               False).status == "FAIL"))
    return out
