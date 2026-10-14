# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The M10 check for one encoding of one type: our asn1c codec against pycrate
and tshark.

    asn1c   decodes the octets and re-encodes them byte for byte;
    JER     pycrate reads asn1c's JER and gets the value it decodes from the
            octets itself (a schema-aware comparison, no text normalising);
    pycrate decodes and re-encodes the octets, and tshark finds nothing wrong
            (compare.check_pdu, with its oracle-lag and nested-filler classes);
    agree   for generated values: asn1c encodes pycrate's JER of the value into
            exactly pycrate's octets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import asn, compare, jer, rrc
from .codec import Codec

AP_TOP = {"ngap": "NGAP-PDU", "f1ap": "F1AP-PDU", "e1ap": "E1AP-PDU", "xnap": "XnAP-PDU"}


@dataclass
class Result:
    status: str = "FAIL"                 # PASS, ORACLE_LAG, NESTED_FILLER or FAIL
    asn1c_roundtrip: bool = False
    jer_match: bool = False
    pycrate_ok: bool = False
    tshark_clean: bool = False
    encoders_agree: bool | None = None   # generated values only
    notes: list[str] = field(default_factory=list)


def target(proto: str, pdu: str):
    """(pycrate top object, encoding, top type name, tshark dissector) for a v1 type."""
    if proto == "rrc":
        pl = rrc.place(pdu)
        return rrc.obj(pl.top), "uper", pl.top, pl.dissector
    o, enc = asn.top(proto)
    return o, enc, AP_TOP[proto], compare.TSHARK_PROTO[proto]


def _first_diff(a, b, path: str = "") -> str:
    """Where two JSON values first differ, for the report."""
    if type(a) is not type(b):
        return f"{path or '/'}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    if isinstance(a, dict):
        for k in list(dict.fromkeys(list(a) + list(b))):
            if k not in a or k not in b:
                return f"{path}/{k}: only in {'asn1c' if k in a else 'expected'}"
            if a[k] != b[k]:
                return _first_diff(a[k], b[k], f"{path}/{k}")
        if list(a) != list(b):
            return f"{path or '/'}: member order {list(a)[:4]} vs {list(b)[:4]}"
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path or '/'}: {len(a)} items vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return _first_diff(x, y, f"{path}[{i}]")
    return f"{path or '/'}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"


def check(codec: Codec, proto: str, pdu: str, data: bytes, intended=None, generated: bool = False) -> Result:
    o, enc, top, dissector = target(proto, pdu)
    r = Result()
    if intended is None:                         # a corpus vector: the value is what pycrate reads
        try:
            intended = asn.decode(o, data, enc)
        except Exception as e:  # noqa: BLE001
            r.notes.append(f"pycrate cannot decode: {type(e).__name__}: {str(e)[:160]}")
            intended = None
    if intended is not None:
        v = compare.check_pdu(proto, o, enc, dissector, data, intended, generated)
        r.pycrate_ok = v.pycrate_roundtrip and v.pycrate_value_match
        r.tshark_clean = v.tshark_clean
        r.notes += v.notes
        m8_status = v.status
    else:
        m8_status = "FAIL"

    asn1c_jer = None
    a = codec.dec(proto, top, data)
    if not a.ok:
        r.notes.append(f"asn1c {a.stage}: {a.error[:200]}")
    else:
        r.asn1c_roundtrip = a.data == data
        if not r.asn1c_roundtrip:
            r.notes.append(f"asn1c re-encode differs: {a.hex[:80]}")
        if intended is not None:
            try:
                o.set_val(intended)
                want = jer.to_asn1c(proto, o, json.loads(o.to_jer()), intended)
                got = json.loads(a.jer)
                r.jer_match = jer.normalize(got) == want
                asn1c_jer = got if r.jer_match else want
                if not r.jer_match:
                    r.notes.append("asn1c's JER is not the JER of pycrate's value: "
                                   + _first_diff(jer.normalize(got), want))
            except Exception as e:  # noqa: BLE001
                r.notes.append(f"JER comparison: {type(e).__name__}: {str(e)[:160]}")

    if generated and intended is not None:
        # asn1c's own JER once it is proven equal to pycrate's value (inline-type
        # keys are spelled as asn1c prints them); else the prediction.
        if asn1c_jer is None:
            o.set_val(intended)
            asn1c_jer = jer.to_asn1c(proto, o, json.loads(o.to_jer()), intended)
        b = codec.enc(proto, top, json.dumps(asn1c_jer, separators=(",", ":")))
        r.encoders_agree = b.ok and b.data == data
        if not b.ok:
            r.notes.append(f"asn1c from pycrate's JER, {b.stage}: {b.error[:200]}")
        elif b.data != data:
            r.notes.append(f"asn1c encodes pycrate's JER differently: {b.hex[:80]}")

    ours_ok = r.asn1c_roundtrip and r.jer_match and r.encoders_agree is not False
    r.status = m8_status if ours_ok and m8_status != "FAIL" else "FAIL"
    if (r.status == "FAIL" and generated and ours_ok and r.encoders_agree and not r.pycrate_ok
            and any(n.startswith("pycrate decode:") for n in r.notes)
            and not any(n.startswith("tshark:") for n in r.notes)):
        # pycrate cannot read back its own encoding, which asn1c reads and
        # re-encodes exactly, from which it gets the intended value, and which
        # tshark reads without complaint: a pycrate decoder defect (KS-PLAT-T16).
        r.status = "ORACLE_LAG"
        r.notes.append("oracle-lag: pycrate cannot decode its own encoding; asn1c and tshark read it")
    return r


def generate(proto: str, pdu: str, mode: str):
    """A generated value of a v1 type and pycrate's octets for it."""
    from .valuegen import Gen
    o, enc, _, _ = target(proto, pdu)
    if proto == "rrc":
        pl = rrc.place(pdu)
        inner = Gen(mode).value(rrc.obj(pdu)) if pl.path else Gen(mode).value(o)
        value = rrc.wrap(pl, inner) if pl.path else inner
    else:
        value = Gen(mode).procedure_message(o, pdu)
    return value, asn.encode(o, value, enc)
