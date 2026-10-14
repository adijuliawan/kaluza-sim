# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Verdicts: does an encoding carry the value it was meant to carry, according
to two decoders that are not ours?

check() takes the bytes and the intended value (as pycrate understands it) and
produces:
  pycrate   decode, re-encode byte-identical, and decoded value == intended value
  tshark    no malformed packet and no expert error or warning, after the
            classification below
  status    PASS | ORACLE_LAG | NESTED_FILLER | FAIL

Classification. These are recorded, never silently dropped:
  ORACLE_LAG     tshark's ASN.1 is older than Rel-19. Either its size/value bound
                 is narrower than the one pycrate accepted from our Rel-19 text
                 ("Size constraint: value too big: N (lo .. hi)"), or it does not
                 know an IE id ("something unknown here") and the message carries
                 an id that the derived list says tshark lacks.
  NESTED_FILLER  a generated message carries filler bytes in a container that
                 tshark dissects further (an RRC container inside F1AP, a NAS-PDU
                 inside NGAP), and the nested dissector throws. Generated values
                 only: a real vector gets no such allowance.
A bit flipped or a field written with the wrong width changes the decoded value,
so the value comparison catches it even when both decoders accept the bytes.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from . import asn, pcap, tshark

ROOT = asn.ROOT

TSHARK_PROTO = {"ngap": "ngap", "f1ap": "f1ap", "e1ap": "e1ap", "xnap": "xnap"}
_BOUND = re.compile(r"^Size constraint: (value too (big|small)|too (many|few) items): (-?\d+) "
                    r"\((-?\d+) \.\. (-?\d+)\)")
_UNKNOWN = re.compile(r"^something unknown here")
_NESTED = re.compile(r"^(Malformed Packet \(Exception occurred\)|Open type length\(|PDCP signalling header|"
                     r"malformed packet)")


@dataclass
class Verdict:
    status: str
    pycrate_roundtrip: bool = False
    pycrate_value_match: bool = False
    tshark_clean: bool = False
    notes: list[str] = field(default_factory=list)


@lru_cache(maxsize=None)
def tshark_known_ie_ids(proto: str) -> frozenset[int]:
    out = subprocess.run(["tshark", "-G", "values"], capture_output=True, text=True).stdout
    ids = set()
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) >= 4 and f[0] == "V" and f[1] == f"{proto}.id":
            ids.add(int(f[2]))
    return frozenset(ids)


@lru_cache(maxsize=None)
def spec_ie_ids(proto: str) -> dict[int, str]:
    text = next((ROOT / "spec" / "asn1" / proto).glob("*-Constants.asn")).read_text()
    return {int(n): name for name, n in re.findall(r"^\s*(id-[\w-]+)\s+ProtocolIE-ID\s*::=\s*(\d+)", text, re.M)}


def unknown_to_tshark(proto: str) -> dict[int, str]:
    """Rel-19 IE ids tshark's dissector has no name for (a derived allowlist)."""
    known = tshark_known_ie_ids(proto)
    return {i: n for i, n in spec_ie_ids(proto).items() if i not in known}


def _ie_ids(value) -> set[int]:
    """Every protocol IE / extension id inside a pycrate value of an AP PDU."""
    ids: set[int] = set()

    def walk(v):
        if isinstance(v, dict):
            if "id" in v and isinstance(v["id"], int) and ("value" in v or "extensionValue" in v):
                ids.add(v["id"])
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)

    walk(value)
    return ids


def canonical_jer(o, value) -> str:
    o.set_val(value)
    return json.dumps(json.loads(o.to_jer()), sort_keys=True)


def check_ap(proto: str, data: bytes, intended, generated: bool = False) -> Verdict:
    o, enc = asn.top(proto)
    v = Verdict("FAIL")
    want = canonical_jer(o, intended)
    try:
        asn.decode(o, data, enc)
        again = o.to_aper() if enc == "aper" else o.to_uper()
        v.pycrate_roundtrip = again == data
        got = json.dumps(json.loads(o.to_jer()), sort_keys=True)
        v.pycrate_value_match = got == want
        if not v.pycrate_roundtrip:
            v.notes.append(f"pycrate re-encode differs: {again.hex()[:80]}")
        if not v.pycrate_value_match:
            v.notes.append("pycrate decodes a different value than intended")
    except Exception as e:  # noqa: BLE001
        v.notes.append(f"pycrate decode: {type(e).__name__}: {str(e)[:160]}")
    pkt = tshark.decode(pcap.exported_pdu([(TSHARK_PROTO[proto], data)]))[0]
    errs = tshark.errors(pkt)
    lag, nested, other = [], [], []
    unknown = unknown_to_tshark(proto)
    carried_unknown = sorted(_ie_ids(intended) & set(unknown))
    for e in errs:
        if _BOUND.match(e) and v.pycrate_value_match:
            lag.append(e)
        elif _UNKNOWN.match(e) and carried_unknown:
            lag.append(f"{e} (carries ids unknown to tshark: {carried_unknown[:6]})")
        elif _NESTED.match(e) and generated:
            nested.append(e)
        else:
            other.append(e)
    v.tshark_clean = not errs
    for kind, items in (("oracle-lag", lag), ("nested-filler", nested), ("tshark", other)):
        for text, n in sorted({t: items.count(t) for t in items}.items()):
            v.notes.append(f"{kind}: {text}" + (f" (x{n})" if n > 1 else ""))
    pycrate_ok = v.pycrate_roundtrip and v.pycrate_value_match
    if pycrate_ok and not errs:
        v.status = "PASS"
    elif pycrate_ok and not other and lag and not nested:
        v.status = "ORACLE_LAG"
    elif pycrate_ok and not other and nested:
        v.status = "NESTED_FILLER"
    return v
