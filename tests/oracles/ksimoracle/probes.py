# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The M10 probes: values at the edges of the constructs that break PER codecs.

Each probe is a type and a list of values. pycrate encodes each value; asn1c
(through ksim-codec) must decode the octets, re-encode them byte for byte,
write JER that is the JER of pycrate's value, and encode that JER back to the
same octets. A value outside the type (the 257th list item) must be refused by
both. One probe goes through tshark too (lengths of 16K and more, in a PDU).
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field

from . import asn, jer, pcap, roundtrip, tshark
from .codec import Codec
from .valuegen import Gen


@dataclass
class Probe:
    name: str
    proto: str
    type_name: str
    values: list
    reject: list = field(default_factory=list)   # values both must refuse


def _rrc_max(name: str):
    return Gen("max").value(jer._types("rrc")[name])


def _ta_list(n: int):
    item = Gen("min").value(jer._types("ngap")["SupportedTAItem"])
    return [copy.deepcopy(item) for _ in range(n)]


def probes() -> list[Probe]:
    return [
        Probe("integer-extensible (root, then additions)", "ngap", "MaximumDataBurstVolume", [0, 4095, 4096, 2000000]),
        Probe("integer-extensible, 16-bit root", "ngap", "ExtendedPacketDelayBudget", [1, 65535, 65536, 109999]),
        Probe("integer union of values, 8-bit root below 256", "ngap", "ExpectedActivityPeriod", [1, 30, 40, 181, 182]),
        Probe("integer-negative-lower-bound, 8 bits", "ngap", "N6JitterInformation",
              [{"n6JitterLowerBound": -127, "n6JitterUpperBound": 127},
               {"n6JitterLowerBound": 0, "n6JitterUpperBound": -1}]),
        Probe("integer-range-over-2^32 (BitRate)", "ngap", "BitRate",
              [0, 2**32 - 1, 2**32, 2**32 + 1, 4000000000000, 4000000000001]),
        Probe("integer-range to 2^64-1 (usage counts)", "e1ap", "DRB-Usage-Report-Item",
              [{"startTimeStamp": bytes(4), "endTimeStamp": bytes(4), "usageCountUL": u, "usageCountDL": u}
               for u in (0, 2**32, 2**63 - 1, 2**63, 2**64 - 1)]),
        Probe("length 16K and more (fragmentation)", "ngap", "NAS-PDU",
              [bytes(n) for n in (16383, 16384, 16385, 32768, 49152, 65535, 65536, 65537, 131072, 200000)]),
        Probe("[[ ]] in a CHOICE (RRC)", "rrc", "RLF-Report-r16", [_rrc_max("RLF-Report-r16")]),
        Probe("extensible ENUMERATED (root, additions)", "rrc", "CA-BandwidthClassNR", ["a", "q", "r2-v1730"]),
        Probe("SEQUENCE OF at its bounds (1..maxnoofTACs)", "ngap", "SupportedTAList",
              [_ta_list(1), _ta_list(256)], reject=[_ta_list(257)]),
        Probe("APER PrintableString (SIZE(1..150, ...))", "ngap", "RANNodeName",
              ["a", "gnb1", "z" * 150, "z" * 151]),
    ]


def _enc(proto: str) -> str:
    return "uper" if proto == "rrc" else "aper"


def check_value(codec: Codec, p: Probe, value) -> str:
    """'' if pycrate and asn1c agree on the value both ways, else what differs."""
    o = jer._types(p.proto)[p.type_name]
    data = asn.encode(o, value, _enc(p.proto))
    a = codec.dec(p.proto, p.type_name, data)
    if not a.ok:
        return f"asn1c {a.stage}: {a.error[:120]}"
    if a.data != data:
        return f"asn1c re-encodes differently ({a.hex[:40]} vs {data.hex()[:40]})"
    o.set_val(value)
    want = jer.to_asn1c(p.proto, o, json.loads(o.to_jer()), value)
    got = json.loads(a.jer)
    if jer.normalize(got) != want:
        return "asn1c's JER is not the JER of pycrate's value"
    b = codec.enc(p.proto, p.type_name, a.jer)
    if not b.ok or b.data != data:
        return f"asn1c encodes its JER differently: {b.stage} {b.error[:80]}"
    return ""


def check_reject(codec: Codec, p: Probe, value) -> str:
    """'' if both refuse the value."""
    o = jer._types(p.proto)[p.type_name]
    try:
        asn.encode(o, value, _enc(p.proto))
        return "pycrate encoded it"
    except Exception:  # noqa: BLE001
        pass
    o2 = jer._types(p.proto)[p.type_name]
    # asn1c from the JER of the value, written as asn1c writes it
    items = [jer.to_asn1c(p.proto, o2._cont, json.loads(_item_jer(o2, v)), v) for v in value]
    b = codec.enc(p.proto, p.type_name, json.dumps(items, separators=(",", ":")))
    return "" if not b.ok else "asn1c encoded it"


def _item_jer(o, v) -> str:
    o._cont.set_val(v)
    return o._cont.to_jer()


def fragmented_pdu(codec: Codec, n: int) -> str:
    """A DownlinkNASTransport whose NAS-PDU is n octets: asn1c, pycrate and tshark."""
    value, _ = roundtrip.generate("ngap", "DownlinkNASTransport", "min")
    v = copy.deepcopy(value)
    for ie in v[1]["value"][1]["protocolIEs"]:
        if ie["id"] == 38:
            ie["value"] = ("NAS-PDU", b"\x7e\x00\x46" + bytes(n - 3))
    o, enc, top, _ = roundtrip.target("ngap", "DownlinkNASTransport")
    data = asn.encode(o, v, enc)
    r = roundtrip.check(codec, "ngap", "DownlinkNASTransport", data, v, generated=True)
    if r.status != "PASS":
        return f"{r.status}: {'; '.join(r.notes)[:160]}"
    pkt = tshark.decode(pcap.exported_pdu([("ngap", data)]))[0]
    return "" if not tshark.errors(pkt) else "tshark complains"


def run(codec: Codec) -> list[tuple[str, int, int, list[str]]]:
    """(probe, values, passed, failures) for every probe."""
    out = []
    for p in probes():
        fails = []
        for v in p.values:
            why = check_value(codec, p, v)
            if why:
                fails.append(f"{repr(v)[:40]}: {why}")
        for v in p.reject:
            why = check_reject(codec, p, v)
            if why:
                fails.append(f"reject {repr(v)[:40]}: {why}")
        n = len(p.values) + len(p.reject)
        out.append((p.name, n, n - len(fails), fails))
    fails = [why for n in (16384, 65537, 200000) if (why := fragmented_pdu(codec, n))]
    out.append(("length 16K and more, in a PDU, through tshark", 3, 3 - len(fails), fails))
    return out
