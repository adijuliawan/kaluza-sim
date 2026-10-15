#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Redacts an interop peer's own captures (P2 Q4; ADR 0012): the peer writes
NGAP and E1AP in clear, K_gNB in the Security Key IE (TS 38.413 9.3.1.87) and
the UP keys in the Security Information IE (TS 37.483 9.3.1.31), as our own
captures never do (rule R3; the canary's rows).

    .venv/bin/python -I tools/peer_redact.py <peer dir>

Every *.pcap in the directory whose frames are exported PDUs (link type 252)
is read; each NGAP and E1AP PDU is decoded with pycrate, its key material
zeroed (the Security Key, the Next Hop NH, the UP encryption and integrity
keys) and re-encoded in place. A PDU pycrate cannot decode is zeroed whole,
since what it holds is not known. Prints PEER_REDACTED=<fields> and
PEER_PDUS_ZEROED=<n>, and exits non-zero when a file cannot be rewritten.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "oracles"))
from ksimoracle import asn  # noqa: E402

KEY_FIELDS = {"encryptionKey", "integrityProtectionKey", "nextHopNH"}
KEY_IE_TYPES = {"SecurityKey", "NextHopNH"}
EXPORTED_PDU = 252


def zero(v):
    """The same value with its octets or bits all zero."""
    if isinstance(v, (bytes, bytearray)):
        return bytes(len(v))
    if isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], int) and isinstance(v[1], int):
        return (0, v[1])   # a BIT STRING: (value, length)
    return v


def scrub(v, hits: list[int]):
    """Walks a pycrate value; zeroes key fields and key IEs; counts them."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k in KEY_FIELDS:
                out[k] = zero(x)
                hits[0] += 1
            elif k == "value" and isinstance(x, tuple) and len(x) == 2 and x[0] in KEY_IE_TYPES:
                out[k] = (x[0], zero(x[1]))
                hits[0] += 1
            else:
                out[k] = scrub(x, hits)
        return out
    if isinstance(v, list):
        return [scrub(x, hits) for x in v]
    if isinstance(v, tuple):
        return tuple(scrub(x, hits) for x in v)
    return v


def tags_end(pkt: bytes) -> tuple[int, str]:
    """Where the exported PDU's payload starts, and its protocol name."""
    i, proto = 0, ""
    while i + 4 <= len(pkt):
        t, n = struct.unpack_from(">HH", pkt, i)
        if t == 0:
            return i + 4, proto
        if t == 12:   # EXP_PDU_TAG_DISSECTOR_NAME
            proto = pkt[i + 4:i + 4 + n].decode("ascii", "replace")
        i += 4 + n
    return len(pkt), proto


def redact(path: Path, notes: list[str]) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) < 24:
        return 0, 0
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    link = struct.unpack_from(endian + "I", data, 20)[0]
    if link != EXPORTED_PDU:
        return 0, 0
    out = bytearray(data[:24])
    off, fields, zeroed, frame = 24, 0, 0, 0
    while off + 16 <= len(data):
        frame += 1
        ts, tu, incl, orig = struct.unpack_from(endian + "IIII", data, off)
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        start, proto = tags_end(pkt)
        if proto in ("ngap", "e1ap"):
            pdu = pkt[start:]
            hits = [0]
            try:
                o, enc = asn.top(proto)
                again = asn.encode(o, scrub(asn.decode(o, pdu, enc), hits), enc)
            except Exception as e:  # noqa: BLE001 - anything pycrate cannot read is zeroed whole
                again, hits[0] = bytes(len(pdu)), 0
                zeroed += 1
                notes.append(f"PEER_ZEROED {path.name} frame {frame} {proto} {len(pdu)} octets: "
                             f"{type(e).__name__}: {str(e)[:120]}")
            fields += hits[0]
            pkt = pkt[:start] + again
        out += struct.pack(endian + "IIII", ts, tu, len(pkt), len(pkt)) + pkt
    path.write_bytes(bytes(out))
    return fields, zeroed


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
        print(__doc__)
        return 2
    fields = zeroed = 0
    notes: list[str] = []
    for f in sorted(Path(sys.argv[1]).glob("*.pcap")):
        a, b = redact(f, notes)
        fields += a
        zeroed += b
    for n in notes:
        print(n)
    print(f"PEER_REDACTED={fields}\nPEER_PDUS_ZEROED={zeroed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
