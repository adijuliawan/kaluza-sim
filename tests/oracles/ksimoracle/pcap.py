# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Capture writers for the oracles: classic pcap, one link type per file.

  exported_pdu(records)  DLT 252 (LINKTYPE_WIRESHARK_UPPER_PDU). Each record carries
                         EXP_PDU_TAG_PROTO_NAME (12) naming the dissector: ngap,
                         f1ap, e1ap, xnap, nr-rrc.ul.ccch, nas-5gs, gsm_sms, ...
                         The tag length counts the NUL padding to 4 octets.
  raw_udp(records)       LINKTYPE_IPV4 (228) with a synthesized IPv4/UDP header, so
                         port-based dissectors (gtp on 2152, gsmtap on 4729) apply.
These are written from the formats' descriptions; our C++ pcapng writer (M13)
is checked against tshark separately.
"""

from __future__ import annotations

import struct

DLT_UPPER_PDU = 252
DLT_IPV4 = 228
GTPU_PORT = 2152
GSMTAP_PORT = 4729


def _file(dlt: int, packets: list[bytes]) -> bytes:
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, dlt)]
    for n, p in enumerate(packets, start=1):
        out.append(struct.pack("<IIII", n, 0, len(p), len(p)) + p)
    return b"".join(out)


def exported_pdu(records: list[tuple[str, bytes]]) -> bytes:
    pkts = []
    for proto, pdu in records:
        name = proto.encode()
        name += b"\0" * ((-len(name)) % 4)
        pkts.append(struct.pack(">HH", 12, len(name)) + name + struct.pack(">HH", 0, 0) + pdu)
    return _file(DLT_UPPER_PDU, pkts)


def _ipv4_udp(payload: bytes, dport: int, sport: int = 40000,
              src: bytes = bytes([10, 0, 0, 1]), dst: bytes = bytes([10, 0, 0, 2])) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 17, 0, src, dst)
    csum = 0
    for i in range(0, 20, 2):
        csum += (hdr[i] << 8) | hdr[i + 1]
    while csum >> 16:
        csum = (csum & 0xFFFF) + (csum >> 16)
    hdr = hdr[:10] + struct.pack(">H", ~csum & 0xFFFF) + hdr[12:]
    return hdr + udp


def raw_udp(records: list[tuple[int, bytes]]) -> bytes:
    """records: (destination port, UDP payload)."""
    return _file(DLT_IPV4, [_ipv4_udp(p, port) for port, p in records])


def read_exported_pdu(data: bytes) -> list[tuple[int, str, bytes]]:
    """(frame number, dissector name, payload) for each record of a classic
    pcap of DLT 252 (Exported PDU). Records of other link types are skipped."""
    if len(data) < 24:
        return []
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        e = ">"
    else:
        raise ValueError("not a classic pcap file")
    dlt = struct.unpack(e + "I", data[20:24])[0]
    out, off, n = [], 24, 0
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(e + "IIII", data[off:off + 16])
        rec = data[off + 16:off + 16 + incl]
        off += 16 + incl
        n += 1
        if dlt != 252:
            continue
        name, pos = "", 0
        while pos + 4 <= len(rec):
            tag, ln = struct.unpack(">HH", rec[pos:pos + 4])
            pos += 4
            if tag == 0:
                break
            if tag == 12:                     # EXP_PDU_TAG_PROTO_NAME
                name = rec[pos:pos + ln].rstrip(b"\0").decode(errors="replace")
            pos += ln + ((4 - ln % 4) % 4 if tag not in (12,) and ln % 4 else 0)
        out.append((n, name, rec[pos:]))
    return out
