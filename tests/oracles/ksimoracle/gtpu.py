# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""A structural check of GTP-U path management messages (P2 Q13), for the frames
tshark cannot read: TS 29.281 V19.2.0, the header (clause 5.1, 5.2), Echo Request and
Echo Response (clause 7.2.1, 7.2.2, Tables 7.2.1-1 and 7.2.2-1) and their IEs
(clause 8: Recovery 8.2, Private Extension 8.6, Recovery Time Stamp 8.8).

tshark 4.6.4 flags an Echo Request carrying a Recovery Time Stamp (IE type 231, added
for TS 23.527 restoration) as malformed, though Table 7.2.1-1 allows it: the
Open5GS rig's UPF sends one on every path (2026-10-16). tools/pcap_check.py judges
such a frame here instead, so the verdict still comes from a reading of the spec."""

from __future__ import annotations

import struct

ECHO_REQUEST, ECHO_RESPONSE = 1, 2
IE_RECOVERY, IE_RECOVERY_TIME_STAMP, IE_PRIVATE_EXTENSION = 14, 231, 255
# The IEs each message may carry, by Tables 7.2.1-1 and 7.2.2-1; Recovery is mandatory
# in an Echo Response.
ALLOWED = {ECHO_REQUEST: {IE_RECOVERY_TIME_STAMP, IE_PRIVATE_EXTENSION},
           ECHO_RESPONSE: {IE_RECOVERY, IE_RECOVERY_TIME_STAMP, IE_PRIVATE_EXTENSION}}
TV_LENGTH = {IE_RECOVERY: 1}   # TV IEs (type < 128) have fixed lengths (clause 8.1)


def gtpu_of_ipv4(frame: bytes) -> bytes | None:
    """The UDP payload of an IPv4/UDP frame to or from port 2152 (link type 228), or None."""
    if len(frame) < 28 or frame[0] >> 4 != 4 or frame[9] != 17:
        return None
    ihl = (frame[0] & 0x0F) * 4
    if len(frame) < ihl + 8:
        return None
    sport, dport, ulen = struct.unpack(">HHH", frame[ihl:ihl + 6])
    if 2152 not in (sport, dport) or ulen < 8 or ihl + ulen > len(frame):
        return None
    return frame[ihl + 8:ihl + ulen]


def message_type(gtp: bytes) -> int:
    return gtp[1] if len(gtp) >= 2 else -1


def path_message_problem(gtp: bytes) -> str:
    """'' when gtp is a well-formed Echo Request or Echo Response, else why not."""
    if len(gtp) < 8:
        return "shorter than the 8-octet header"
    flags, mtype, length = gtp[0], gtp[1], struct.unpack(">H", gtp[2:4])[0]
    if flags >> 5 != 1 or not flags & 0x10:
        return f"flags {flags:#04x}: not version 1 with PT 1"
    if mtype not in ALLOWED:
        return f"message type {mtype}: not a path management message"
    if 8 + length != len(gtp):
        return f"length {length} for {len(gtp) - 8} octets after the header"
    if struct.unpack(">I", gtp[4:8])[0] != 0:
        return "TEID not 0 (clause 5.1: Echo Request and Response carry all zeros)"
    pos, nxt = 8, 0
    if flags & 0x07:                                   # E, S or PN: the optional four octets
        if len(gtp) < 12:
            return "E, S or PN set without the optional fields"
        pos, nxt = 12, gtp[11] if flags & 0x04 else 0
    while nxt:                                         # extension headers (clause 5.2.1)
        if pos >= len(gtp) or gtp[pos] == 0:
            return "an extension header of length 0 or past the end"
        end = pos + 4 * gtp[pos]
        if end > len(gtp):
            return "an extension header past the end"
        nxt, pos = gtp[end - 1], end
    seen: list[int] = []
    while pos < len(gtp):
        t = gtp[pos]
        if t < 128:
            n = TV_LENGTH.get(t)
            if n is None:
                return f"TV IE {t}: not one the message may carry"
            pos += 1 + n
        else:
            if pos + 3 > len(gtp):
                return f"TLV IE {t}: no room for its length"
            n = struct.unpack(">H", gtp[pos + 1:pos + 3])[0]
            if t == IE_RECOVERY_TIME_STAMP and n < 4:
                return f"Recovery Time Stamp of length {n} (clause 8.8: at least 4)"
            pos += 3 + n
        if pos > len(gtp):
            return f"IE {t} past the end"
        if t not in ALLOWED[mtype]:
            return f"IE {t} in message type {mtype} (Tables 7.2.1-1, 7.2.2-1)"
        if seen and t < seen[-1]:
            return f"IE {t} after IE {seen[-1]} (clause 8.1: IEs in increasing type order)"
        seen.append(t)
    if mtype == ECHO_RESPONSE and IE_RECOVERY not in seen:
        return "an Echo Response without Recovery (Table 7.2.2-1: mandatory)"
    return ""


def selftest() -> list[tuple[str, bool]]:
    """(case, passed): the rig UPF's Echo Request passes, and broken copies fail."""
    rig = bytes.fromhex("3201000b0000000000030000e70004ee7ca596")   # 2026-10-16, run open5gs-…T133056Z frame 33
    response = bytes([0x32, 0x02, 0x00, 0x06, 0, 0, 0, 0, 0x00, 0x03, 0x00, 0x00, 0x0E, 0x00])
    cases = [
        ("the rig UPF's Echo Request with a Recovery Time Stamp", path_message_problem(rig) == ""),
        ("an Echo Response with Recovery", path_message_problem(response) == ""),
        ("a length one octet long", path_message_problem(rig[:3] + bytes([rig[3] + 1]) + rig[4:]) != ""),
        ("a Recovery Time Stamp cut short", path_message_problem(rig[:2] + b"\x00\x0a" + rig[4:-1]) != ""),
        ("a Recovery Time Stamp of length 3",
         path_message_problem(rig[:2] + b"\x00\x0a" + rig[4:13] + b"\x00\x03" + rig[15:18]) != ""),
        ("an unknown TV IE", path_message_problem(rig[:12] + b"\x10" + rig[13:]) != ""),
        ("an Echo Response without Recovery", path_message_problem(rig[:1] + b"\x02" + rig[2:]) != ""),
        ("a TEID other than 0", path_message_problem(rig[:7] + b"\x01" + rig[8:]) != ""),
    ]
    return cases
