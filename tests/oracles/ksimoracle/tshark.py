# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""tshark as an oracle (verification.md §2): pcaps go in on stdin, PDML comes out.

For each packet: every field (name, show, value), whether any field is
_ws.malformed, and the expert items of severity error or warning. Paths under
~/Development are blocked for tshark by AppArmor, so nothing is read by path.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

TSHARK = "tshark"


@dataclass
class Leaf:
    name: str
    show: str
    value: str
    pos: int = -1     # offset in the frame, as PDML gives it


@dataclass
class Packet:
    protocols: list[str] = field(default_factory=list)
    leaves: list[Leaf] = field(default_factory=list)
    malformed: bool = False
    expert: list[str] = field(default_factory=list)   # "severity: message"
    # The innermost protocol each expert item or malformed mark was raised in:
    # (layer, "severity: message"), malformed as (layer, "malformed: ").
    layered: list[tuple[str, str]] = field(default_factory=list)

    def field_values(self, name: str) -> list[str]:
        return [lf.show for lf in self.leaves if lf.name == name]


def version() -> str:
    out = subprocess.run([TSHARK, "-v"], capture_output=True, text=True).stdout
    return out.split("\n", 1)[0]


# Protocols that ride inside AP and RRC containers. Disabling them shows which
# complaints belong to the carrying PDU itself (compare.check_pdu).
NESTED = ("nas-5gs", "nas-eps", "nr-rrc", "lte_rrc", "pdcp-nr", "pdcp-lte", "rlc-nr", "mac-nr", "s1ap",
          "x2ap", "ranap", "lpp", "lppa", "nrppa", "e2ap", "gtpv2", "gtp", "ngap", "xnap", "f1ap", "e1ap")


def decode(pcap: bytes, prefs: list[str] | None = None, disable: list[str] | None = None) -> list[Packet]:
    cmd = [TSHARK, "-n", "-r", "-", "-T", "pdml"]
    for p in prefs or []:
        cmd += ["-o", p]
    if disable:
        cmd += ["--disable-protocol", ",".join(disable)]
    r = subprocess.run(cmd, input=pcap, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"tshark failed: {r.stderr.decode(errors='replace')[:400]}")
    root = ET.fromstring(r.stdout)
    packets = []
    for pkt in root.iter("packet"):
        p = Packet()
        for proto in pkt.findall("proto"):
            p.protocols.append(proto.get("name", ""))
        for f in pkt.iter("field"):
            name = f.get("name", "")
            show = f.get("show", "") or f.get("showname", "")
            p.leaves.append(Leaf(name, show, f.get("value", ""), int(f.get("pos", "-1") or -1)))
            if name == "_ws.malformed" or name.startswith("_ws.malformed"):
                p.malformed = True
            if name == "_ws.expert":
                sev = ""
                msg = f.get("showname", "")
                for sub in f.iter("field"):
                    if sub.get("name") == "_ws.expert.severity":
                        sev = sub.get("show", "")
                    if sub.get("name") == "_ws.expert.message":
                        msg = sub.get("show", msg)
                p.expert.append(f"{sev}: {msg}")
        for proto in pkt.findall("proto"):
            if proto.get("name") == "_ws.malformed":
                p.malformed = True
        _walk_layers(pkt, "frame", p.layered)
        packets.append(p)
    return packets


def _walk_layers(pkt, _layer: str, out: list[tuple[str, str]]) -> None:
    """Attribute each complaint to the protocol whose field was dissected last
    before it (the namespace of that field's name). PDML nesting is no guide:
    an AP dissector calls the RRC or NGAP PER routines for a container
    directly, and an exception is reported where it is caught."""
    ns = "frame"
    for f in pkt.iter("field"):
        name = f.get("name", "")
        if name == "_ws.expert":
            sev, msg = "", f.get("showname", "")
            for sub in f.iter("field"):
                if sub.get("name") == "_ws.expert.severity":
                    sev = sub.get("show", "")
                if sub.get("name") == "_ws.expert.message":
                    msg = sub.get("show", msg)
            out.append((ns, f"{sev}: {msg}"))
        elif name == "_ws.malformed":
            out.append((ns, "malformed: "))
        elif name and not name.startswith(("_ws", "per.", "geninfo", "frame", "exported_pdu")):
            ns = name.split(".", 1)[0]
    for proto in pkt.findall("proto"):          # a malformed mark at packet level
        if proto.get("name") == "_ws.malformed":
            out.append((ns, "malformed: "))


def errors_by_layer(p: Packet) -> list[tuple[str, str]]:
    """errors(), each with the innermost protocol that raised it."""
    bad = []
    for layer, e in p.layered:
        sev, _, msg = e.partition(": ")
        if sev == "malformed":
            bad.append((layer, "malformed packet"))
        elif sev in ("8388608", "6291456") or sev.lower() in ("error", "warning"):
            bad.append((layer, msg))
    return bad


def errors(p: Packet) -> list[str]:
    """Expert items that mean the dissector disagreed with the bytes.

    Severity numbers follow Wireshark's PI_* values: 0x00800000 error, 0x00600000
    warning. Notes and chats (informational) do not count."""
    bad = []
    for e in p.expert:
        sev, _, msg = e.partition(": ")
        if sev in ("8388608", "6291456") or sev.lower() in ("error", "warning"):
            bad.append(msg)
    if p.malformed:
        bad.append("malformed packet")
    return bad
