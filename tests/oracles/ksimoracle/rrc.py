# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Where each v1 RRC type travels (plan M10): the top-level type it is encoded
as, the CHOICE path inside it, and tshark's dissector for that top type.

A message (RRCSetupRequest) is found by walking the logical-channel message
types of TS 38.331 down their c1/c2/messageClassExtension CHOICEs; a container
(CG-ConfigInfo, HandoverPreparationInformation) is its own top type.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from . import asn

MODULE = "NR_RRC_Definitions"
INTERNODE = "NR_InterNodeDefinitions"

# Logical-channel message types and tshark's dissector for each.
CHANNELS = {
    "BCCH-BCH-Message": "nr-rrc.bcch.bch",
    "BCCH-DL-SCH-Message": "nr-rrc.bcch.dl.sch",
    "DL-CCCH-Message": "nr-rrc.dl.ccch",
    "DL-DCCH-Message": "nr-rrc.dl.dcch",
    "PCCH-Message": "nr-rrc.pcch",
    "UL-CCCH-Message": "nr-rrc.ul.ccch",
    "UL-CCCH1-Message": "nr-rrc.ul.ccch1",
    "UL-DCCH-Message": "nr-rrc.ul.dcch",
}

# Containers encoded on their own, and tshark's dissector (None: tshark 4.6.4
# registers none for the type).
CONTAINERS = {
    "CG-Config": None,
    "CG-ConfigInfo": "nr-rrc.cg_configinfo",
    "HandoverPreparationInformation": "nr-rrc.handoverpreparationinformation_msg",
    "HandoverCommand": "nr-rrc.handovercommand_msg",
    "MeasurementTimingConfiguration": None,
    "CellGroupConfig": "nr-rrc.cellgroupconfig_msg",
    "RadioBearerConfig": "nr-rrc.radiobearerconfig",
    "UE-NR-Capability": "nr-rrc.ue_nr_cap_msg",
    "UE-MRDC-Capability": "nr-rrc.ue_mrdc_cap_msg",
    "UE-CapabilityRAT-ContainerList": "nr-rrc.ue_capabilityrat_containerlist",
    "UERadioPagingInformation": "nr-rrc.ue_radio_paging_info",
    "UERadioAccessCapabilityInformation": "nr-rrc.ue_radio_access_cap_info_msg",
}


@dataclass(frozen=True)
class Place:
    top: str                      # the type the octets are encoded as
    path: tuple[tuple[str, str], ...]   # (kind, component) from the top down: kind "seq" or "choice"
    dissector: str | None


def _ident(name: str) -> str:
    return name.replace("-", "_")


def obj(name: str):
    for mod in (MODULE, INTERNODE):
        try:
            return asn.obj("rrc", mod, _ident(name))
        except AttributeError:
            continue
    raise KeyError(f"RRC type {name} not found")


def _ref(o) -> str | None:
    t = getattr(o, "_typeref", None)
    c = getattr(t, "called", None) if t is not None else None
    return c[1] if c else None


def _search(o, target: str, depth: int):
    if depth > 5 or o.TYPE not in ("SEQUENCE", "CHOICE"):
        return None
    kind = "seq" if o.TYPE == "SEQUENCE" else "choice"
    for name, comp in o._cont.items():
        if _ref(comp) == target:
            return ((kind, name),)
    for name, comp in o._cont.items():
        # descend through the message-class CHOICEs (UL-CCCH-MessageType, c1,
        # c2, messageClassExtension), named or inline, and inline SEQUENCEs
        if comp.TYPE == "CHOICE" or (comp.TYPE == "SEQUENCE" and _ref(comp) is None):
            sub = _search(comp, target, depth + 1)
            if sub is not None:
                return ((kind, name),) + sub
    return None


@lru_cache(maxsize=None)
def place(name: str) -> Place:
    if name in CONTAINERS:
        return Place(name, (), CONTAINERS[name])
    if name == "SIB1":
        return Place("BCCH-DL-SCH-Message", (("seq", "message"), ("choice", "c1"),
                                             ("choice", "systemInformationBlockType1")), CHANNELS["BCCH-DL-SCH-Message"])
    for ch, dis in CHANNELS.items():
        p = _search(obj(ch), name, 0)
        if p is not None:
            return Place(ch, p, dis)
    raise KeyError(f"RRC type {name}: not in any logical-channel message and not a known container")


def wrap(pl: Place, value):
    """The top-level value carrying `value` at the place's path."""
    for kind, comp in reversed(pl.path):
        value = {comp: value} if kind == "seq" else (comp, value)
    return value


def unwrap(pl: Place, value):
    """The inner value at the path, or None if the top value takes another branch."""
    for kind, comp in pl.path:
        if kind == "seq":
            if not isinstance(value, dict) or comp not in value:
                return None
            value = value[comp]
        else:
            if not isinstance(value, tuple) or value[0] != comp:
                return None
            value = value[1]
    return value
