# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Minimal and maximal values per ASN.1 type, generated from pycrate's compiled
types (plan M8).

  min: mandatory components only, lower size and value bounds, the first
       CHOICE alternative and ENUMERATED item; ProtocolIE containers hold every
       IE the object set marks mandatory.
  max: every root component, upper bounds (capped where the spec allows huge
       sizes), the last alternative and item; ProtocolIE containers hold every
       IE of the object set.

Open types are filled from their table constraint. An IE's id, criticality and
value always come from the same object-set entry, so a generated message is one
the spec allows. Extension additions are not generated: they are covered by
the external vectors and the explicit probes of M10.
"""

from __future__ import annotations

from dataclasses import dataclass

class Omit(Exception):
    """An optional component that cannot be generated (an empty object set with a
    size lower bound of 1, e.g. an iE-Extensions container): leave it out."""


STR_TYPES = {"PrintableString", "VisibleString", "UTF8String", "IA5String", "NumericString",
             "GraphicString", "BMPString", "UniversalString", "TeletexString", "T61String"}


@dataclass
class Caps:
    seqof_max: int = 2       # items in a maximal SEQUENCE OF (beyond the lower bound)
    octets_max: int = 48     # bytes in a maximal unbounded or huge OCTET STRING
    bits_max: int = 160      # bits in a maximal unbounded or huge BIT STRING
    chars_max: int = 24
    depth_max: int = 40      # beyond this depth, fall back to minimal values


def type_name(o) -> str:
    """The identifier pycrate expects for an open-type value: the referenced type's
    name, or the built-in type (e.g. 'OCTET STRING') for a type written inline in
    the object set."""
    tr = getattr(o, "_typeref", None)
    called = getattr(tr, "called", None) if tr is not None else None
    if called:
        return called[1]
    if o._name in ("Value", "Extension") or o._name.startswith("_"):
        return o.TYPE
    return o._name


def _bounds(const):
    """(lb, ub) of the first root range of a pycrate value/size constraint, or (None, None)."""
    if const is None:
        return None, None
    try:
        r = const.root[0]
    except (AttributeError, IndexError, TypeError):
        return None, None
    lb, ub = getattr(r, "lb", r), getattr(r, "ub", r)
    if isinstance(lb, int) and not isinstance(lb, bool) and isinstance(ub, int) and not isinstance(ub, bool):
        return lb, ub
    if isinstance(r, int):
        return r, r
    return (lb if isinstance(lb, int) else None), (ub if isinstance(ub, int) else None)


class Gen:
    def __init__(self, mode: str, caps: Caps | None = None):
        assert mode in ("min", "max")
        self.mode = mode
        self.caps = caps or Caps()

    # -- entry points -----------------------------------------------------------------

    def value(self, o, depth: int = 0):
        t = o.TYPE
        if depth > self.caps.depth_max and self.mode == "max":
            return Gen("min", self.caps).value(o, depth)
        if t == "NULL":
            return 0
        if t == "BOOLEAN":
            return self.mode == "max"
        if t == "INTEGER":
            return self._int(o)
        if t == "ENUMERATED":
            names = list(o._root)
            return names[0] if self.mode == "min" else names[-1]
        if t == "BIT STRING":
            return self._bits(o)
        if t == "OCTET STRING":
            return self._octets(o)
        if t in STR_TYPES:
            return self._chars(o, t)
        if t in ("SEQUENCE", "SET"):
            return self._seq(o, depth)
        if t in ("SEQUENCE OF", "SET OF"):
            return self._seqof(o, depth)
        if t == "CHOICE":
            # min: the first alternative that can be generated; max: the last.
            # (A choice-Extensions alternative over an empty object set cannot.)
            names = list(o._root)
            for alt in (names if self.mode == "min" else reversed(names)):
                try:
                    return (alt, self.value(o._cont[alt], depth + 1))
                except Omit:
                    continue
            raise Omit(f"{o._name}: no alternative can be generated")
        if t == "OPEN_TYPE":
            raise ValueError(f"open type {o._name} outside a table-constrained SEQUENCE")
        raise ValueError(f"unsupported ASN.1 type {t} ({o._name})")

    def procedure_message(self, pdu, message: str, depth: int = 0):
        """A top-level AP PDU (NGAP-PDU, F1AP-PDU, ...) carrying `message`."""
        for kind in ("initiatingMessage", "successfulOutcome", "unsuccessfulOutcome"):
            seq = pdu._cont[kind]
            vfield = seq._cont["value"]
            for entry in vfield._const_tab._val.root:
                m = entry.get(vfield._const_tab_id)
                if m is not None and type_name(m) == message:
                    return (kind, {"procedureCode": entry["procedureCode"],
                                   "criticality": entry["criticality"],
                                   "value": (message, self.value(m, depth + 1))})
        raise KeyError(f"no procedure carries {message}")

    # -- scalars ---------------------------------------------------------------------

    def _int(self, o) -> int:
        lb, ub = _bounds(getattr(o, "_const_val", None))
        if lb is None and ub is None:
            return 0 if self.mode == "min" else 1 << 31
        if self.mode == "min":
            return lb if lb is not None else 0
        return ub if ub is not None else (lb or 0) + (1 << 31)

    def _size(self, o, cap: int) -> int:
        lb, ub = _bounds(getattr(o, "_const_sz", None))
        lb = lb or 0
        if self.mode == "min":
            return lb
        if ub is None or ub > cap:
            return max(lb, min(cap, ub if ub is not None else cap))
        return ub

    def _contained(self, o):
        """(type name, value) for a string with a CONTAINING constraint, or None."""
        c = getattr(o, "_const_cont", None)
        if c is None:
            return None
        return (type_name(c), self.value(c))

    def _bits(self, o):
        cont = self._contained(o)
        if cont is not None:
            return cont
        n = self._size(o, self.caps.bits_max)
        return ((1 << n) - 1 if self.mode == "max" else 0, n)

    def _octets(self, o):
        cont = self._contained(o)
        if cont is not None:
            return cont
        n = self._size(o, self.caps.octets_max)
        return (b"\xff" if self.mode == "max" else b"\x00") * n

    def _chars(self, o, t: str) -> str:
        n = self._size(o, self.caps.chars_max)
        ch = "1" if t == "NumericString" else ("z" if self.mode == "max" else "a")
        return ch * n

    # -- constructed -----------------------------------------------------------------

    def _seq(self, o, depth: int):
        names = list(o._root_mand) if self.mode == "min" else list(o._root)
        # Components bound to a table constraint (id / criticality / value of an IE
        # or of a procedure) come from one entry of the object set.
        tabbed = {n: o._cont[n] for n in o._cont if getattr(o._cont[n], "_const_tab", None) is not None}
        entry = None
        if tabbed:
            first = next(iter(tabbed.values()))
            root = first._const_tab._val.root or []
            if not root:
                raise Omit(f"{o._name}: empty object set")
            entry = root[0] if self.mode == "min" else root[-1]
        val = {}
        for n in names:
            c = o._cont[n]
            optional = n not in o._root_mand
            try:
                val[n] = self._component(o, n, c, entry, tabbed, depth)
            except Omit:
                if not optional:
                    raise
        return val

    def _component(self, o, n, c, entry, tabbed, depth):
        if True:
            if entry is not None and n in tabbed:
                key = c._const_tab_id
                v = entry.get(key)
                if c.TYPE == "OPEN_TYPE":
                    return (type_name(v), self.value(v, depth + 1))
                return v
            return self.value(c, depth + 1)

    def ie_entries(self, field):
        """Object-set entries for a ProtocolIE-Field-like SEQUENCE, by mode."""
        vfield = next(c for c in field._cont.values() if getattr(c, "_const_tab", None) is not None
                      and c.TYPE == "OPEN_TYPE")
        root = vfield._const_tab._val.root or []
        if self.mode == "max":
            return root
        return [e for e in root if str(e.get("presence", "mandatory")) == "mandatory"]

    def _seqof(self, o, depth: int):
        item = o._cont
        lb, ub = _bounds(getattr(o, "_const_sz", None))
        lb = lb or 0
        # A ProtocolIE container: one item per object-set entry (mandatory or all).
        if item.TYPE == "SEQUENCE" and any(getattr(c, "_const_tab", None) is not None and c.TYPE == "OPEN_TYPE"
                                           for c in item._cont.values()):
            out = []
            for e in self.ie_entries(item):
                one = {}
                for n, c in item._cont.items():
                    if getattr(c, "_const_tab", None) is not None:
                        v = e.get(c._const_tab_id)
                        one[n] = (type_name(v), self.value(v, depth + 1)) if c.TYPE == "OPEN_TYPE" else v
                    elif n in item._root_mand or self.mode == "max":
                        one[n] = self.value(c, depth + 1)
                out.append(one)
            if ub is not None:
                out = out[:ub]
            if len(out) < lb:
                raise Omit(f"{o._name}: {len(out)} IEs available, at least {lb} required")
            return out
        if self.mode == "min":
            n = lb
        else:
            n = max(lb, min(ub if ub is not None else lb + self.caps.seqof_max, lb + self.caps.seqof_max))
            n = max(n, 1) if (ub is None or ub >= 1) else n
        return [self.value(item, depth + 1) for _ in range(n)]
