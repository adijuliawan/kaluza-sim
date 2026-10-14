# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""asn1c's JER, predicted from pycrate's value, for the M10 comparison.

asn1c 18e56503's JER differs from X.697 JER as pycrate writes it (row
KS-PLAT-T15). Rather than parse one dialect with the other's tool, the harness
rewrites pycrate's X.697 JSON of a value into the JSON asn1c must produce for
the same value, walking pycrate's type tree and decoded value side by side, and
requires equality. The rewrites, each only where the schema says so:

  - open type: asn1c writes {"<ActualType>": <value>} (its CHOICE-shaped C
    struct, keyed by the ASN.1 type name); X.697 writes the value alone. A type
    written inline in an object set is keyed by its printed text, e.g.
    "BIT STRING (SIZE (24))", which normalize() reduces to "BIT STRING";
  - OCTET STRING with a CONTAINING constraint: asn1c writes the octets (the
    contained value encoded with the protocol's PER variant); pycrate writes
    {"<ContainedType>": <value>};
  - BIT STRING: asn1c writes a hex string only for a fixed size without an
    extension marker, else {"value", "length"} in that order; pycrate writes a
    string whenever the root size is fixed;
  - hex digits: asn1c writes upper case;
  - SEQUENCE members: asn1c's JER decoder takes them in definition order only.
"""

from __future__ import annotations

import re
from functools import lru_cache

from . import asn

_INLINE_KEY = re.compile(r"^(BIT STRING|OCTET STRING|INTEGER|BOOLEAN|ENUMERATED|NULL|PrintableString|"
                         r"VisibleString|UTF8String|IA5String|BMPString|NumericString)\b.*$")


@lru_cache(maxsize=None)
def _types(proto: str) -> dict:
    """Every named type of the protocol's compiled modules, by name and by C name."""
    m = asn.module(proto)
    out = {}
    for attr in dir(m):
        cls = getattr(m, attr)
        names = getattr(cls, "_type_", None)
        if not isinstance(names, list) or not hasattr(cls, "_name_"):
            continue
        for n in names:
            o = getattr(cls, n.replace("-", "_"), None)
            if o is not None:
                out.setdefault(n, o)
                out.setdefault(n.replace("-", "_"), o)
    return out


def _enc(proto: str) -> str:
    return "uper" if proto == "rrc" else "aper"


def _contained(o):
    return getattr(o, "_const_cont", None)


def _size(o):
    """(fixed root size or None, extensible) of a string type's size constraint."""
    c = getattr(o, "_const_sz", None)
    if c is None:
        return None, False
    root = getattr(c, "root", None) or []
    fixed = root[0] if len(root) == 1 and isinstance(root[0], int) else None
    return fixed, getattr(c, "ext", None) is not None


def _bits(v) -> tuple[str, int] | None:
    """pycrate's BIT STRING value (int, nbits) as asn1c's hex (left-aligned, upper case) and length."""
    if not (isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], int) and isinstance(v[1], int)):
        return None
    val, n = v
    nbytes = (n + 7) // 8
    return (val << (nbytes * 8 - n)).to_bytes(nbytes, "big").hex().upper() if nbytes else "", n


def to_asn1c(proto: str, o, j, v):
    """pycrate's X.697 JSON `j` of type o, with pycrate's value `v`, rewritten as asn1c's JER."""
    t = o.TYPE
    c = _contained(o)
    if c is not None and t == "OCTET STRING" and isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str):
        return asn.encode(c, v[1], _enc(proto)).hex().upper()
    if t == "OCTET STRING":
        return j.upper() if isinstance(j, str) else j
    if t == "BIT STRING":
        b = _bits(v)
        if b is None:
            return j
        fixed, ext = _size(o)
        return b[0] if fixed is not None and not ext else {"value": b[0], "length": b[1]}
    if t == "OPEN_TYPE":
        if not (isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str)):
            return j
        name, inner = v
        sub = _types(proto).get(name)
        if sub is None:                       # a type written inline in the object set
            try:
                sub = o._get_val_obj(name)
            except Exception:  # noqa: BLE001
                sub = None
        conv = j if sub is None else to_asn1c(proto, sub, j, inner)
        return {name: conv}
    if t == "SEQUENCE" and isinstance(j, dict) and isinstance(v, dict):
        order = [k for k in o._cont.keys() if k in j] + [k for k in j if k not in o._cont]
        return {k: (to_asn1c(proto, o._cont[k], j[k], v.get(k)) if k in o._cont else j[k]) for k in order}
    if t == "CHOICE" and isinstance(j, dict) and len(j) == 1 and isinstance(v, tuple):
        k, x = next(iter(j.items()))
        return {k: to_asn1c(proto, o._cont[k], x, v[1])} if k in o._cont else j
    if t in ("SEQUENCE OF", "SET OF") and isinstance(j, list) and isinstance(v, list):
        return [to_asn1c(proto, o._cont, x, y) for x, y in zip(j, v)]
    return j


def normalize(j):
    """asn1c's JSON with inline-type keys reduced to the built-in name
    ("BIT STRING (SIZE (24))" -> "BIT STRING"); nothing else changes."""
    if isinstance(j, dict):
        out = {}
        for k, v in j.items():
            m = _INLINE_KEY.match(k)
            out[m.group(1) if m and len(j) == 1 else k] = normalize(v)
        return out
    if isinstance(j, list):
        return [normalize(x) for x in j]
    return j
