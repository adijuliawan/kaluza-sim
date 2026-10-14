# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Find the smallest named type on which pycrate and asn1c disagree (plan M10).

Given a value pycrate encodes and asn1c cannot decode (or re-encodes
differently), test each named type inside it on its own, depth first, and
report the deepest ones that still fail: the place to look in X.691, pycrate
and asn1c.
"""

from __future__ import annotations

from . import asn
from .codec import Codec
from .jer import _types
from .valuegen import type_name


def _enc(proto: str) -> str:
    return "uper" if proto == "rrc" else "aper"


def agrees(codec: Codec, proto: str, o, name: str, value) -> tuple[bool, str]:
    try:
        data = asn.encode(o, value, _enc(proto))
    except Exception as e:  # noqa: BLE001
        return True, f"pycrate cannot encode alone ({type(e).__name__})"   # not testable alone
    a = codec.dec(proto, name, data)
    if not a.ok and a.stage == "type":
        return True, "not a type asn1c decodes on its own (a class field)"
    if not a.ok:
        return False, f"asn1c {a.stage}: {a.error[:120]} ({len(data)} octets: {data.hex()[:64]})"
    if a.data != data:
        return False, f"asn1c re-encodes differently: {a.hex[:64]} vs {data.hex()[:64]}"
    return True, ""


def _children(proto: str, o, value):
    """(object, named type or None, value) for each component worth testing."""
    t = o.TYPE
    if t == "OPEN_TYPE" and isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        sub = _types(proto).get(value[0])
        if sub is not None:
            yield sub, value[0], value[1]
        return
    c = getattr(o, "_const_cont", None)
    if c is not None and isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        yield c, type_name(c), value[1]
        return
    if t == "SEQUENCE" and isinstance(value, dict):
        for k, v in value.items():
            if k in o._cont:
                yield o._cont[k], _named(o._cont[k], proto), v
    elif t == "CHOICE" and isinstance(value, tuple) and value[0] in o._cont:
        yield o._cont[value[0]], _named(o._cont[value[0]], proto), value[1]
    elif t in ("SEQUENCE OF", "SET OF") and isinstance(value, list) and value:
        seen = set()
        for v in value:                      # every distinct element: the culprit may be the fifth IE
            key = repr(v)
            if key not in seen:
                seen.add(key)
                yield o._cont, _named(o._cont, proto), v


def _named(o, proto: str) -> str | None:
    """The type a component refers to by name, if it is a type (not a class field)."""
    tr = getattr(o, "_typeref", None)
    called = getattr(tr, "called", None) if tr is not None else None
    if not called or o.TYPE == "OPEN_TYPE" or called[1] not in _types(proto):
        return None
    return called[1]


def localize(codec: Codec, proto: str, o, name: str, value, depth: int = 0, out=None) -> list[tuple[str, str]]:
    """Deepest failing named types under (o, name, value); [] if this one agrees.
    A type that cannot be tested alone (parameterised, or a class field) is
    looked through."""
    out = [] if out is None else out
    ok, why = agrees(codec, proto, o, name, value)
    if ok and why:                              # untestable alone: look through it
        for co, cname, cv in _children(proto, o, value):
            if depth < 40:
                localize(codec, proto, co, cname or name, cv, depth + 1, out)
        return out
    if ok:
        return out
    before = len(out)
    if depth < 40:
        for co, cname, cv in _children(proto, o, value):
            if cname:
                localize(codec, proto, co, cname, cv, depth + 1, out)
            else:   # an inline type: look through it
                for go, gname, gv in _children(proto, co, cv):
                    if gname:
                        localize(codec, proto, go, gname, gv, depth + 1, out)
    if len(out) == before:
        out.append((name, why))
    return out
