#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: every event the sim emits is registered, and every registered event is
emitted (P1 N1, ADR 0009 point 6; architecture §9).

Events are what gates and `ksim-ctl wait` read, so their names are a contract:
src/api/events.tsv lists each name with the spec clause it reports (or `sim`
for the simulator's own state) and a description. Code emits with a literal,
`events.emit("nas.reg.accept", …)` (EventName's constructor is consteval); this
guard finds those literals in src/ and apps/ and requires:

- each name has the form area.what[.more] in lower case;
- each emitted name is registered, and each registered name is emitted;
- a registered name has a clause;
- emit( is never called with a non-literal name, which this guard could not see.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, read_text, repo_files, run_self_test, under  # noqa: E402

REGISTRY = Path("src/api/events.tsv")
CODE_SUFFIXES = {".cpp", ".hpp", ".h", ".cc", ".ipp"}
SCANNED = ("src", "apps")
EXEMPT = ("src/platform/event.hpp", "src/platform/event.cpp")
NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
EMIT_LITERAL = re.compile(r"\bemit\s*\(\s*\"([^\"\\]*)\"")
EMIT_ANY = re.compile(r"\bemit\s*\(\s*([^\s)])")
EVENTNAME_LITERAL = re.compile(r"\bEventName\s*[({]\s*\"([^\"\\]*)\"")


def registry(root: Path, out: list[Violation]) -> dict[str, int]:
    names: dict[str, int] = {}
    path = root / REGISTRY
    if not path.is_file():
        return names
    for n, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if cols[0] == "name":
            continue
        name = cols[0]
        if len(cols) < 3 or not cols[1].strip():
            out.append(Violation(REGISTRY.as_posix(), n, "event-registry",
                                 f"'{name}' needs a clause (or 'sim') and a description"))
        if not NAME.match(name):
            out.append(Violation(REGISTRY.as_posix(), n, "event-name", f"'{name}' is not area.what in lower case"))
        if name in names:
            out.append(Violation(REGISTRY.as_posix(), n, "event-registry", f"'{name}' is registered twice"))
        names[name] = n
    return names


def check(root: Path) -> list[Violation]:
    out: list[Violation] = []
    registered = registry(root, out)
    emitted: dict[str, tuple[str, int]] = {}
    for rel in repo_files(root):
        if rel.suffix not in CODE_SUFFIXES or not under(rel, *SCANNED) or under(rel, *EXEMPT):
            continue
        for n, line in enumerate(read_text(root, rel).splitlines(), start=1):
            code = line.split("//", 1)[0]
            for m in list(EMIT_LITERAL.finditer(code)) + list(EVENTNAME_LITERAL.finditer(code)):
                name = m.group(1)
                emitted.setdefault(name, (rel.as_posix(), n))
                if not NAME.match(name):
                    out.append(Violation(rel.as_posix(), n, "event-name", f"'{name}' is not area.what in lower case"))
                elif name not in registered:
                    out.append(Violation(rel.as_posix(), n, "event-unregistered",
                                         f"'{name}' is emitted but not in {REGISTRY.as_posix()}"))
            for m in EMIT_ANY.finditer(code):
                if m.group(1) != '"':
                    out.append(Violation(rel.as_posix(), n, "event-literal",
                                         "emit() takes the event name as a string literal"))
    for name, line in sorted(registered.items()):
        if name not in emitted:
            out.append(Violation(REGISTRY.as_posix(), line, "event-unused", f"'{name}' is registered but never emitted"))
    return out


def self_test() -> int:
    tsv = "name\tclause\tdescription\nnas.reg.accept\t24.501 5.5.1.2.4\tREGISTRATION ACCEPT taken\n"
    clean = {
        "src/api/events.tsv": tsv,
        "src/proc/ue/nas_mm/reg.cpp": 'void f(IEventSink& s) { s.emit("nas.reg.accept", ue, {}); }\n',
    }
    dirty = {
        "src/api/events.tsv": tsv + "nas.never\t24.501 1\tnot emitted\n",
        "src/proc/ue/nas_mm/reg.cpp": 'void f(IEventSink& s) { s.emit("nas.reg.accept", ue, {}); }\n',
        "src/proc/ue/nas_mm/bad.cpp": 'void g(IEventSink& s) {\n s.emit("nas.reg.reject", ue, {});\n'
                                      ' s.emit(kName, ue, {});\n s.emit("Bad Name", ue, {});\n}\n',
    }
    expect = [("src/proc/ue/nas_mm/bad.cpp", "event-unregistered"),
              ("src/proc/ue/nas_mm/bad.cpp", "event-literal"),
              ("src/proc/ue/nas_mm/bad.cpp", "event-name"),
              ("src/api/events.tsv", "event-unused")]
    return run_self_test("events", check, clean, dirty, expect)


if __name__ == "__main__":
    main("events", check, self_test)
