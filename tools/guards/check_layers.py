#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard: the code layering rules R1–R8 of architecture.md §3.

Three checks share one rule table:
  1. quoted #include "layer/..." lines under src/<layer>/ name only allowed layers;
  2. pure layers (codec, crypto, radio) include only their allowed platform
     headers and none of the forbidden system headers (no sockets, timers,
     threads; codec and radio no crypto);
  3. the CMake link graph (<build>/layers.json from cmake/layers.cmake) links
     only allowed layers;
  plus R7: socket, epoll, ioctl and setns calls only in net/, node/ and the
  platform reactor.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import Violation, main, read_text, repo_files, run_self_test, under  # noqa: E402

LAYERS = ["platform", "net", "crypto", "codec", "entity", "uicc", "radio", "proc", "node", "api"]

# Which layers each layer may depend on (besides itself). R1: platform depends on nothing.
ALLOWED: dict[str, set[str]] = {
    "platform": set(),
    "net": {"platform"},
    "crypto": {"platform"},                                   # R2
    "codec": {"platform"},                                    # R3
    "radio": {"platform"},                                    # R8
    "entity": {"platform", "codec", "crypto"},                # R4
    "uicc": {"platform", "codec", "crypto"},                  # R5
    "proc": {"platform", "codec", "crypto", "entity", "uicc", "radio"},  # R6
    "api": {"platform", "codec"},
    "node": {"platform", "net", "crypto", "codec", "entity", "uicc", "radio", "proc", "api"},
}

# Pure layers may include only these platform headers (by stem): data types, no
# I/O, no time, no logging (R2, R3, R8).
PURE_PLATFORM: dict[str, set[str]] = {
    "codec": {"buf", "result", "bytes"},
    "crypto": {"buf", "result", "bytes", "secret"},
    "radio": {"buf", "result", "bytes"},
}

_SYSIO = {"sys/socket.h", "sys/epoll.h", "sys/timerfd.h", "sys/eventfd.h", "sys/ioctl.h",
          "netinet/in.h", "netinet/sctp.h", "thread", "mutex", "condition_variable", "future",
          "chrono", "iostream", "cstdio"}
FORBIDDEN_SYSTEM: dict[str, set[str]] = {
    "codec": _SYSIO | {"openssl/*"},     # R3: no crypto in codecs
    "crypto": _SYSIO,                     # R2: pure functions over OpenSSL
    "radio": _SYSIO | {"openssl/*"},     # R8
}

# R7: these calls only in net/, node/ and the platform reactor itself.
SYSCALL = re.compile(r"(?<![\w.>])(?:::)?(socket|epoll_create1?|epoll_ctl|epoll_p?wait2?|ioctl|setns)\s*\(")
SYSCALL_OK_DIRS = ("src/net", "src/node")
SYSCALL_OK_PREFIX = "src/platform/reactor"  # reactor.cpp, reactor.hpp, reactor/…

INC_QUOTED = re.compile(r'^\s*#\s*include\s+"([^"]+)"')
INC_ANGLE = re.compile(r"^\s*#\s*include\s+<([^>]+)>")
CODE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".ipp"}


def layer_of(rel: Path) -> str | None:
    parts = rel.parts
    if len(parts) >= 2 and parts[0] == "src" and parts[1] in LAYERS:
        return parts[1]
    return None


def forbidden_system(layer: str, header: str) -> bool:
    for pat in FORBIDDEN_SYSTEM.get(layer, ()):
        if pat.endswith("/*") and header.startswith(pat[:-1]):
            return True
        if header == pat:
            return True
    return False


def check_sources(root: Path) -> list[Violation]:
    out: list[Violation] = []
    for rel in repo_files(root):
        if rel.suffix not in CODE_SUFFIXES:
            continue
        layer = layer_of(rel)
        if layer is None:
            continue
        for n, line in enumerate(read_text(root, rel).splitlines(), start=1):
            m = INC_QUOTED.match(line)
            if m:
                inc = m.group(1)
                head = inc.split("/", 1)[0]
                if head in LAYERS and head != layer and head not in ALLOWED[layer]:
                    out.append(Violation(rel.as_posix(), n, "layer-include",
                                         f"{layer} may not include {head}/ ('{inc}')"))
                if head == "platform" and layer in PURE_PLATFORM:
                    stem = Path(inc).stem
                    if stem not in PURE_PLATFORM[layer]:
                        out.append(Violation(rel.as_posix(), n, "pure-layer",
                                             f"{layer} is pure; platform/{Path(inc).name} is not allowed"))
            m = INC_ANGLE.match(line)
            if m and forbidden_system(layer, m.group(1)):
                out.append(Violation(rel.as_posix(), n, "pure-layer",
                                     f"{layer} may not include <{m.group(1)}>"))
            s = SYSCALL.search(line.split("//", 1)[0])
            if s and not (under(rel, *SYSCALL_OK_DIRS)
                          or rel.as_posix().startswith(SYSCALL_OK_PREFIX)):
                out.append(Violation(rel.as_posix(), n, "r7-syscall",
                                     f"{s.group(1)}() outside net/, node/ and the platform reactor"))
    return out


def check_graph(graph_file: Path) -> list[Violation]:
    out: list[Violation] = []
    nodes = json.loads(graph_file.read_text())
    layer_by_target = {n["target"]: n["layer"] for n in nodes}
    for n in nodes:
        src_layer = n["layer"]
        for link in filter(None, n["links"].split(";")):
            target = link.replace("ksim::", "ksim_", 1)
            dst_layer = layer_by_target.get(target)
            if dst_layer and dst_layer != src_layer and dst_layer not in ALLOWED[src_layer]:
                out.append(Violation(graph_file.name, 0, "layer-link",
                                     f"{n['target']} ({src_layer}) links {link} ({dst_layer})"))
    return out


def check(root: Path) -> list[Violation]:
    out = check_sources(root)
    build = root / "build"
    for graph in sorted(build.glob("*/layers.json")) if build.is_dir() else []:
        out += check_graph(graph)
    return out


HDR = "// SPDX-FileCopyrightText: 2026 T\n// SPDX-License-Identifier: LicenseRef-x\n"


def self_test() -> int:
    clean = {
        "src/platform/buf.hpp": HDR + "#pragma once\n",
        "src/platform/reactor.cpp": HDR + "int fd = epoll_create1(0);\n",
        "src/codec/nas/ok.cpp": HDR + '#include "platform/buf.hpp"\n#include <cstdint>\n',
        "src/proc/ue/ok.cpp": HDR + '#include "codec/nas/msg.hpp"\n#include "entity/pdcp.hpp"\n',
        "src/net/sctp.cpp": HDR + "int s = ::socket(1, 2, 3);\n",
        "src/entity/ok.cpp": HDR + "std::bind(f); conn.socket_count(); // socket( in a comment\n",
        "build/dev/layers.json": json.dumps([
            {"target": "ksim_platform", "layer": "platform", "links": ""},
            {"target": "ksim_codec", "layer": "codec", "links": "ksim::platform"},
        ]),
    }
    dirty = {
        "src/codec/nas/up.cpp": HDR + '#include "proc/ue/nas_mm.hpp"\n',
        "src/codec/nas/log.cpp": HDR + '#include "platform/log.hpp"\n',
        "src/codec/nas/ssl.cpp": HDR + "#include <openssl/evp.h>\n",
        "src/crypto/thr.cpp": HDR + "#include <thread>\n",
        "src/platform/up.hpp": HDR + '#include "codec/x.hpp"\n',
        "src/entity/sock.cpp": HDR + "int s = socket(1, 2, 3);\n",
        "build/asan/layers.json": json.dumps([
            {"target": "ksim_proc", "layer": "proc", "links": ""},
            {"target": "ksim_codec", "layer": "codec", "links": "ksim::proc"},
        ]),
    }
    expect = [
        ("src/codec/nas/up.cpp", "layer-include"),
        ("src/codec/nas/log.cpp", "pure-layer"),
        ("src/codec/nas/ssl.cpp", "pure-layer"),
        ("src/crypto/thr.cpp", "pure-layer"),
        ("src/platform/up.hpp", "layer-include"),
        ("src/entity/sock.cpp", "r7-syscall"),
        ("layers.json", "layer-link"),
    ]
    return run_self_test("layers", check, clean, dirty, expect)


if __name__ == "__main__":
    main("layers", check, self_test)
