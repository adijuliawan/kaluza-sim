#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Stamp-keyed asn1c generation for the five protocol libraries (plan M6,
architecture.md §4.1).

    spec/tools/asn1_gen.py --cmake-out <build>/asn1/files.cmake [proto...]

For each protocol the stamp is the sha256 of: the extracted .asn files, the
asn1c binary, the flags, the prefix, the forced-include config header and this
tool's version. Generation runs once per stamp into a shared cache
(~/.cache/kaluza-sim/asn1-gen/<proto>-<stamp>/), in parallel across
protocols, so every preset and every clean build reuses it. The fixer alone
takes minutes on F1AP (row KS-PLAT-T7).

After generating, the tool:
  - reads asn1c's own Makefile.am.libasncodec to split generated sources (those
    carrying the protocol prefix) from runtime skeletons. There is no glob, so
    no stale-file-list trap;
  - checks every skeleton asn1c copied is byte-identical to the vendored
    runtime (third_party/asn1c/runtime), then deletes the copies, so only the
    vendored runtime is ever compiled or included;
  - renames C enumerators that collide with a typedef name. ENUMERATED value
    't' of a type T yields the enumerator T_t, which is also T's typedef. Only
    the C identifier changes (to T_value_t); the ASN.1 and the value name used
    by JER and printing stay 't' (row KS-RRC-B1). Renames are logged in
    postprocess.log;
  - prefixes the few typedef names -fprefix leaves bare: inner SEQUENCE OF
    member structs such as CriticalityDiagnostics_IE_List__Member, which E1AP
    and XnAP both declare. They are header-only names, so nm cannot see them;
    without the rename the two protocols cannot share a translation unit
    (row KS-PLAT-B8);
  - writes a files.cmake listing every protocol's sources and the union of
    runtime files they need.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import fcntl
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOL_VERSION = "4"
ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "third_party" / "asn1c" / "runtime"
CONFIG_H = ROOT / "src" / "codec" / "asn1" / "ksim_asn1_config.h"
DEFAULT_ASN1C = Path.home() / ".local" / "opt" / "asn1c-18e56503" / "bin" / "asn1c"
DEFAULT_CACHE = Path.home() / ".cache" / "kaluza-sim" / "asn1-gen"

FLAGS = ["-fcompound-names", "-findirect-choice", "-fno-include-deps", "-pdu=all",
         "-no-gen-OER", "-no-gen-BER", "-no-gen-XER", "-no-gen-random-fill", "-no-gen-example"]
PREFIX = {"rrc": "RRC", "ngap": "NGAP", "f1ap": "F1AP", "e1ap": "E1AP", "xnap": "XNAP"}


def sha256_bytes(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    return h.hexdigest()


def asn_files(proto: str) -> list[Path]:
    files = sorted((ROOT / "spec" / "asn1" / proto).glob("*.asn"))
    if not files:
        raise SystemExit(f"ASN1_GEN=FAIL no .asn files for {proto} (run spec/tools/docx_asn1.py)")
    return files


def stamp(proto: str, asn1c: Path) -> str:
    parts = [TOOL_VERSION.encode(), PREFIX[proto].encode(), " ".join(FLAGS).encode(),
             asn1c.read_bytes(), CONFIG_H.read_bytes()]
    for f in asn_files(proto):
        parts += [f.name.encode(), f.read_bytes()]
    return sha256_bytes(*parts)[:16]


def parse_makefile_am(path: Path) -> list[str]:
    """Every .c file named in asn1c's Makefile.am.libasncodec (basenames)."""
    names = re.findall(r"([A-Za-z0-9_.+-]+\.c)\b", path.read_text())
    return sorted(set(names))


_TYPEDEF = re.compile(r"\btypedef\b[^;{]*?\b(\w+_t)\s*;|\}\s*(\w+_t)\s*;")
_ENUMERATOR = re.compile(r"^(\s+)(\w+)(\s*=\s*-?\d+)", re.M)


def fix_enumerator_collisions(gen_dir: Path) -> list[tuple[str, str, str]]:
    """Rename enumerators whose identifier is also a typedef name (C forbids it)."""
    headers = sorted(gen_dir.glob("*.h"))
    typedefs: set[str] = set()
    for h in headers:
        for m in _TYPEDEF.finditer(h.read_text(errors="replace")):
            typedefs.add(m.group(1) or m.group(2))
    renames = []
    for h in headers:
        text = h.read_text(errors="replace")
        hits = [m.group(2) for m in _ENUMERATOR.finditer(text) if m.group(2) in typedefs]
        for name in hits:
            new = name[:-2] + "_value_t"
            text = re.sub(rf"^(\s+){name}(\s*=)", rf"\1{new}\2", text, flags=re.M)
            renames.append((h.name, name, new))
        if hits:
            h.write_text(text)
    return renames


# Typedef names in asn1c headers: a single-line "typedef ... NAME;" or the
# "} NAME;" that closes a typedef struct/union/enum. asn1c writes the latter at
# column 0; indented "} name;" lines are member declarations, not typedefs.
_TYPEDEF_ONE_LINE = re.compile(r"^typedef\b[^;{]*?\b(\w+)\s*;", re.M)
_TYPEDEF_CLOSE = re.compile(r"^\}\s*(\w+)\s*;", re.M)


def typedef_names(text: str) -> set[str]:
    return ({m.group(1) for m in _TYPEDEF_ONE_LINE.finditer(text)}
            | {m.group(1) for m in _TYPEDEF_CLOSE.finditer(text)})


def prefix_bare_typedefs(gen_dir: Path, prefix: str) -> list[tuple[str, str, str]]:
    """Give every typedef name that lacks the protocol prefix the prefix, in
    every generated file of the protocol."""
    has_prefix = re.compile(rf"(^|_){prefix}_")
    names: set[str] = set()
    for h in gen_dir.glob("*.h"):
        names |= {n for n in typedef_names(h.read_text(errors="replace"))
                  if not has_prefix.search(n)}
    if not names:
        return []
    pat = re.compile(r"\b(" + "|".join(map(re.escape, sorted(names, key=len, reverse=True))) + r")\b")
    for f in sorted(gen_dir.glob("*.h")) + sorted(gen_dir.glob("*.c")):
        text = f.read_text(errors="replace")
        new = pat.sub(lambda m: f"{prefix}_{m.group(1)}", text)
        if new != text:
            f.write_text(new)
    return [("*", n, f"{prefix}_{n}") for n in sorted(names)]


def generate(proto: str, asn1c: Path, cache: Path) -> dict:
    st = stamp(proto, asn1c)
    final = cache / f"{proto}-{st}"
    lock_path = cache / f"{proto}-{st}.lock"
    cache.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (final / ".done").is_file():
            return {"proto": proto, "stamp": st, "dir": final, "generated": False, "seconds": 0.0}
        t0 = time.monotonic()
        tmp = Path(tempfile.mkdtemp(prefix=f"{proto}-{st}.", dir=cache))
        try:
            cmd = [str(asn1c), *FLAGS, f"-fprefix={PREFIX[proto]}_", "-D", str(tmp),
                   *[str(f) for f in asn_files(proto)]]
            r = subprocess.run(cmd, capture_output=True, text=True)
            (tmp / "asn1c.stderr").write_text(r.stderr)
            fatal = [ln for ln in r.stderr.splitlines() if "FATAL" in ln]
            if r.returncode != 0 or fatal:
                raise RuntimeError(f"asn1c rc={r.returncode} fatal={len(fatal)}: "
                                   f"{(fatal or r.stderr.splitlines()[-3:])[:3]}")
            listed = parse_makefile_am(tmp / "Makefile.am.libasncodec")
            gen = [n for n in listed if n.startswith(PREFIX[proto] + "_")]
            runtime = [n for n in listed if not n.startswith(PREFIX[proto] + "_")]
            for n in runtime:
                vendored = RUNTIME / n
                if not vendored.is_file() or vendored.read_bytes() != (tmp / n).read_bytes():
                    raise RuntimeError(f"runtime file {n} differs from third_party/asn1c/runtime")
            # Keep only generated files: the vendored runtime is the one compiled and included.
            for p in tmp.iterdir():
                if p.is_file() and not p.name.startswith(PREFIX[proto] + "_") and p.name not in (
                        "Makefile.am.libasncodec", "asn1c.stderr"):
                    p.unlink()
            renames = fix_enumerator_collisions(tmp) + prefix_bare_typedefs(tmp, PREFIX[proto])
            (tmp / "postprocess.log").write_text("".join(f"rename {a} -> {b} in {f}\n"
                                                         for f, a, b in renames))
            (tmp / "generated-sources.txt").write_text("\n".join(gen) + "\n")
            (tmp / "runtime-sources.txt").write_text("\n".join(runtime) + "\n")
            (tmp / ".done").write_text(f"stamp={st} seconds={time.monotonic() - t0:.0f}\n")
            if final.exists():
                shutil.rmtree(final)
            tmp.rename(final)
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        prune(cache, proto, keep=final)
        return {"proto": proto, "stamp": st, "dir": final, "generated": True,
                "seconds": time.monotonic() - t0}


def prune(cache: Path, proto: str, keep: Path, spare: int = 1) -> None:
    """Keep the current stamp plus the `spare` most recent others per protocol
    (a branch switch back stays cheap); remove older ones."""
    others = sorted((d for d in cache.glob(f"{proto}-*") if d.is_dir() and d != keep),
                    key=lambda d: d.stat().st_mtime, reverse=True)
    for d in others[spare:]:
        shutil.rmtree(d, ignore_errors=True)
        (cache / f"{d.name}.lock").unlink(missing_ok=True)


def write_cmake(results: list[dict], out: Path) -> None:
    lines = ["# Generated by spec/tools/asn1_gen.py. Do not edit.", ""]
    runtime: set[str] = set()
    for r in sorted(results, key=lambda r: r["proto"]):
        p = r["proto"].upper()
        d = r["dir"]
        gen = [x for x in (d / "generated-sources.txt").read_text().split() if x]
        runtime |= {x for x in (d / "runtime-sources.txt").read_text().split() if x}
        lines.append(f'set(KSIM_ASN1_{p}_STAMP "{r["stamp"]}")')
        lines.append(f'set(KSIM_ASN1_{p}_DIR "{d}")')
        lines.append(f"set(KSIM_ASN1_{p}_SRCS")
        lines += [f'    "{d}/{g}"' for g in gen]
        lines += [")", ""]
    lines.append("set(KSIM_ASN1_RUNTIME_SRCS")
    lines += [f'    "${{PROJECT_SOURCE_DIR}}/third_party/asn1c/runtime/{n}"' for n in sorted(runtime)]
    lines += [")", ""]
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.write_text("\n".join(lines))
    tmp.replace(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("protos", nargs="*", default=list(PREFIX))
    ap.add_argument("--asn1c", type=Path, default=Path(os.environ.get("KSIM_ASN1C", DEFAULT_ASN1C)))
    ap.add_argument("--cache", type=Path, default=Path(os.environ.get("KSIM_ASN1_CACHE", DEFAULT_CACHE)))
    ap.add_argument("--cmake-out", type=Path, help="write a files.cmake here")
    args = ap.parse_args()
    if not args.asn1c.is_file():
        raise SystemExit(f"ASN1_GEN=FAIL no asn1c at {args.asn1c} (run tools/build-asn1c.sh)")
    results = []
    with cf.ProcessPoolExecutor(max_workers=len(args.protos)) as ex:
        futs = {ex.submit(generate, p, args.asn1c, args.cache): p for p in args.protos}
        for f in cf.as_completed(futs):
            p = futs[f]
            try:
                r = f.result()
            except Exception as e:  # noqa: BLE001
                print(f"ASN1_GEN=FAIL proto={p}: {e}", file=sys.stderr)
                sys.exit(1)
            n = len((r["dir"] / "generated-sources.txt").read_text().split())
            renamed = len((r["dir"] / "postprocess.log").read_text().splitlines())
            print(f"ASN1_GEN proto={p} stamp={r['stamp']} "
                  f"{'generated' if r['generated'] else 'cached'} sources={n} "
                  f"renamed={renamed} seconds={r['seconds']:.0f}")
            results.append(r)
    if args.cmake_out:
        write_cmake(results, args.cmake_out)


if __name__ == "__main__":
    main()
