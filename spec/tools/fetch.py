#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Fetch the pinned spec documents and write spec/INDEX.tsv (docs/specs.md).

    spec/tools/fetch.py            fetch what is missing, then (re)write INDEX.tsv
    spec/tools/fetch.py --t0       also list the 3GPP archive and report, per spec,
                                   whether a higher Rel-19 ('j') version exists

Input:  spec/manifest.tsv (doc, version, origin, purpose).
Output: documents under spec/3gpp/<series>/, spec/etsi/, spec/ietf/,
        spec/3gpp/sage/ (all gitignored), and spec/INDEX.tsv (tracked).

A document kaluza-core already holds (docs/3gpp/ts/<series>-series/) is copied
byte for byte. Everything else is downloaded. The 3GPP archive refuses curl's
default User-Agent, so a browser one is sent. Nothing here reads kaluza-core
beyond those document files (ADR 0005 allows the documents, not their reading).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import re
import shutil
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "spec" / "manifest.tsv"
INDEX = ROOT / "spec" / "INDEX.tsv"
CORE_SPECS = Path("/home/amadeus/Development/kaluza-core/docs/3gpp/ts")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/130.0 Safari/537.36")
ARCHIVE = "https://www.3gpp.org/ftp/Specs/archive"

INDEX_COLUMNS = ["doc", "version", "file", "sha256", "bytes", "origin", "source_url",
                 "fetched_utc", "derived"]


@dataclass
class Doc:
    doc: str
    version: str
    origin: str
    purpose: str

    @property
    def nodot(self) -> str:
        return self.doc.replace(".", "")

    @property
    def series(self) -> str:
        return self.doc.split(".", 1)[0]

    def target(self) -> tuple[Path, str]:
        """Local path (relative to ROOT) and canonical source URL."""
        if self.origin == "3gpp":
            name = f"{self.nodot}-{self.version}.zip"
            return (Path("spec/3gpp") / self.series / name,
                    f"{ARCHIVE}/{self.series}_series/{self.doc}/{name}")
        if self.origin == "etsi":
            # ETSI TS 102 221 V18.4.0 -> .../102200_102299/102221/18.04.00_60/ts_102221v180400p.pdf
            num = self.nodot                      # 102221
            ver = self.version.replace(".", "")   # 180400
            lo = int(num) // 100 * 100
            name = f"ts_{num}v{ver}p.pdf"
            return (Path("spec/etsi") / name,
                    f"https://www.etsi.org/deliver/etsi_ts/{lo}_{lo + 99}/{num}/"
                    f"{self.version}_60/{name}")
        if self.origin == "ietf":
            return (Path("spec/ietf") / f"{self.doc}.txt",
                    f"https://www.rfc-editor.org/rfc/{self.doc}.txt")
        if self.origin == "sage":
            name = "Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.pdf"
            return (Path("spec/3gpp/sage") / name, f"local-only:{CORE_SPECS / 'sage' / name}")
        raise ValueError(f"unknown origin {self.origin!r} for {self.doc}")

    def core_copy(self) -> Path | None:
        if self.origin == "3gpp":
            p = CORE_SPECS / f"{self.series}-series" / f"{self.nodot}-{self.version}.zip"
        elif self.origin == "sage":
            p = CORE_SPECS / "sage" / "Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.pdf"
        else:
            return None
        return p if p.is_file() else None


def load_manifest() -> list[Doc]:
    with MANIFEST.open(newline="") as f:
        return [Doc(r["doc"], r["version"], r["origin"], r["purpose"])
                for r in csv.DictReader(f, delimiter="\t")]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def load_index() -> dict[tuple[str, str], dict[str, str]]:
    if not INDEX.is_file():
        return {}
    with INDEX.open(newline="") as f:
        return {(r["doc"], r["version"]): r for r in csv.DictReader(f, delimiter="\t")}


def fetch(docs: list[Doc]) -> int:
    old = load_index()
    rows = []
    failures = 0
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for d in docs:
        rel, url = d.target()
        dest = ROOT / rel
        prev = old.get((d.doc, d.version), {})
        origin = prev.get("origin", "")
        fetched = prev.get("fetched_utc", "")
        if not dest.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = d.core_copy()
            try:
                if src is not None:
                    shutil.copyfile(src, dest)
                    origin = "kaluza-core-copy"
                elif url.startswith("local-only:"):
                    raise FileNotFoundError(url)
                else:
                    dest.write_bytes(http_get(url))
                    origin = "download"
                fetched = now
                print(f"FETCHED {d.doc} {d.version} ({origin})")
            except Exception as e:  # noqa: BLE001 - report every failure, continue
                print(f"FAILED {d.doc} {d.version}: {e}", file=sys.stderr)
                failures += 1
                continue
        rows.append({
            "doc": d.doc, "version": d.version, "file": rel.as_posix(),
            "sha256": sha256(dest), "bytes": str(dest.stat().st_size),
            "origin": origin or "present", "source_url": url,
            "fetched_utc": fetched or now, "derived": prev.get("derived", "-"),
        })
    with INDEX.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=INDEX_COLUMNS, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"INDEX_ROWS={len(rows)} FAILED={failures}")
    return failures


_B36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def version_key(v: str) -> tuple[int, int, int]:
    """'j4a' -> (19, 4, 10): 3GPP encodes each field as one base-36 character (j = 19)."""
    return (_B36.index(v[0]), _B36.index(v[1]), _B36.index(v[2]))


def t0(docs: list[Doc]) -> int:
    newer = 0
    for d in docs:
        if d.origin != "3gpp":
            continue
        try:
            listing = http_get(f"{ARCHIVE}/{d.series}_series/{d.doc}/").decode("latin-1")
        except Exception as e:  # noqa: BLE001
            print(f"T0 {d.doc}: listing failed: {e}", file=sys.stderr)
            newer += 1
            continue
        found = set(re.findall(rf"{re.escape(d.nodot)}-(j[0-9a-z]{{2}})\.zip", listing))
        if not found:
            print(f"T0 {d.doc}: no Rel-19 versions listed")
            continue
        latest = max(found, key=version_key)
        state = "PINNED_IS_LATEST" if latest == d.version else f"NEWER_AVAILABLE={latest}"
        if latest != d.version:
            newer += 1
        print(f"T0 {d.doc} pinned={d.version} latest_j={latest} {state}")
    print(f"T0_NEWER_COUNT={newer}")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--t0", action="store_true", help="re-read the archive for newer j versions")
    args = ap.parse_args()
    docs = load_manifest()
    rc = fetch(docs)
    if args.t0:
        t0(docs)
    sys.exit(1 if rc else 0)


if __name__ == "__main__":
    main()
