#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Verify spec/INDEX.tsv: every listed document is present with its recorded
size and sha256, so every extracted artefact traces to exact bytes.

Exit 0 when all match, 1 on any mismatch or partial absence, and 77 (CI "SKIP")
when no document is present at all (a fresh clone: run spec/tools/fetch.py).
--self-test proves a tampered document is caught.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(root: Path, index: Path) -> tuple[int, int, list[str]]:
    rows = list(csv.DictReader(index.open(newline=""), delimiter="\t"))
    problems: list[str] = []
    present = 0
    for r in rows:
        p = root / r["file"]
        if not p.is_file():
            problems.append(f"MISSING {r['file']}")
            continue
        present += 1
        if str(p.stat().st_size) != r["bytes"]:
            problems.append(f"SIZE {r['file']}: {p.stat().st_size} != {r['bytes']}")
        elif sha256(p) != r["sha256"]:
            problems.append(f"SHA256 {r['file']}: content differs from INDEX.tsv")
    return len(rows), present, problems


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="ksim-verify-index-") as tmp:
        root = Path(tmp)
        doc = root / "spec/3gpp/24/24501-j80.zip"
        doc.parent.mkdir(parents=True)
        doc.write_bytes(b"original bytes")
        index = root / "INDEX.tsv"
        index.write_text("doc\tversion\tfile\tsha256\tbytes\n"
                         f"24.501\tj80\t{doc.relative_to(root)}\t{sha256(doc)}\t{doc.stat().st_size}\n")
        if verify(root, index)[2]:
            print("SELFTEST verify-index: FAIL (clean copy flagged)")
            return 1
        doc.write_bytes(b"tampered bytes")          # same length, different content
        if not any(p.startswith("SHA256") for p in verify(root, index)[2]):
            print("SELFTEST verify-index: FAIL (tampered copy not caught)")
            return 1
    print("SELFTEST verify-index: OK (caught a tampered document)")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        sys.exit(self_test())
    total, present, problems = verify(ROOT, ROOT / "spec" / "INDEX.tsv")
    if present == 0:
        print(f"SPEC_INDEX=SKIP rows={total} present=0 (run spec/tools/fetch.py)")
        sys.exit(77)
    for p in problems:
        print(p)
    print(f"SPEC_INDEX={'FAIL' if problems else 'PASS'} rows={total} present={present} "
          f"problems={len(problems)}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
