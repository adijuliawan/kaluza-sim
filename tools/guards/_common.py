# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Shared plumbing for the CI guards in tools/guards/.

Every guard exposes check(root) -> list[Violation] and a --self-test that runs
the check on a temporary tree containing a planted violation. The self-test
fails unless the guard catches the violation and passes the clean files: a guard
that cannot fail is not a guard (plan M1, "must-fail fixtures").
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

# Never scanned: build output, virtualenvs, fetched documents.
SKIP_DIRS = {".git", "build", "out", ".venv", ".cache", "__pycache__", "node_modules"}


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.message}"


def repo_files(root: Path) -> list[Path]:
    """Tracked plus untracked-but-not-ignored files, relative to root.

    In a git checkout this follows .gitignore. In a plain directory (self-tests)
    it walks the tree and skips SKIP_DIRS.
    """
    if (root / ".git").exists():
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            check=True, capture_output=True).stdout
        names = [n for n in out.decode().split("\0") if n]
        return sorted(Path(n) for n in names if (root / n).is_file())
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            found.append(Path(dirpath, f).relative_to(root))
    return sorted(found)


def under(path: Path, *prefixes: str) -> bool:
    parts = path.as_posix()
    return any(parts == p or parts.startswith(p.rstrip("/") + "/") for p in prefixes)


def read_text(root: Path, rel: Path) -> str:
    return (root / rel).read_text(encoding="utf-8", errors="replace")


def write_tree(base: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def run_self_test(name: str, check: Callable[[Path], list[Violation]],
                  clean: dict[str, str], dirty: dict[str, str],
                  expect: Iterable[tuple[str, str]]) -> int:
    """Clean tree must pass; clean+dirty must yield exactly the expected (path, rule) pairs."""
    with tempfile.TemporaryDirectory(prefix=f"ksim-guard-{name}-") as tmp:
        base = Path(tmp)
        write_tree(base, clean)
        got_clean = check(base)
        if got_clean:
            print(f"SELFTEST {name}: FAIL (clean tree flagged)")
            for v in got_clean:
                print(f"  unexpected: {v}")
            return 1
        write_tree(base, dirty)
        got = {(v.path, v.rule) for v in check(base)}
        want = set(expect)
        if got != want:
            print(f"SELFTEST {name}: FAIL")
            for miss in sorted(want - got):
                print(f"  not caught: {miss}")
            for extra in sorted(got - want):
                print(f"  unexpected: {extra}")
            return 1
    print(f"SELFTEST {name}: OK (caught {len(want)} planted violations)")
    return 0


def main(name: str, check: Callable[[Path], list[Violation]],
         self_test: Callable[[], int]) -> None:
    ap = argparse.ArgumentParser(description=f"kaluza-sim guard: {name}")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard catches a planted violation")
    args = ap.parse_args()
    if args.self_test:
        sys.exit(self_test())
    violations = check(args.root)
    for v in violations:
        print(v)
    print(f"GUARD={name} VIOLATIONS={len(violations)}")
    sys.exit(1 if violations else 0)
