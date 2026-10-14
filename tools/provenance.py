#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Provenance scan (plan M14, ADRs 0004 and 0005): does any of our hand-written
code share code with a tree we must not copy from?

    tools/provenance.py build [--tree NAME]   fingerprint the trees of
                                               tools/provenance/trees.tsv into
                                               ~/.cache/kaluza-sim/provenance/ and
                                               rewrite tools/provenance/manifest.tsv
    tools/provenance.py scan                   scan our code; exit 1 on a match,
                                               a missing or stale database
    tools/provenance.py explain <our file>     where a flagged file's shared runs are

Fingerprints are winnowed hashes of token k-grams (Schleimer, Wilkerson and
Aiken, "Winnowing: local algorithms for document fingerprinting", SIGMOD 2003):
comments and include/import lines are dropped, identifiers are lower-cased,
literals kept as written, k = 30 tokens, window w = 20, so any shared run of
k + w - 1 = 49 tokens or more is found; a k-gram with fewer than six
identifiers or keywords (a run of punctuation or numbers) takes no part. The database holds hashes only; the
repository commits a manifest of what was fingerprinted (paths, versions,
counts, digests) and no text of any tree.

A tree is identified by its git HEAD (or, without git, a digest of its file
list): a database built from another version is stale and fails the scan, so
a scan never passes on fingerprints that do not describe the tree as it is.
Files asn1c generated are skipped in the trees (our scan excludes ours too).
"""

from __future__ import annotations

import argparse
import array
import bisect
import csv
import glob
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import zlib
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONF = ROOT / "tools" / "provenance"
CACHE = Path(os.environ.get("KSIM_PROVENANCE_CACHE", Path.home() / ".cache" / "kaluza-sim" / "provenance"))
TOOL_VERSION = "1.1"
K, W = 30, 20
MOD = (1 << 61) - 1
BASE = 1_000_003
CODE_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".py", ".go", ".kt", ".java", ".rs"}
PRUNE = {".git", "build", "node_modules", "target", ".gradle", "__pycache__", ".venv", "venv", ".claude"}
FLAG_AT = 3        # shared fingerprints in one of our files that make a match
MAX_BYTES = 4_000_000

_TOKEN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?|"(?:\\.|[^"\\\n])*"|'
                    r"'(?:\\.|[^'\\\n])*'|::|->|<<=?|>>=?|&&|\|\||[-+*/%&|^!=<>]=?|[{}()\[\];,.:?~#@]")
_C_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_PY_COMMENT = re.compile(r"#[^\n]*")


_INCLUDE = re.compile(r"^[ \t]*#[ \t]*(?:include|import)\b[^\n]*$", re.M)
_PY_IMPORT = re.compile(r"^[ \t]*(?:from[ \t]+\S+[ \t]+)?import[ \t]+[^\n]*$", re.M)
_WORD = re.compile(r"[A-Za-z_]")
MIN_WORDS = 6   # a k-gram needs this many identifiers or keywords (no runs of punctuation or numbers)


def tokens(text: str, suffix: str) -> list[tuple[int, bool]]:
    """(token hash, is a word) with comments and include/import lines dropped;
    identifiers lower-cased, literals kept as written."""
    if suffix == ".py":
        text = _PY_IMPORT.sub(" ", _PY_COMMENT.sub(" ", text))
    else:
        text = _INCLUDE.sub(" ", _C_COMMENT.sub(" ", text))
    out = []
    for t in _TOKEN.findall(text):
        word = bool(_WORD.match(t))
        out.append((zlib.crc32((t.lower() if word else t).encode()), word))
    return out


def fingerprints(toks: list[tuple[int, bool]]) -> set[int]:
    """Winnowing: the minimum k-gram hash of each window of W, once per position;
    k-grams with fewer than MIN_WORDS words take no part."""
    if len(toks) < K:
        return set()
    hashes: list[int] = []
    h = 0
    words = 0
    top = pow(BASE, K - 1, MOD)
    for i, (t, w) in enumerate(toks):
        if i >= K:
            h = (h - toks[i - K][0] * top) % MOD
            words -= toks[i - K][1]
        h = (h * BASE + t) % MOD
        words += w
        if i >= K - 1:
            hashes.append(h if words >= MIN_WORDS else MOD)   # MOD: never a minimum worth keeping
    if len(hashes) < W:
        m = min(hashes)
        return set() if m == MOD else {m}
    out = set()
    last = -1
    dq: deque[int] = deque()   # positions of increasing hashes; equal ones keep the rightmost
    for i, h in enumerate(hashes):
        while dq and hashes[dq[-1]] >= h:
            dq.pop()
        dq.append(i)
        if dq[0] <= i - W:
            dq.popleft()
        if i >= W - 1 and dq[0] != last:
            last = dq[0]
            if hashes[last] != MOD:
                out.add(hashes[last])
    return out


def file_fingerprints(path: str) -> set[int]:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_BYTES:
            return set()
        text = p.read_text(errors="replace")
    except OSError:
        return set()
    if "Generated by asn1c" in text[:4096] or "asn1c-skeletons" in text[:4096]:
        return set()
    return fingerprints(tokens(text, p.suffix))


def code_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE and not d.startswith("cmake-build")]
        for f in filenames:
            if Path(f).suffix in CODE_EXT:
                yield Path(dirpath) / f


def identity(path: Path) -> str:
    """The git HEAD of a tree that is a repository's top level; otherwise (a
    package directory inside some other checkout) a digest of its file list."""
    top = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if top.returncode == 0 and Path(top.stdout.strip()).resolve() == path.resolve():
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True)
        return "git:" + r.stdout.strip()
    h = hashlib.sha256()
    for f in sorted(code_files(path)):
        st = f.stat()
        h.update(f"{f.relative_to(path)}\t{st.st_size}\t{int(st.st_mtime)}\n".encode())
    return "files:" + h.hexdigest()[:16]


def load_trees(conf: Path = CONF) -> list[dict]:
    with (conf / "trees.tsv").open() as f:
        rows = list(csv.DictReader((ln for ln in f if not ln.startswith("#")), delimiter="\t"))
    for r in rows:
        paths = []
        for p in r["paths"].split(";"):
            p = os.path.expandvars(os.path.expanduser(p))
            matches = sorted(glob.glob(p)) if any(c in p for c in "*?[") else [p]
            paths += [Path(m) for m in matches] or [Path(p)]
        r["paths"] = paths
    return rows


def build_tree(tree: dict, cache: Path) -> dict:
    present = [p for p in tree["paths"] if p.is_dir()]
    meta = {"tree": tree["name"], "tool": TOOL_VERSION, "k": K, "w": W, "paths": [str(p) for p in tree["paths"]],
            "present": [str(p) for p in present], "identities": {str(p): identity(p) for p in present}}
    files = [str(f) for p in present for f in code_files(p)]
    fps: set[int] = set()
    with ProcessPoolExecutor(max_workers=max(1, (os.cpu_count() or 2) - 2)) as ex:
        for s in ex.map(file_fingerprints, files, chunksize=64):
            fps |= s
    arr = array.array("Q", sorted(fps))
    cache.mkdir(parents=True, exist_ok=True)
    data = arr.tobytes()
    (cache / f"{tree['name']}.fp").write_bytes(data)
    meta.update({"files": len(files), "fingerprints": len(arr), "sha256": hashlib.sha256(data).hexdigest()})
    (cache / f"{tree['name']}.json").write_text(json.dumps(meta, indent=1) + "\n")
    return meta


def write_manifest(trees: list[dict], cache: Path, conf: Path = CONF, dry: bool = False) -> str:
    buf = io.StringIO()
    buf.write("# SPDX-FileCopyrightText: 2026 Adi Juliawan\n# SPDX-License-Identifier: LicenseRef-kaluza-sim-private\n"
              "# Provenance database manifest (tools/provenance.py build). The fingerprints stay in\n"
              "# ~/.cache/kaluza-sim/provenance/; nothing of any tree is committed. Do not edit.\n")
    w = csv.writer(buf, delimiter="\t", lineterminator="\n")
    w.writerow(["tree", "licence", "policy", "present", "identities", "files", "fingerprints", "sha256"])
    for t in trees:
        mp = cache / f"{t['name']}.json"
        m = json.loads(mp.read_text()) if mp.is_file() else {}
        w.writerow([t["name"], t["licence"], t["policy"], len(m.get("present", [])) or "absent",
                    ";".join(f"{Path(p).name}={i}" for p, i in m.get("identities", {}).items()),
                    m.get("files", 0), m.get("fingerprints", 0), m.get("sha256", "")])
    if not dry:
        (conf / "manifest.tsv").write_text(buf.getvalue())
    return buf.getvalue()


def our_files(root: Path = ROOT):
    """Our hand-written code: src, apps, tools, tests and spec/tools; not
    third_party, generated output, vectors or spec text."""
    for top in ("src", "apps", "tools", "tests", "spec/tools", "cmake"):
        base = root / top
        if not base.is_dir():
            continue
        for f in code_files(base):
            rel = f.relative_to(root).as_posix()
            if rel.startswith(("tests/vectors/", "tools/provenance/fixtures/")):
                continue
            yield f


def load_db(tree: dict, cache: Path) -> tuple[array.array | None, str]:
    """The tree's fingerprints, or None and why the database cannot be used."""
    mp, fp = cache / f"{tree['name']}.json", cache / f"{tree['name']}.fp"
    present = [p for p in tree["paths"] if p.is_dir()]
    if not present:
        return None, "absent"
    if not mp.is_file() or not fp.is_file():
        return None, "MISSING"
    meta = json.loads(mp.read_text())
    data = fp.read_bytes()
    if meta.get("tool") != TOOL_VERSION or meta.get("k") != K or meta.get("w") != W:
        return None, "STALE (built by another tool version)"
    if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
        return None, "STALE (fingerprint file does not match its manifest)"
    for p in present:
        if meta.get("identities", {}).get(str(p)) != identity(p):
            return None, f"STALE ({p.name} moved to another version)"
    arr = array.array("Q")
    arr.frombytes(data)
    return arr, "ok"


def contains(arr: array.array, x: int) -> bool:
    i = bisect.bisect_left(arr, x)
    return i < len(arr) and arr[i] == x


def allowed(conf: Path = CONF) -> list[tuple[str, str]]:
    p = conf / "allow.tsv"
    if not p.is_file():
        return []
    with p.open() as f:
        rows = list(csv.DictReader((ln for ln in f if not ln.startswith("#")), delimiter="\t"))
    return [(r["file"], r["tree"]) for r in rows]


def scan(cache: Path = CACHE, conf: Path = CONF, root: Path = ROOT, quiet: bool = False, verbose: bool = False) -> int:
    trees = load_trees(conf)
    dbs, problems = {}, []
    for t in trees:
        arr, why = load_db(t, cache)
        if arr is not None:
            dbs[t["name"]] = (t, arr)
        elif why != "absent":
            problems.append(f"{t['name']}: {why}")
        elif not quiet:
            print(f"PROVENANCE_TREE {t['name']}=absent (not on this machine)")
    if not problems and dbs:
        committed = conf / "manifest.tsv"
        if not committed.is_file() or committed.read_text() != write_manifest(trees, cache, conf, dry=True):
            problems.append("manifest.tsv: not the manifest of this database (run tools/provenance.py build)")
    allow = allowed(conf)
    matches, minor = [], 0
    files = list(our_files(root))
    for f in files:
        fps = file_fingerprints(str(f))
        rel = f.relative_to(root).as_posix()
        for name, (t, arr) in dbs.items():
            shared = sum(1 for x in fps if contains(arr, x))
            if not shared:
                continue
            if t["policy"] == "third-party-only" and rel.startswith("third_party/"):
                continue
            if any(rel == a and name == tr for a, tr in allow):
                continue
            if shared >= FLAG_AT:
                matches.append((rel, name, shared, len(fps)))
            else:
                minor += 1
                if verbose:
                    print(f"PROVENANCE_BELOW {rel} shares {shared}/{len(fps)} with {name}")
    for rel, name, shared, n in matches:
        print(f"PROVENANCE_MATCH {rel} shares {shared}/{n} fingerprints with {name}")
    for p in problems:
        print(f"PROVENANCE_DB {p}")
    ok = not matches and not problems
    print(f"PROVENANCE={'PASS' if ok else 'FAIL'} files={len(files)} trees={len(dbs)} matches={len(matches)} "
          f"below_threshold={minor} database_problems={len(problems)}")
    return 0 if ok else 1


def explain(target: Path, cache: Path = CACHE, conf: Path = CONF) -> int:
    """Re-fingerprint the trees file by file to show where a flagged file's runs come from."""
    ours = file_fingerprints(str(target))
    for t in load_trees(conf):
        for p in t["paths"]:
            if not p.is_dir():
                continue
            for f in code_files(p):
                shared = ours & file_fingerprints(str(f))
                if shared:
                    print(f"{t['name']}\t{f}\t{len(shared)}")
    return 0


def self_test() -> int:
    """Must-fail cases on a synthetic tree (no third-party text): a copied run
    must be found, an unrelated file must not, a missing or stale database must
    fail the scan."""
    import random
    rng = random.Random(7)
    words = [f"name{i}" for i in range(400)] + list("+-*/=;(){}[]<>,.")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        tree, repo, cache, conf = td / "tree", td / "repo", td / "cache", td / "conf"
        (tree / "lib").mkdir(parents=True)
        (repo / "src").mkdir(parents=True)
        conf.mkdir()
        body = " ".join(rng.choice(words) for _ in range(3000))   # mostly identifiers
        (tree / "lib" / "a.c").write_text(body)
        (repo / "src" / "copied.cpp").write_text("int ours = 1;\n" + " ".join(body.split()[1000:1120]) + "\n")
        (repo / "src" / "own.cpp").write_text(" ".join(rng.choice(words) for _ in range(800)))
        (conf / "trees.tsv").write_text("name\tpaths\tlicence\tpolicy\tnote\nsynthetic\t" + str(tree)
                                        + "\tGPL-3.0\tforbidden\tself-test\n")
        trees = load_trees(conf)
        results = []
        rc = scan(cache, conf, repo, quiet=True)
        results.append(("a missing database fails", rc == 1))
        build_tree(trees[0], cache)
        write_manifest(trees, cache, conf)
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            rc = scan(cache, conf, repo, quiet=True)
        finally:
            sys.stdout = old
        text = out.getvalue()
        results.append(("a copied 120-token run is found", rc == 1 and "src/copied.cpp" in text))
        results.append(("an unrelated file is not", "src/own.cpp" not in text))
        (repo / "src" / "copied.cpp").unlink()
        sys.stdout = io.StringIO()
        try:
            rc_clean = scan(cache, conf, repo, quiet=True)
            manifest = (conf / "manifest.tsv").read_text()
            (conf / "manifest.tsv").write_text(manifest.replace("synthetic\t", "synthetic-other\t"))
            rc_manifest = scan(cache, conf, repo, quiet=True)
            (conf / "manifest.tsv").write_text(manifest)
            meta = json.loads((cache / "synthetic.json").read_text())
            meta["identities"] = {k: "files:0000" for k in meta["identities"]}
            (cache / "synthetic.json").write_text(json.dumps(meta))
            rc_stale = scan(cache, conf, repo, quiet=True)
        finally:
            sys.stdout = old
        results.append(("without the copy the scan passes", rc_clean == 0))
        results.append(("a committed manifest that is not the database's fails", rc_manifest == 1))
        results.append(("a stale database fails", rc_stale == 1))
    for name, ok in results:
        print(f"PROVENANCE_SELFTEST {'CAUGHT' if ok else 'MISSED'} {name}")
    ok = all(c for _, c in results)
    print(f"PROVENANCE_SELFTEST={'PASS' if ok else 'FAIL'} cases={len(results)}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["build", "scan", "explain", "self-test"])
    ap.add_argument("target", nargs="?")
    ap.add_argument("--tree", action="append")
    ap.add_argument("--verbose", action="store_true", help="scan: list the pairs below the threshold too")
    a = ap.parse_args()
    if a.command == "self-test":
        return self_test()
    if a.command == "scan":
        return scan(verbose=a.verbose)
    if a.command == "explain":
        return explain(Path(a.target))
    trees = load_trees()
    for t in trees:
        if a.tree and t["name"] not in a.tree:
            continue
        if not any(p.is_dir() for p in t["paths"]):
            print(f"PROVENANCE_BUILD {t['name']}=absent")
            continue
        m = build_tree(t, CACHE)
        print(f"PROVENANCE_BUILD {t['name']} files={m['files']} fingerprints={m['fingerprints']}")
    write_manifest(trees, CACHE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
