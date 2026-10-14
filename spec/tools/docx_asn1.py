#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Extract the ASN.1 modules of a 3GPP specification (.docx inside the .zip).

Clean-room (ADR 0004): written from the WordprocessingML structure and the
specs' own "-- ASN1START" / "-- ASN1STOP" convention, standard library only.

    spec/tools/docx_asn1.py rrc|ngap|f1ap|e1ap|xnap|all   write spec/asn1/<proto>/
    spec/tools/docx_asn1.py --list ngap                     list modules only

Docx traps handled (each has a test in tests/spec_tools/test_docx_asn1.py):
  - w:tab is a sibling of w:t inside a run: it is a real tab character;
  - w:br / w:cr are real line breaks;
  - w:noBreakHyphen is '-', w:softHyphen is nothing;
  - w:delText (tracked deletions) and w:instrText (field codes such as
    PAGEREF/TOC) are not text;
  - text boxes (w:txbxContent) are not part of the paragraph they float in;
  - NBSP, smart quotes and dashes are normalised to ASCII inside ASN.1;
  - a marker split over several runs is still one marker;
  - "-- /<tag>/ ASN1START" blocks (non-normative "/example/", "/bad example/",
    "/example 1/" blocks of 38.331 Annex A) are skipped whole;
  - a STOP marker after code on the same line ("}-- ASN1STOP") still closes;
  - module headers may span lines (name, OID lines, then DEFINITIONS);
  - an unbalanced START/STOP raises an error unless the spec is known to need
    a recorded repair (REPAIRS below, each a -S row).

Output is byte-stable: the same input gives identical files on every run.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

TOOL_VERSION = "1.0"
ROOT = Path(__file__).resolve().parents[2]
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

# Which spec and which modules make each protocol (architecture.md §4.1).
PROTOCOLS: dict[str, dict] = {
    "rrc": {"doc": "38.331", "version": "j40",
            "modules": ["NR-RRC-Definitions", "NR-InterNodeDefinitions"]},
    "ngap": {"doc": "38.413", "version": "j40", "modules": None},   # None: every module
    "f1ap": {"doc": "38.473", "version": "j40", "modules": None},
    "e1ap": {"doc": "37.483", "version": "j40", "modules": None},
    "xnap": {"doc": "38.423", "version": "j40", "modules": None},
}

# Known defects of a pinned document that extraction must repair. Each entry is
# a -S row in docs/compliance/rows.tsv.
#   stop-typo:<text>    a paragraph whose marker text (spaces removed) equals
#                       <text> closes the open block, like ASN1STOP would.
#   split-after:<text>  a line break is missing right after <text>: break there.
# Every listed repair must apply at least once, or extraction fails: a repair
# never silently outlives the defect it was written for.
REPAIRS: dict[tuple[str, str], list[str]] = {
    # TS 37.483 j40: the last ASN.1 block (E1AP-Containers) ends "-- ASN1STO". Row KS-E1AP-S1.
    ("37.483", "j40"): ["stop-typo:--ASN1STO"],
    # TS 38.473 j40, F1AP-Constants: "...ProtocolIE-ID ::= 925id-CSI-RSResourceSetToReleaseList
    # ProtocolIE-ID ::= 926" sits in one paragraph with no break. Row KS-F1AP-S1.
    ("38.473", "j40"): ["split-after:ProtocolIE-ID ::= 925"],
}

_CHAR_MAP = {
    " ": " ", " ": " ", " ": " ", " ": " ",
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-",
    "­": "",
}
_MAP_TABLE = str.maketrans(_CHAR_MAP)

_SKIP_SUBTREES = {W + "pPr", W + "rPr", W + "del", W + "txbxContent", W + "delText",
                  W + "instrText", W + "commentReference", W + "footnoteReference"}
_CONTAINERS = {W + "body", W + "tbl", W + "tr", W + "tc", W + "sdt", W + "sdtContent",
               W + "customXml", W + "ins", W + "smartTag"}


# The STOP marker is an ASN.1 comment: "--" then ASN1STOP. Prose that mentions
# the word (the conventions clause of 38.331 does) is not a marker.
_STOP = re.compile(r"--[ \t]*(/[^/\n]*/[ \t]*)?ASN1STOP")
# Non-normative blocks carry a /tag/ before the marker: "/example/", "/bad example/",
# "/example 1/" (38.331 Annex A). They are skipped whole.
_EXAMPLE = re.compile(r"--[ \t]*/[^/\n]*/[ \t]*ASN1START")


class ExtractError(Exception):
    pass


def paragraphs(elem: ET.Element):
    """w:p elements in document order, descending into tables and content controls."""
    for child in elem:
        if child.tag == W + "p":
            yield child
        elif child.tag in _CONTAINERS:
            yield from paragraphs(child)


def para_text(p: ET.Element) -> str:
    out: list[str] = []

    def walk(e: ET.Element) -> None:
        for c in e:
            tag = c.tag
            if tag in _SKIP_SUBTREES:
                continue
            if tag == W + "t":
                out.append(c.text or "")
            elif tag == W + "tab":
                out.append("\t")
            elif tag in (W + "br", W + "cr"):
                out.append("\n")
            elif tag == W + "noBreakHyphen":
                out.append("-")
            elif tag == W + "softHyphen":
                pass
            elif tag == W + "sym":
                out.append("�")  # a symbol-font glyph; flagged if it lands in ASN.1
            else:
                walk(c)

    walk(p)
    return "".join(out)


@dataclass
class Module:
    name: str
    lines: list[str] = field(default_factory=list)


def document_xml(zip_path: Path) -> bytes:
    with zipfile.ZipFile(zip_path) as zf:
        docx = [n for n in zf.namelist() if n.lower().endswith(".docx")]
        if len(docx) != 1:
            raise ExtractError(f"{zip_path.name}: expected one .docx, found {docx}")
        with zipfile.ZipFile(io.BytesIO(zf.read(docx[0]))) as inner:
            return inner.read("word/document.xml")


def asn1_lines(xml: bytes, repairs: list[str] | None = None) -> list[str]:
    """Every line between ASN1START and ASN1STOP markers, in document order."""
    root = ET.fromstring(xml)
    body = root.find(W + "body")
    if body is None:
        raise ExtractError("no w:body")
    lines: list[str] = []
    inside = False          # inside a normative block
    example = False         # inside a "/example/" block: content dropped
    starts = 0
    typos = {r.split(":", 1)[1] for r in (repairs or []) if r.startswith("stop-typo:")}
    splits = [r.split(":", 1)[1] for r in (repairs or []) if r.startswith("split-after:")]
    applied: set[str] = set()
    for p in paragraphs(body):
        text = para_text(p)
        squashed = text.strip().replace(" ", "").replace("\t", "")
        if "ASN1START" in squashed and squashed.startswith("--"):
            if inside or example:
                raise ExtractError(f"ASN1START #{starts + 1} while a block is still open")
            if _EXAMPLE.search(text):
                example = True
            else:
                inside = True
                starts += 1
            continue
        m_stop = _STOP.search(text)
        stop_at = m_stop.start() if m_stop else -1
        is_typo_stop = squashed in typos
        if stop_at >= 0 or is_typo_stop:
            if not (inside or example):
                raise ExtractError(f"ASN1STOP after block #{starts} without an open block")
            if inside and stop_at >= 0:
                before = text[:stop_at].rstrip()
                if before.strip():
                    lines.append(before.translate(_MAP_TABLE).rstrip())
            if is_typo_stop:
                applied.add("stop-typo:" + squashed)
            inside = example = False
            continue
        if inside:
            for cut in splits:
                at = text.find(cut)
                if at >= 0 and at + len(cut) < len(text) and not text[at + len(cut)].isspace():
                    text = text[:at + len(cut)] + "\n" + text[at + len(cut):]
                    applied.add("split-after:" + cut)
            for ln in text.split("\n"):
                ln = ln.translate(_MAP_TABLE).rstrip()
                if "\ufffd" in ln:
                    raise ExtractError(f"symbol-font glyph inside ASN.1 block #{starts}: {ln!r}")
                lines.append(ln)
    if inside or example:
        raise ExtractError(f"ASN1START #{starts} never closed")
    unused = set(repairs or []) - applied
    if unused:
        raise ExtractError(f"listed repairs did not apply: {sorted(unused)}")
    if starts == 0:
        raise ExtractError("no ASN1START markers")
    return lines


_HEADER = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9-]*)\s*(\{[^}]*\})?\s*DEFINITIONS\b", re.S)
_NAME_START = re.compile(r"^[A-Za-z][A-Za-z0-9-]*(\s|\{|$)")
_MAX_HEADER_LINES = 12


def _strip_comment(ln: str) -> str:
    i = ln.find("--")
    return ln if i < 0 else ln[:i]


def split_modules(lines: list[str]) -> list[Module]:
    """Split ASN.1 text into modules. A module header may span several lines:
    'Name {' + OID lines + '} DEFINITIONS ... ::=' + 'BEGIN'."""
    modules: list[Module] = []
    cur: Module | None = None
    pending: list[str] = []
    for n, ln in enumerate(lines, start=1):
        if cur is None:
            code = _strip_comment(ln).strip()
            if not pending:
                if not code:
                    continue
                if not _NAME_START.match(code):
                    raise ExtractError(f"line {n}: text outside any module: {ln!r}")
            pending.append(ln)
            joined = " ".join(_strip_comment(x).strip() for x in pending)
            m = _HEADER.match(joined)
            if m:
                cur = Module(m.group("name"), pending)
                pending = []
            elif len(pending) > _MAX_HEADER_LINES:
                raise ExtractError(f"line {n}: no DEFINITIONS within {_MAX_HEADER_LINES} lines "
                                   f"of {pending[0]!r}")
            continue
        cur.lines.append(ln)
        if ln.strip() == "END":
            modules.append(cur)
            cur = None
    if cur is not None:
        raise ExtractError(f"module {cur.name} has no END")
    if pending:
        raise ExtractError(f"dangling module header {pending[0]!r}")
    names = [m.name for m in modules]
    if len(set(names)) != len(names):
        raise ExtractError(f"duplicate module names: {names}")
    return modules


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def index_row(doc: str, version: str) -> dict[str, str]:
    with (ROOT / "spec" / "INDEX.tsv").open(newline="") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if r["doc"] == doc and r["version"] == version:
                return r
    raise ExtractError(f"{doc} {version} not in spec/INDEX.tsv (run spec/tools/fetch.py)")


def module_text(mod: Module, header: list[str]) -> str:
    body = list(mod.lines)
    while body and not body[-1].strip():
        body.pop()
    return "\n".join(header + body) + "\n"


def extract(proto: str, write: bool = True, out_root: Path | None = None,
            update_index: bool = True) -> dict:
    cfg = PROTOCOLS[proto]
    row = index_row(cfg["doc"], cfg["version"])
    zip_path = ROOT / row["file"]
    if sha256_file(zip_path) != row["sha256"]:
        raise ExtractError(f"{zip_path} does not match its INDEX.tsv sha256")
    repairs = REPAIRS.get((cfg["doc"], cfg["version"]), [])
    modules = split_modules(asn1_lines(document_xml(zip_path), repairs))
    wanted = cfg["modules"]
    chosen = [m for m in modules if wanted is None or m.name in wanted]
    excluded = [m.name for m in modules if m not in chosen]
    if wanted is not None:
        missing = set(wanted) - {m.name for m in chosen}
        if missing:
            raise ExtractError(f"{proto}: modules not found: {sorted(missing)}")
    header = [
        f"-- Extracted by spec/tools/docx_asn1.py {TOOL_VERSION} from 3GPP TS {cfg['doc']} "
        f"{cfg['version']} ({Path(row['file']).name}, sha256 {row['sha256']}).",
        "-- Do not edit: regenerate with spec/tools/docx_asn1.py. "
        "Text (c) 3GPP; see spec/INDEX.tsv for the source.",
        "",
    ]
    outdir = (out_root or ROOT / "spec" / "asn1") / proto
    manifest = []
    if write:
        outdir.mkdir(parents=True, exist_ok=True)
        for old in outdir.glob("*.asn"):
            old.unlink()
    for m in chosen:
        text = module_text(m, header)
        path = outdir / f"{m.name}.asn"
        if write:
            path.write_text(text, encoding="ascii")
        manifest.append({"module": m.name, "file": f"spec/asn1/{proto}/{m.name}.asn",
                         "lines": str(text.count("\n")),
                         "sha256": hashlib.sha256(text.encode("ascii")).hexdigest()})
    if write:
        with (outdir / "MANIFEST.tsv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["module", "file", "lines", "sha256"], delimiter="\t",
                               lineterminator="\n")
            w.writeheader()
            w.writerows(manifest)
        if update_index:
            record_derived(cfg["doc"], cfg["version"], f"spec/asn1/{proto}/")
    return {"proto": proto, "modules": [m["module"] for m in manifest], "excluded": excluded,
            "lines": sum(int(m["lines"]) for m in manifest)}


def record_derived(doc: str, version: str, artefact: str) -> None:
    """Add an artefact to the 'derived' column of spec/INDEX.tsv (idempotent)."""
    path = ROOT / "spec" / "INDEX.tsv"
    with path.open(newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        fields = reader.fieldnames
        rows = list(reader)
    for r in rows:
        if r["doc"] == doc and r["version"] == version:
            items = [x for x in r["derived"].split(",") if x and x != "-"]
            if artefact not in items:
                items.append(artefact)
            r["derived"] = ",".join(sorted(items)) or "-"
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("proto", choices=[*PROTOCOLS, "all"])
    ap.add_argument("--list", action="store_true", help="list modules, write nothing")
    ap.add_argument("--out", type=Path, help="write under this directory instead of spec/asn1 "
                    "(and leave spec/INDEX.tsv alone); CI uses it to detect drift")
    args = ap.parse_args()
    protos = list(PROTOCOLS) if args.proto == "all" else [args.proto]
    rc = 0
    for p in protos:
        try:
            r = extract(p, write=not args.list, out_root=args.out, update_index=args.out is None)
            print(f"ASN1_EXTRACT proto={p} modules={len(r['modules'])} lines={r['lines']} "
                  f"included={','.join(r['modules'])} excluded={','.join(r['excluded']) or '-'}")
        except ExtractError as e:
            print(f"ASN1_EXTRACT proto={p} FAIL: {e}", file=sys.stderr)
            rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
