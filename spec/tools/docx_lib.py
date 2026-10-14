# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Document-order access to a 3GPP .docx: paragraphs with their style, and
tables as rows of cell texts (clean-room, standard library only).

Paragraph text follows the same rules as docx_asn1.py (tabs, breaks, hyphens,
field codes, deletions and text boxes), whose para_text() this module reuses.
Tables: horizontally merged cells (w:gridSpan) occupy one entry but carry their
span; vertically merged continuation cells (w:vMerge without "restart") repeat
the text of the cell above, so every row has its full column set.
"""

from __future__ import annotations

import csv
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docx_asn1 as _dx  # noqa: E402

W = _dx.W
ROOT = _dx.ROOT
para_text = _dx.para_text
ExtractError = _dx.ExtractError


@dataclass
class Para:
    style: str
    text: str


@dataclass
class Cell:
    text: str
    span: int = 1


@dataclass
class Table:
    rows: list[list[Cell]]

    def texts(self) -> list[list[str]]:
        return [[c.text for c in r] for r in self.rows]


def _style(p: ET.Element) -> str:
    ps = p.find(W + "pPr/" + W + "pStyle")
    return ps.get(W + "val", "") if ps is not None else ""


# Characters set with a Word SYMBOL field ({ SYMBOL 68 \\f "Symbol" }): the glyph
# is the field instruction, which para_text() rightly skips. 23.038's alphabet
# writes its Greek letters this way. Symbol-font code -> Unicode, the letters only.
_SYMBOL_FIELD = re.compile(r'SYMBOL\s+(\d+)\s+\\f\s+"Symbol"')
SYMBOL_FONT = {
    65: "\u0391", 66: "\u0392", 67: "\u03a7", 68: "\u0394", 69: "\u0395", 70: "\u03a6",
    71: "\u0393", 72: "\u0397", 73: "\u0399", 75: "\u039a", 76: "\u039b", 77: "\u039c",
    78: "\u039d", 79: "\u039f", 80: "\u03a0", 81: "\u0398", 82: "\u03a1", 83: "\u03a3",
    84: "\u03a4", 85: "\u03a5", 87: "\u03a9", 88: "\u039e", 89: "\u03a8", 90: "\u0396",
}


def _symbol_fields(e: ET.Element) -> str:
    out = []
    for it in e.iter(W + "instrText"):
        m = _SYMBOL_FIELD.search(it.text or "")
        if m:
            code = int(m.group(1))
            if code not in SYMBOL_FONT:
                raise ExtractError(f"SYMBOL field with unmapped Symbol-font code {code}")
            out.append(SYMBOL_FONT[code])
    return "".join(out)


def _cell_text(tc: ET.Element) -> str:
    return ("\n".join(para_text(p) for p in tc.iter(W + "p")).strip() + _symbol_fields(tc))


def _table(tbl: ET.Element) -> Table:
    rows: list[list[Cell]] = []
    above: dict[int, str] = {}           # grid column -> text, for vMerge continuation
    for tr in tbl.findall(W + "tr"):
        row: list[Cell] = []
        col = 0
        for tc in tr.findall(W + "tc"):
            pr = tc.find(W + "tcPr")
            span = 1
            vmerge = None
            if pr is not None:
                gs = pr.find(W + "gridSpan")
                if gs is not None:
                    span = int(gs.get(W + "val", "1"))
                vm = pr.find(W + "vMerge")
                if vm is not None:
                    vmerge = vm.get(W + "val", "continue")
            text = _cell_text(tc)
            if vmerge == "continue":
                text = above.get(col, "")
            else:
                above[col] = text
            row.append(Cell(text, span))
            col += span
        rows.append(row)
    return Table(rows)


def body_items(zip_path: Path) -> list[Para | Table]:
    """Top-level paragraphs and tables of the document body, in order."""
    root = ET.fromstring(_dx.document_xml(zip_path))
    body = root.find(W + "body")
    if body is None:
        raise ExtractError("no w:body")
    out: list[Para | Table] = []
    for e in body:
        if e.tag == W + "p":
            out.append(Para(_style(e), para_text(e)))
        elif e.tag == W + "tbl":
            out.append(_table(e))
        elif e.tag == W + "sdt":
            for p in _dx.paragraphs(e):
                out.append(Para(_style(p), para_text(p)))
    return out


def source(doc: str, version: str) -> tuple[Path, dict[str, str]]:
    """The pinned document's zip, verified against spec/INDEX.tsv."""
    row = _dx.index_row(doc, version)
    path = ROOT / row["file"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
        raise ExtractError(f"{path} does not match its INDEX.tsv sha256")
    return path, row


def header_lines(tool: str, version: str, doc: str, docver: str, row: dict[str, str]) -> list[str]:
    return [f"# Extracted by spec/tools/{tool} {version} from 3GPP TS {doc} {docver} "
            f"({Path(row['file']).name}, sha256 {row['sha256']}). Do not edit."]


def write_tsv(path: Path, header: list[str], fields: list[str], rows: list[dict]) -> None:
    """TSV with leading '#' comment lines, then a header row. Byte-stable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        for h in header:
            f.write(h + "\n")
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n",
                           extrasaction="raise")
        w.writeheader()
        for r in rows:
            w.writerow({k: str(v).replace("\t", " ").replace("\n", " / ") for k, v in r.items()})


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        lines = [ln for ln in f if not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t"))
