#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Extract known-answer test vectors from the pinned documents (plan M7).

    spec/tools/kat_extract.py [name...] [--out DIR]     write spec/kat/<name>.tsv

Every vector row records the document, version and clause it came from, the
test set, the field name as the document prints it, the value in lower-case hex
and its length in bits. A field the document gives in both binary and hex is
read in both forms and they must agree. Each source declares the sets and
fields it must contain, and a missing or extra set fails the run.

Value forms understood (each seen in a pinned document):
    K:\t\t\tabab...                     35.233 (TUAK), 35.208 hex block
    K:\t01000110 01011011 ...           35.208 binary block ("Binary Format")
    Key        = (hex) d3c5d592 ...      33.401 Annex C, with (bin) twins and
                 continuation lines      indented continuations
    OP = { c0 c1 ... }                   35.236 (MILENAGE-256), across lines
    Home Network Private Key:  / 'c53c..'   33.501 C.4 (label line, quoted value)
    IN: / 24 76 d2 ...                   35.233 Keccak sets (label, then lines)
    CK':          0093 962d ...          RFC 9048 Appendix D
    Count-C    = 72A4F20F, Plaintext:    SAGE UEA2/UIA2 Document 3 (PDF text)
plus one table form: 35.208 §3.3.2 (Rijndael, Set | Plaintext | Ciphertext | Key),
and the SAGE UEA2 keystream table, whose "enc/dec data" column is the
ciphertext.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docx_lib as dl  # noqa: E402

TOOL_VERSION = "1.1"
ROOT = dl.ROOT
HEX = set("0123456789abcdefABCDEF")
TABLE_ROW = "\x00row\x00"   # marks a flattened table row: cells joined by tabs


@dataclass
class Vec:
    set: str
    field: str
    hex: str = ""
    bits: int | None = None
    clause: str = ""
    text: str = ""          # a value the document gives as text (an NAI-form SUCI)


# Labels whose value may be text rather than hex (33.501 C.4: the network
# specific identifier SUCI 'ecckey<..>.cip<..>.mac<..>').
TEXT_LABELS = {"Scheme Output", "Network name"}


@dataclass
class Collector:
    """Turns a stream of text lines into labelled values for one test set."""
    mode: str = "hex"                 # default radix: hex unless marked binary
    values: dict = field(default_factory=dict)      # field -> {"hex": str, "bin": str}
    params: dict = field(default_factory=dict)      # Length = 253 bits etc.
    texts: dict = field(default_factory=dict)       # TEXT_LABELS values given as text
    _text_label: str | None = None
    _label: str | None = None
    _radix: str = "hex"
    _brace: bool = False

    def _add(self, label: str, radix: str, text: str) -> None:
        slot = self.values.setdefault(label, {"hex": "", "bin": ""})
        slot[radix] += text

    def feed(self, raw: str) -> None:
        if raw.startswith(TABLE_ROW):           # "Variable | Value" tables (35.208 sets 2-20)
            cells = [c.strip() for c in raw[len(TABLE_ROW):].split("\t")]
            self._label = None
            if len(cells) >= 2 and cells[0] and _is_value(cells[1]) and cells[0] != "Variable":
                self._add(cells[0], self.mode, cells[1])
            return
        line = raw.replace("\u00a0", " ").replace("\u2019", "'").replace("\u2018", "'").rstrip()
        stripped = line.strip()
        if not stripped:
            if not self._brace:
                self._label = None
            return
        if self._text_label:                     # "Scheme Output:" then the value on the next line
            if not _is_value(stripped.strip("'\"")):
                self.texts[self._text_label] = stripped
                self._text_label = None
                return
            self._text_label = None
        if self._brace:                          # inside { ... }
            body = stripped.split("}", 1)[0]
            self._add(self._label, "hex", body)
            if "}" in stripped:
                self._brace = False
                self._label = None
            return
        m = re.match(r"^(?P<label>[A-Za-z][\w*'.\- ()/]*?)\s*(?P<sep>=|:)\s*(?P<rest>.*)$", stripped)
        if m:
            label = m.group("label").strip()
            rest = m.group("rest").strip()
            pm = re.fullmatch(r"(\d+)\s*bits?", rest)
            if pm:                                  # Length = 253 bits
                self.params[label] = int(pm.group(1))
                self._label = None
                return
            if "," in rest and "=" in rest:          # Klength = 128 bits, MAClength = ...
                for part in [stripped] + []:
                    for name, num in re.findall(r"([A-Za-z_][\w]*)\s*=\s*(\d+)", part):
                        self.params[name] = int(num)
                self._label = None
                return
            radix = self.mode
            rm = re.match(r"^\((hex|bin)\)\s*(.*)$", rest)
            if rm:
                radix, rest = rm.group(1), rm.group(2)
            if rest.startswith("{"):
                self._label, self._radix, self._brace = label, "hex", True
                body = rest[1:]
                self._add(label, "hex", body.split("}", 1)[0])
                if "}" in body:
                    self._brace, self._label = False, None
                return
            rest = rest.strip("'\"")
            if label in TEXT_LABELS and not rest:
                self._text_label = label             # value on the next line, hex or text
            if rest and not _is_value(rest):          # prose after a colon: not a vector
                if label in TEXT_LABELS:
                    self.texts[label] = rest
                self._label = None
                return
            self._label, self._radix = label, radix
            if rest:
                self._add(label, radix, rest)
            return
        if self._label and _is_value(stripped.strip("'\"")):   # continuation line
            self._add(self._label, self._radix, stripped.strip("'\""))
            return
        self._label = None                                     # anything else ends a value

    def vectors(self, set_name: str, clause: str) -> list[Vec]:
        out = []
        for label, v in self.values.items():
            h = re.sub(r"[^0-9a-fA-F]", "", v["hex"]).lower()
            b = re.sub(r"[^01]", "", v["bin"])
            bits = self.params.get("Length") or self.params.get("LENGTH")
            if b:
                hb = _bin_to_hex(b)
                # 33.401 writes BEARER and DIRECTION right-aligned (a 5-bit bearer
                # 10101 is hex 15) and data left-aligned (253 bits in 64 hex digits).
                if h and int(h, 16) != int(b, 2) and not _same_left_aligned(h, hb, len(b)):
                    raise dl.ExtractError(f"{clause} set {set_name} {label}: hex {h} != bin {b}")
                h = h or hb
                nbits = len(b)
            else:
                nbits = len(h) * 4
            if not h:
                continue
            out.append(Vec(set_name, label, h, nbits, clause))
        for name, num in self.params.items():
            out.append(Vec(set_name, name, f"{num:x}", None, clause))
        for name, text in self.texts.items():
            if name not in {v.field for v in out}:
                out.append(Vec(set_name, name, "", None, clause, text))
        return out


def _is_value(s: str) -> bool:
    t = s.replace(" ", "").replace("\t", "")
    return bool(t) and all(c in HEX for c in t)


def _bin_to_hex(b: str) -> str:
    pad = (-len(b)) % 4
    v = int(b + "0" * pad, 2)
    return f"{v:0{(len(b) + pad) // 4}x}"


def _same_left_aligned(h: str, hb: str, nbits: int) -> bool:
    """Compare the first nbits of two left-aligned hex strings."""
    n = (nbits + 3) // 4
    a, b = h[:n].ljust(n, "0"), hb[:n].ljust(n, "0")
    ia, ib = int(a, 16), int(b, 16)
    shift = n * 4 - nbits
    return (ia >> shift) == (ib >> shift)


# ---- document sources ------------------------------------------------------------

def docx_lines_by_clause(doc: str, ver: str, clause_re: str):
    """(clause, set label, lines) for every heading matching clause_re (group 1 = set)."""
    path, row = dl.source(doc, ver)
    items = dl.body_items(path)
    out, cur = [], None
    for it in items:
        if isinstance(it, dl.Para) and it.style.startswith("Heading"):
            num, _, title = it.text.strip().partition("\t")
            m = re.match(clause_re, num.strip())
            if m:
                cur = (num.strip(), m.group(1), [])
                out.append(cur)
            elif cur is not None and _depth(num) <= _depth(cur[0]):
                cur = None
            continue
        if cur is None:
            continue
        if isinstance(it, dl.Para):
            cur[2].extend(it.text.split("\n"))
        else:
            for r in it.texts():
                cur[2].append(TABLE_ROW + "\t".join(r))
    return out, row


# Fields that carry a bit string of the set's Length (33.401 Annex C, SAGE Document 3).
DATA_FIELDS = {"Plaintext", "Ciphertext", "Message", "MESSAGE"}


def _length_problems(name: str, vecs: list[Vec]) -> list[str]:
    """A data field shorter than its set's Length means the extraction lost text."""
    out = []
    by_set: dict[str, dict[str, Vec]] = {}
    for v in vecs:
        by_set.setdefault(v.set, {})[v.field] = v
    for s, f in by_set.items():
        ln = f.get("Length") or f.get("LENGTH")
        if not ln:
            continue
        need = int(ln.hex, 16)
        for d in DATA_FIELDS & f.keys():
            have = len(f[d].hex) * 4
            if have < need:
                out.append(f"{name}: set {s} {d} has {have} bits, Length is {need}")
    return out


def _depth(num: str) -> int:
    return num.strip().count(".") + 1 if num.strip() else 99


def collect(lines: list[str], mode_markers: dict[str, str] | None = None) -> Collector:
    c = Collector()
    for ln in lines:
        mk = (mode_markers or {}).get(ln.strip())
        if mk:
            c.mode = mk
            c._label = None
            continue
        c.feed(ln)
    return c


# ---- sources -----------------------------------------------------------------------

# 35.208 and 35.233 print some sets twice, under these headings; both forms are
# read and must agree.
FORMAT_MARKERS = {"Binary Format": "bin", "Hexadecimal Format": "hex"}


def src_milenage():
    sets, row = docx_lines_by_clause("35.208", "j00", r"^4\.3\.(\d+)$")
    out = []
    for clause, n, lines in sets:
        c = collect(lines, FORMAT_MARKERS)
        out += c.vectors(n, clause)
    return out, row, {"sets": 20, "fields": {"K", "RAND", "SQN", "AMF", "OP", "OPC", "f1", "f1*",
                                            "f2", "f5", "f3", "f4", "f5*"}}


def src_rijndael():
    path, row = dl.source("35.208", "j00")
    items = dl.body_items(path)
    out = []
    for i, it in enumerate(items):
        if isinstance(it, dl.Table) and it.rows and [c.text for c in it.rows[0]][:4] == \
                ["Set", "Plaintext", "Ciphertext", "Key"]:
            for r in it.texts()[1:]:
                for name, v in zip(("Plaintext", "Ciphertext", "Key"), r[1:4]):
                    h = re.sub(r"\s", "", v).lower()
                    out.append(Vec(r[0], name, h, len(h) * 4, "3.3.2"))
    return out, row, {"sets": 20, "fields": {"Plaintext", "Ciphertext", "Key"}}


def src_keccak():
    sets, row = docx_lines_by_clause("35.233", "j00", r"^5\.([3-9])$")
    out = []
    for clause, n, lines in sets:
        out += collect(lines, FORMAT_MARKERS).vectors(str(int(n) - 2), clause)
    return out, row, {"sets": 6, "fields": {"IN", "OUT"}}


def src_tuak():
    sets, row = docx_lines_by_clause("35.233", "j00", r"^6\.([3-9])$")
    out = []
    for clause, n, lines in sets:
        out += collect(lines, FORMAT_MARKERS).vectors(str(int(n) - 2), clause)
    return out, row, {"sets": 6, "fields": {"K", "RAND", "SQN", "AMF", "TOP", "TOPc", "f1", "f1*",
                                           "f2", "f3", "f4", "f5", "f5*"}}


def src_milenage256():
    """35.236 §6.3: '=== Milenage-256 TEST #n ===' blocks carry the inputs; each
    'Case #na: RES_sz=.., ..' inside carries output sizes and outputs. A set is a
    case (1a..5e), with its test's inputs."""
    sets, row = docx_lines_by_clause("35.236", "j00", r"^(6\.3)$")
    out = []
    for clause, _, lines in sets:
        tests: list[tuple[str, list[str], list[tuple[str, str, list[str]]]]] = []
        for ln in lines:
            t = re.match(r"^=== Milenage-256 TEST #(\d+) ===", ln.strip())
            c = re.match(r"^Case #(\d+[a-e]):\s*(.*)$", ln.strip())
            if t:
                tests.append((t.group(1), [], []))
            elif c and tests:
                tests[-1][2].append((c.group(1), c.group(2), []))
            elif tests:
                (tests[-1][2][-1][2] if tests[-1][2] else tests[-1][1]).append(ln)
        for _, inputs, cases in tests:
            for name, sizes, body in cases:
                coll = collect(inputs + [""] + _m256_labels(body))
                for k, v in re.findall(r"(\w+_sz)\s*=\s*(\d+)", sizes):
                    coll.params[k] = int(v)
                for v in coll.vectors(name, clause):
                    v.field = v.field.replace("/", ":")
                    out.append(v)
    return out, row, {"sets": 25, "fields": {"KEY", "RAND", "SQN", "AMF", "OP", "OPc"} | M256_OUTPUTS}


# 35.236 prints each output as "<function>:<name> = { .. }" (f1*:MAC_S, f5**:AK*).
M256_OUTPUTS = {"f1*:MAC_S", "f1:MAC_A", "f2:RES", "f3:CK", "f4:IK", "f5:AK", "f5*:AK*", "f5**:AK*"}


def _m256_labels(body: list[str]) -> list[str]:
    """Make 35.236's labels unique for the collector: '<fn>:<name> =' becomes
    '<fn>/<name> =' (a ':' would end the label), and the debug intermediates that
    repeat under each 'Intermediates for the function index k:' get 'idx<k>.'."""
    out, idx = [], None
    for ln in body:
        m = re.match(r"^\s*Intermediates for the function index (\d+):", ln)
        if m:
            idx = m.group(1)
            continue
        f = re.match(r"^(\s*)(f[0-9]\**):(\w+\**)\s*=(.*)$", ln)
        if f:
            out.append(f"{f.group(1)}{f.group(2)}/{f.group(3)} ={f.group(4)}")
            continue
        g = re.match(r"^(\s*)([A-Za-z_]\w*)\s*=(\s*\{.*)$", ln)
        if g and idx is not None:
            out.append(f"{g.group(1)}idx{idx}.{g.group(2)} ={g.group(3)}")
            continue
        out.append(ln)
    return out


def src_33401(sub: str, sets: int, fields: set[str]):
    def f():
        found, row = docx_lines_by_clause("33.401", "j20", rf"^C\.{sub}\.(\d+)$")
        out = []
        for clause, n, lines in found:
            out += collect(lines).vectors(n, clause)
        return out, row, {"sets": sets, "fields": fields}
    return f


def src_ecies():
    found, row = docx_lines_by_clause("33.501", "j70", r"^(C\.4\.[234]\.\d)$")
    out = []
    for clause, n, lines in found:
        vecs = collect(_ecies_labels(lines)).vectors(clause, clause)
        need = {"C.4.3": ECIES_A, "C.4.4": ECIES_B}.get(clause[:5], set())
        missing = need - {v.field for v in vecs}
        if missing:
            raise dl.ExtractError(f"33.501 {clause}: missing {sorted(missing)}")
        out += vecs
    return out, row, {"sets": 6, "fields": {"Scheme Output"}}


ECIES_A = {"Home Network Private Key", "Home Network Public Key", "Eph. Private Key", "Eph. Public Key",
           "Cipher-text vaue", "MAC-tag value"}
ECIES_B = {"Home Network Private Key", "Home Network Public Key (compressed)", "Eph. Private Key",
           "Eph. Public Key (compressed)", "Cipher-text vaue", "MAC-tag value"}


def _ecies_labels(lines: list[str]) -> list[str]:
    """33.501 C.4.4 gives each Profile B public key as 'uncompressed:' and
    '(i|I)f compressed:' / 'compressed:' lines under a 'Home Network Public Key:'
    or 'Eph. Public Key:' heading; name them after the heading. The private key's
    label carries a parenthetical with a comma; drop it."""
    out, head = [], None
    for ln in lines:
        st = ln.strip()
        h = re.match(r"^(Home Network Public Key|Eph\. Public Key)\s*(?:\([^)]*\))?:\s*$", st)
        if h:
            head = h.group(1)
            out.append(ln)
            continue
        m = re.match(r"^(uncompressed|[Ii]f compressed|compressed):\s*(.*?),?$", st)
        if m and head:
            form = "uncompressed" if m.group(1) == "uncompressed" else "compressed"
            out.append(f"{head} ({form}): {m.group(2)}")
            continue
        if re.match(r"^[A-Z][^:']*:", st):        # any other label ends the group
            head = None
        out.append(re.sub(r"^(Home Network Private Key)\s*\([^)]*\)\s*:", r"\1:", st))
    return out


def src_rfc9048():
    path = ROOT / "spec" / "ietf" / "rfc9048.txt"
    row = next(r for r in dl.read_tsv(ROOT / "spec" / "INDEX.tsv") if r["doc"] == "rfc9048")
    text = path.read_text().split("Appendix D.  Test Vectors", 2)[-1]
    out = []
    for m in re.finditer(r"\n   Case (\d+)\n(.*?)(?=\n   Case \d+\n|\nAcknowledgments|\Z)", text, re.S):
        lines = [ln for ln in m.group(2).split("\n") if not re.match(r"^RFC 9048|^Arkko", ln)]
        c = collect(lines)
        for v in c.vectors(m.group(1), "Appendix D"):
            if v.field == "Identity":            # a quoted string of digits, not hex
                v.text, v.hex, v.bits = v.hex, "", None
            out.append(v)
    return out, row, {"sets": 4, "fields": {"Identity", "Network name", "CK'", "IK'", "K_encr", "K_aut", "K_re",
                                            "MSK", "EMSK"}}


def _sage_text() -> tuple[list[str], dict]:
    row = next(r for r in dl.read_tsv(ROOT / "spec" / "INDEX.tsv") if r["doc"] == "sage-uea2uia2-doc3")
    txt = subprocess.run(["pdftotext", "-layout", str(ROOT / row["file"]), "-"], capture_output=True,
                         text=True, check=True).stdout
    lines: list[str] = []
    for ln in txt.split("\n"):
        if "3GPP Confidentiality and Integrity Algorithms" in ln or "Implementors" in ln:
            while lines and not lines[-1].strip():   # a value continues across the page break
                lines.pop()
            continue
        lines.append(ln.lstrip("\f"))               # the next page's first line starts with \f
    for old, fixed, why in SAGE_REPAIRS:
        hits = [i for i, ln in enumerate(lines) if old in ln]
        if len(hits) != 1:
            raise dl.ExtractError(f"SAGE repair {old!r} matched {len(hits)} lines, expected 1 ({why})")
        lines[hits[0]] = lines[hits[0]].replace(old, fixed)
    return lines, row


# Recorded repairs of the SAGE Document 3 text (rows KS-SEC-S2). Each must apply once.
SAGE_REPAIRS = [
    ("2CCCBFC6 34E1B259 60876A0", "2CCCBFC6 34E1B259 060876A0",
     "UEA2 set 5 plaintext: a group of 7 hex digits; Length 837 bits needs 210 digits, and the same "
     "octets in TS 33.401 C.1 set 6 read 34e1b259 060876a0 fbb5a437"),
]


def _sage_sets(lines: list[str], section: str):
    """Yield (set number, lines) for 'section.N.   Test Set M' blocks (after the TOC)."""
    cur, buf = None, []
    for ln in lines:
        m = re.match(rf"^\s*{section}\.(\d+)\.\s+Test Set (\d+)\s*$", ln)
        if m:
            if cur:
                yield cur, buf
            cur, buf = m.group(2), []
            continue
        if cur and re.match(r"^\s*\d+\.\d*\.?\s+[A-Z]", ln) and "Test Set" not in ln:
            yield cur, buf
            cur, buf = None, []
            continue
        if cur:
            buf.append(ln)
    if cur:
        yield cur, buf


def src_uea2():
    lines, row = _sage_text()
    out = []
    for n, buf in _sage_sets(lines, "4"):
        head, table = [], []
        in_table = False
        for ln in buf:
            if re.match(r"^\s*Wordnumber\s+Keystream\s+enc/dec data", ln):
                in_table = True
                continue
            (table if in_table else head).append(ln)
        c = collect([ln for ln in head if not re.match(r"^\s*(K0|IV0)\s", ln)])
        data = []
        for ln in table:
            tok = ln.split()
            if tok and tok[0].isdigit() and all(_is_value(t) for t in tok[1:]):
                words = tok[1:]
                data += words[len(words) // 2:]
        c.values["Ciphertext"] = {"hex": "".join(data), "bin": ""}
        out += [v for v in c.vectors(n, "SAGE Doc3 4." + str(int(n) + 2)) if v.field in
                {"Count-C", "Bearer", "Direction", "CK", "Length", "Plaintext", "Ciphertext"}]
    return out, row, {"sets": 5, "fields": {"Count-C", "Bearer", "Direction", "CK", "Plaintext",
                                           "Ciphertext"}}


def src_uia2():
    lines, row = _sage_text()
    out = []
    for n, buf in _sage_sets(lines, "5"):
        c = collect(buf)
        out += [v for v in c.vectors(n, "SAGE Doc3 5." + str(int(n) + 2)) if v.field in
                {"COUNT-I", "FRESH", "DIRECTION", "IK", "LENGTH", "MESSAGE", "MAC-I"}]
    return out, row, {"sets": 6, "fields": {"COUNT-I", "FRESH", "DIRECTION", "IK", "MESSAGE", "MAC-I"}}


SOURCES = {
    "milenage": src_milenage,
    "rijndael": src_rijndael,
    "keccak": src_keccak,
    "tuak": src_tuak,
    "milenage256": src_milenage256,
    "eea2": src_33401("1", 6, {"Key", "Count", "Bearer", "Direction", "Plaintext", "Ciphertext"}),
    "eia2": src_33401("2", 8, {"Count-I", "Bearer", "Direction", "IK", "Message", "MACT"}),
    "eia1": src_33401("4", 7, {"Count-I", "Bearer", "Direction", "IK", "Message", "MACT"}),
    "uea2": src_uea2,
    "uia2": src_uia2,
    "ecies": src_ecies,
    "eap_aka_prime": src_rfc9048,
}


def run(name: str, out_dir: Path) -> list[str]:
    vecs, row, expect = SOURCES[name]()
    problems = []
    sets = sorted({v.set for v in vecs}, key=lambda s: (len(s), s))
    problems += _length_problems(name, vecs)
    if expect["sets"] is not None and len(sets) != expect["sets"]:
        problems.append(f"{name}: {len(sets)} sets, expected {expect['sets']}: {sets}")
    for s in sets:
        have = {v.field for v in vecs if v.set == s}
        missing = expect["fields"] - have
        if missing:
            problems.append(f"{name} set {s}: missing {sorted(missing)} (have {sorted(have)})")
    header = [f"# KATs extracted by spec/tools/kat_extract.py {TOOL_VERSION} from {row['doc']} "
              f"{row['version']} ({Path(row['file']).name}, sha256 {row['sha256']}). Do not edit."]
    dl.write_tsv(out_dir / f"{name}.tsv", header, ["set", "field", "hex", "bits", "text", "clause"],
                 [{"set": v.set, "field": v.field, "hex": v.hex, "bits": "" if v.bits is None else v.bits,
                   "text": v.text, "clause": v.clause} for v in vecs])
    print(f"KAT name={name} source={row['doc']} {row['version']} sets={len(sets)} vectors={len(vecs)} "
          f"problems={len(problems)}")
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", default=list(SOURCES))
    ap.add_argument("--out", type=Path, default=ROOT / "spec" / "kat")
    args = ap.parse_args()
    problems = []
    for n in args.names:
        try:
            problems += run(n, args.out)
        except dl.ExtractError as e:
            problems.append(f"{n}: {e}")
    for p in problems:
        print(f"CHECK {p}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
