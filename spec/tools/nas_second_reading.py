#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Second readings of the TS 24.501 tables (plan M7).

Compares our extraction (spec/nas/24501/, j80) with two independent readings:
  - pycrate's own 5GS NAS message definitions (pycrate_mobile, LGPL, run as an
    external oracle in .venv, never linked);
  - the user's own kaluza-ue tables (Nas5gsTables.kt, generated from j70).
Differences go to spec/nas/24501/second_reading.tsv, one row per message and
source, with the IEIs only we have and only they have. A difference is a lead,
not a verdict: the j80 text decides (ADR 0005). The classification column is
filled from TRIAGE below, and an unclassified difference fails the run.

    .venv/bin/python spec/tools/nas_second_reading.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docx_lib as dl  # noqa: E402

ROOT = dl.ROOT
NAS = ROOT / "spec" / "nas" / "24501"
KOTLIN = Path("/home/amadeus/Development/ran/kaluza-ue/decoder/src/main/kotlin/com/kaluza/ue/"
              "decoder/nas/Nas5gsTables.kt")

# Triage of known differences: (source, protocol, type_hex) -> classification.
# Filled after reading each difference against the j80 text.
NEWER = "only-ours: IEs newer than pycrate 0.8.1's tables (Rel-18/19 additions in j80)"
TRIAGE: dict[tuple[str, str, str], str] = {
    ("pycrate-0.8.1", "5GMM", "41"): NEWER + "; pycrate defines N5GC indication (9.11.3.72) as a "
        "full-octet type 2 IEI 0A, j80 Table 8.2.6.1.1 gives the half-octet IEI A- (TV, 1): ours follows j80",
    ("pycrate-0.8.1", "5GMM", "42"): NEWER + "; pycrate puts the Requested WUS/PEIPS IEIs 1A/2A "
        "in REGISTRATION ACCEPT, j80 Table 8.2.7.1.1 (and the user's j70) give the Negotiated ones 1C/33",
    ("pycrate-0.8.1", "5GSM", "C3"): NEWER + "; pycrate's Re-attempt indicator carries IEI 00 (unset), "
        "j80 gives 1D",
    ("pycrate-0.8.1", "5GSM", "CA"): NEWER + "; pycrate's Re-attempt indicator carries IEI 00 (unset), "
        "j80 gives 1D",
    **{("pycrate-0.8.1", p, t): NEWER for p, t in [
        ("5GMM", "44"), ("5GMM", "45"), ("5GMM", "47"), ("5GMM", "4D"), ("5GMM", "54"),
        ("5GMM", "5A"), ("5GMM", "5D"), ("5GMM", "67"), ("5GSM", "C1"), ("5GSM", "C2"),
        ("5GSM", "C9"), ("5GSM", "CB"), ("5GSM", "D3")]},
    **{("kaluza-ue-j70", "5GMM", t): "j80 addition: the Forbidden TAI(s) lists 1D/1E "
       "(9.11.3.9) are new since j70" for t in ("42", "44", "47", "4D", "4E")},
}


def iei_key(iei: str) -> str:
    """Canonical IEI: 'C-' for a half-octet IEI, two hex digits otherwise."""
    return iei.upper() if iei.endswith("-") else iei.upper().zfill(2)


def ours() -> dict[tuple[str, str], dict]:
    msgs = dl.read_tsv(NAS / "messages.tsv")
    ies = dl.read_tsv(NAS / "message_ies.tsv")
    out = {}
    for m in msgs:
        if not m["message_type_hex"]:
            continue
        ieis = {iei_key(r["iei"]) for r in ies if r["key"] == m["key"] and r["iei"]}
        out[(m["protocol"], m["message_type_hex"])] = {"message": m["message"], "ieis": ieis}
    return out


def pycrate_reading() -> dict[tuple[str, str], set[str]]:
    import pycrate_mobile.TS24501_FGMM as F
    import pycrate_mobile.TS24501_FGSM as S
    out = {}
    for proto, classes in (("5GMM", F.FGMMTypeClasses), ("5GSM", S.FGSMTypeClasses)):
        for mtype, cls in classes.items():
            msg = cls()
            ieis = set()
            for ie in msg._content:
                names = [x._name for x in getattr(ie, "_content", [])]
                if names[:1] != ["T"]:
                    continue
                t = ie["T"].get_val()
                half = ie.__class__.__name__.startswith("Type1")
                ieis.add(f"{t:X}-" if half else f"{t:02X}")
            out[(proto, f"{mtype:02X}")] = ieis
    return out


_LAYOUT = re.compile(r"^\s{4}0x([0-9A-F]{2})([0-9A-F]{2}) to MessageLayout\(", re.M)
_IESPEC = re.compile(r"IeSpec\((null|0x[0-9A-F]+), \"[^\"]*\", \"[^\"]*\", \"[^\"]*\", '(\w)', "
                     r"IeFormat\.(\w+), (\w+), (\w+)\)")


def kotlin_reading() -> dict[tuple[str, str], set[str]]:
    text = KOTLIN.read_text()
    out = {}
    starts = [(m.start(), m.group(1), m.group(2)) for m in _LAYOUT.finditer(text)]
    for i, (pos, epd, mtype) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        proto = {"7E": "5GMM", "2E": "5GSM"}[epd]
        ieis = set()
        for m in _IESPEC.finditer(text[pos:end]):
            iei, fmt, lo = m.group(1), m.group(3), m.group(4)
            if iei == "null":
                continue
            v = int(iei, 16)
            if fmt == "TV" and lo == "1":
                ieis.add(f"{v >> 4:X}-")
            else:
                ieis.add(f"{v:02X}")
        out[(proto, mtype)] = ieis
    return out


def main() -> None:
    mine = ours()
    readings = {"pycrate-0.8.1": pycrate_reading()}
    if KOTLIN.is_file():
        readings["kaluza-ue-j70"] = kotlin_reading()
    rows, unclassified = [], 0
    for source, theirs in readings.items():
        for key in sorted(set(mine) | set(theirs)):
            a = mine.get(key, {}).get("ieis")
            b = theirs.get(key)
            if a == b:
                continue
            cls = TRIAGE.get((source, *key), "")
            unclassified += not cls
            rows.append({"source": source, "protocol": key[0], "type_hex": key[1],
                         "message": mine.get(key, {}).get("message", "(absent in j80)"),
                         "only_ours": ",".join(sorted(a - b)) if a is not None and b is not None
                         else ("(message)" if b is None else ""),
                         "only_theirs": ",".join(sorted(b - a)) if a is not None and b is not None
                         else ("(message)" if a is None else ""),
                         "classification": cls or "UNCLASSIFIED"})
        print(f"SECOND_READING source={source} messages_ours={len(mine)} messages_theirs={len(theirs)} "
              f"differing={sum(1 for r in rows if r['source'] == source)}")
    dl.write_tsv(NAS / "second_reading.tsv",
                 ["# Second readings of spec/nas/24501 (spec/tools/nas_second_reading.py). A "
                  "difference is a lead; the j80 text decides."],
                 ["source", "protocol", "type_hex", "message", "only_ours", "only_theirs",
                  "classification"], rows)
    print(f"SECOND_READING unclassified={unclassified}")
    sys.exit(1 if unclassified else 0)


if __name__ == "__main__":
    main()
