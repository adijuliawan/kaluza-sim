#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Seed corpora for the fuzz targets (plan M14), from the external-origin
vectors (tests/vectors, and the local-only ones where this machine has them)
and the M12 generated APDUs and FCP templates:

    tools/fuzz_seeds.py <out dir>     one directory per target, files named by sha256

fuzz_codecs reads its first octet as a selector (tests/fuzz/fuzz_l3.cpp), so
each seed is the selector and the vector; fuzz_asn1_rrc reads one octet to
pick the channel message class.
"""

from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RRC_CLASSES = ["UL_CCCH_Message", "UL_CCCH1_Message", "DL_CCCH_Message", "UL_DCCH_Message", "DL_DCCH_Message",
               "PCCH_Message", "BCCH_BCH_Message", "BCCH_DL_SCH_Message"]
SMS = {"CP-": (3, 0), "RP-": (4, 0)}


def rows(proto: str):
    for path in (ROOT / "tests" / "vectors" / proto / "index.tsv",
                 ROOT / "tests" / "vectors" / "local" / proto / "index.tsv"):
        if path.is_file():
            with path.open() as f:
                yield from csv.DictReader((ln for ln in f if not ln.startswith("#")), delimiter="\t")


def main() -> int:
    out = Path(sys.argv[1])
    seeds: dict[str, list[bytes]] = {}
    for proto in ("ngap", "f1ap", "e1ap", "xnap"):
        seeds[f"fuzz_asn1_{proto}"] = [bytes.fromhex(r["hex"]) for r in rows(proto)]
    rrc = []
    for r in rows("rrc"):
        cls = r["pdu"].split(".")[0]
        if cls in RRC_CLASSES:
            rrc.append(bytes([RRC_CLASSES.index(cls)]) + bytes.fromhex(r["hex"]))
    seeds["fuzz_asn1_rrc"] = rrc
    codecs = []
    for r in rows("nas"):
        data = bytes.fromhex(r["hex"])
        codecs.append(bytes([1 if r["pdu"].startswith("SECURITY PROTECTED") else 0]) + data)
    for r in rows("sms"):
        data = bytes.fromhex(r["hex"])
        sel = 3 if r["pdu"].startswith("CP-") else 4 if r["pdu"].startswith("RP-") else 5
        codecs.append(bytes([sel]) + data)
    for proto, sel in (("gtpu", 6), ("psc", 8), ("nru", 9)):
        codecs += [bytes([sel]) + bytes.fromhex(r["hex"]) for r in rows(proto)]
    sys.path.insert(0, str(ROOT / "tests" / "oracles"))
    from ksimoracle import m12rt
    for _, _, cmd, rsp in m12rt.gen_apdus():
        codecs.append(bytes([10]) + cmd)
        codecs.append(bytes([11, len(cmd)]) + cmd + rsp)
    codecs += [bytes([14]) + f for f in m12rt.gen_fcps().values()]
    seeds["fuzz_codecs"] = codecs
    seeds["fuzz_mustfail"] = [b"KSIM must crash here"]
    total = 0
    for target, items in seeds.items():
        d = out / target
        d.mkdir(parents=True, exist_ok=True)
        for s in items:
            (d / hashlib.sha256(s).hexdigest()[:16]).write_bytes(s)
        total += len(items)
        print(f"FUZZ_SEEDS {target}={len(items)}")
    print(f"FUZZ_SEEDS_TOTAL={total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
