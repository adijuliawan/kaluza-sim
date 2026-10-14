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
    # fuzz_card: (length, APDU) sequences, from power-on habits of a phone.
    def seq(*apdus):
        out = b""
        for a in apdus:
            b = bytes.fromhex(a)
            out += bytes([len(b)]) + b
        return out
    pin = lambda d: d.encode().hex() + "ff" * (8 - len(d))
    # fuzz_nas_ies: a selector octet, then an IE's contents (or a downlink message for 22, 23).
    seeds["fuzz_nas_ies"] = [bytes([sel]) + bytes.fromhex(v) for sel, v in [
        (0, "0100f110f0ff00000000030010"), (0, "f200f110caff8140c0de17"), (0, "f4ff8140c0de17"),
        (1, "0100f110000001000007" "2200f110000010" "4100f11000000299f907000003"), (2, "0101" "0401000001"),
        (3, "0501000001ff"), (4, "01000631310101ff09"), (4, "020013" "21" "22" "0e" "10c0a80000ffff0000" "5113881393" "0a05"),
        (5, "092041010109"), (6, "010a2d0003"), (6, "0300000000000000010a2d0003"), (7, "0600010b0001"),
        (8, "4100000001"), (9, "00f11099f907"), (10, "08696e7465726e6574"), (11, "e0e0e0e0"), (12, "2000"),
        (13, "0503"), (14, "09"), (15, "06"), (16, "09"), (17, "8000"), (18, "00f110000001"), (19, "22"),
        (20, "0000"), (21, "01010008"), (22, "7e03d711f0f3007e005d2201028080e1"), (23, "7e029da9efe70129e873d58806b429697f")]]
    seeds["fuzz_card"] = [
        seq("00A40004022F00", "00C0000020", "00B2010426"),
        seq("00A4040C07A0000000871002", "00A4000C026F07", "00B0000009", "00A4000C025FC0", "00A4000C024F01", "00B0000014"),
        seq("0020000A08" + pin("11111111"), "00A4080C047FF06F07", "00D6000001AA", "00B0000001"),
        seq("00A4040C07A0000000871002", "0088008122" + "10" + "00" * 16 + "10" + "00" * 16),
        seq("0070000001", "01A4040C07A0000000871002", "0070800100"),
        seq("00A4000C022F06", "00A201040383010100", "00B2000228", "00B2000328"),
    ]
    # fuzz_uu: a selector octet, then a KAIR frame (0), a PDCP PDU (1), length-prefixed
    # PDUs for a PDCP entity (2), or an RRC message for one of the readers (3-11): the
    # builder samples of tests/unit/asn1/rrc_samples.hpp.
    kair = ("4b41010b0000001a01020304000000070102030405060708000201094601000301001101020005e3540e"
            "b5e9a2ec15689d750790010006040181")
    seeds["fuzz_uu"] = [bytes([sel]) + bytes.fromhex(v) for sel, v in [
        (0, kair), (1, "82abcd00"), (1, "0001020304a0"), (2, "0001" "0f0005e3540eb5e9a2ec15689d750790" "0a000022091000af3926bd"),
        (3, "410604"), (4, "408008600201ccc9c0000004680000006b682280"), (5, "204032810000000403281000003fc0"),
        (6, "1123456789a6"), (7, "2040009a002500088bd76380a1c0222f5d8e028909f380"), (7, "0880"), (8, "220910"),
        (8, "1600"), (8, "2a808fc00b6020"), (9, "2a00"), (9, "3a01bf002180"), (9, "4882028000000000000000002680"),
        (10, "4004a001117aec7014380445ebb1c051213e70")]]
    # fuzz_ngap_proc: length-prefixed NGAP PDUs: every NGAP vector of the external
    # corpus, one per PDU.
    ngap_rows = [r for r in rows("ngap") if r.get("hex")]
    def lp(*pdus):
        return b"".join(len(p).to_bytes(2, "big") + p for p in pdus)
    seeds["fuzz_ngap_proc"] = [lp(bytes.fromhex(r["hex"])) for r in ngap_rows]
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
