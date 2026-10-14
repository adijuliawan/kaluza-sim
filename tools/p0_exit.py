#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""P0's exit check (plan M16; roadmap P0 exit): from the oracle reports of
build/oracle (tools/p0_exit.sh refreshes them), the KAT run, the construct
table and the must-fail self-tests:

    V1_PDU_TYPES          the v1 types of spec/v1-pdus.tsv
    ROUNDTRIP_OK          types whose every check re-encodes byte for byte (a
                          vector its producer refuses must be refused, or taken
                          as LENIENT where only padding differs)
    TSHARK_OK             types tshark reads cleanly at least once with no
                          failing check (complaints only inside a carried
                          container of generated content count as clean, rule
                          KS-PLAT-B10); TSHARK_LAG the types tshark cannot
                          dissect at all (each a -T row)
    PYCRATE_OK            types pycrate reads the same (ASN.1, NAS, SMS, GTP-U,
                          PSC)
    SECOND_SOURCE_OK      NR-U by OCUDU's vectors, APDU and FCP by pySim (the
                          plan's second source where pycrate has no reader)
    KAT_OK                the KAT test sets, all passing
    ASN1_CONSTRUCTS_UNHANDLED  construct classes without a handling and vector
    GUARDS_MUSTFAIL_OK    must-fail self-tests that catch their mutation

    P0_EXIT=PASS when every type round-trips and is read by tshark (or is a
    declared tshark lag) and by pycrate or its second source, every KAT passes,
    no construct is unhandled and every must-fail case is caught.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OK_STATUSES = {"PASS", "NESTED_FILLER", "NESTED_PAYLOAD", "GENERATED_CONTENT", "ORACLE_LAG", "CIPHERED_CONTAINER",
               "NEGATIVE_AGREED", "LENIENT"}
SECOND_SOURCE = {"nru", "apdu"}


def tsv(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader((ln for ln in f if not ln.startswith("#")), delimiter="\t"))


def reports() -> dict[tuple[str, str], list[dict]]:
    by_type: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for name in ("roundtrip", "l3roundtrip", "m12roundtrip"):
        for r in tsv(ROOT / "build" / "oracle" / f"{name}.tsv"):
            r["_report"] = name
            by_type[(r["protocol"], r["pdu"])].append(r)
    return by_type


def judge(proto: str, checks: list[dict]) -> dict[str, bool]:
    if not checks:
        return {"present": False, "roundtrip": False, "tshark": False, "tshark_lag": False,
                "tshark_nested_only": False, "reader": False}
    statuses = {c["status"] for c in checks}
    no_fail = statuses <= OK_STATUSES
    rt = all(c.get("asn1c_roundtrip", c.get("ours_roundtrip")) == "1" or c["status"] in ("NEGATIVE_AGREED", "LENIENT")
             for c in checks)
    clean = any(c["tshark_clean"] == "1" for c in checks)
    # KS-PLAT-B10: tshark's complaints inside a carried protocol (X2AP, RRC, NAS
    # in an AP container) filled with generated content are that content's; the
    # carrying PDU itself is read cleanly
    nested = not clean and any(c["status"] in ("NESTED_FILLER", "NESTED_PAYLOAD") for c in checks)
    tshark = (clean or nested) and no_fail
    lag = not tshark and no_fail and all("tshark" in c["notes"] and c["status"] == "ORACLE_LAG" for c in checks)
    if proto in SECOND_SOURCE:
        if proto == "nru":   # OCUDU's vectors are the second source: one that ours reads like OCUDU's test
            reader = any(c["source"].startswith("nru-ocudu") and c["status"] in ("PASS", "NEGATIVE_AGREED")
                         for c in checks)
        else:                # pySim
            reader = any(c.get("second_reader") == "1" for c in checks)
    elif checks[0]["_report"] == "roundtrip":
        reader = any(c["pycrate_ok"] == "1" and c["jer_match"] == "1" for c in checks)
    elif checks[0]["_report"] == "l3roundtrip":
        reader = any(c["pycrate_ok"] == "1" and c["ies_match"] in ("1", "") for c in checks)
    else:
        reader = any(c.get("second_reader") == "1" for c in checks)
    return {"present": True, "roundtrip": rt and no_fail, "tshark": tshark, "tshark_lag": lag,
            "tshark_nested_only": nested and no_fail, "reader": reader and no_fail}


def kat_sets() -> tuple[int, bool]:
    sets = sum(len({r["set"] for r in tsv(p)}) for p in (ROOT / "spec" / "kat").glob("*.tsv"))
    r = subprocess.run([str(ROOT / "build" / "dev" / "tests" / "unit" / "crypto" / "unit_crypto"), "--gtest_brief=1"],
                       capture_output=True, text=True)
    return sets, r.returncode == 0


def constructs_unhandled() -> int:
    n = 0
    for r in tsv(ROOT / "spec" / "asn1" / "constructs.tsv"):
        used = any(int(r.get(p) or 0) > 0 for p in ("rrc", "ngap", "f1ap", "e1ap", "xnap"))
        if used and not (r.get("handling") and r.get("vector")):
            n += 1
    return n


def mustfail() -> tuple[int, int, list[str]]:
    """(caught, cases, missed names): every guard's self-test and the oracle,
    canary, clang-tidy and fuzz must-fail cases."""
    py = [str(ROOT / ".venv" / "bin" / "python"), "-I"]
    runs = [(g.stem, ["python3", str(g), "--self-test"]) for g in sorted((ROOT / "tools" / "guards").glob("check_*.py"))]
    runs += [("oracle selftest", py + [str(ROOT / "tests" / "oracles" / "oracle.py"), "selftest"]),
             ("l3roundtrip selftest", py + [str(ROOT / "tests" / "oracles" / "oracle.py"), "l3roundtrip", "--selftest"]),
             ("m12roundtrip selftest", py + [str(ROOT / "tests" / "oracles" / "oracle.py"), "m12roundtrip", "--selftest"]),
             ("secret canary", ["python3", str(ROOT / "tools" / "secret_canary.py")])]
    caught, missed = 0, []
    for name, cmd in runs:
        ok = subprocess.run(cmd, capture_output=True, text=True).returncode == 0
        caught += ok
        if not ok:
            missed.append(name)
    fixture = subprocess.run(["clang-tidy", "--quiet", f"--config-file={ROOT / '.clang-tidy'}",
                              str(ROOT / "tools" / "clang_tidy" / "mustfail.cpp"), "--", "-std=c++20"],
                             capture_output=True, text=True)
    ok = "bugprone-use-after-move" in fixture.stdout + fixture.stderr
    caught += ok
    if not ok:
        missed.append("clang-tidy fixture")
    total = len(runs) + 1
    fz = ROOT / "build" / "fuzz" / "tests" / "fuzz" / "fuzz_mustfail"
    if fz.is_file():
        total += 1
        seed = ROOT / "build" / "p0-exit-mustfail-seed"
        seed.write_bytes(b"KSIM must crash here")
        r = subprocess.run([str(fz), "-runs=1", str(seed)], capture_output=True, text=True)
        seed.unlink()
        if r.returncode != 0:
            caught += 1
        else:
            missed.append("fuzz_mustfail")
    return caught, total, missed


def main() -> int:
    v1 = tsv(ROOT / "spec" / "v1-pdus.tsv")
    by_type = reports()
    counts = defaultdict(int)
    problems = []
    for t in v1:
        j = judge(t["protocol"], by_type.get((t["protocol"], t["pdu"]), []))
        if not j["present"]:
            problems.append(f"{t['protocol']} {t['pdu']}: no check")
            continue
        counts["roundtrip"] += j["roundtrip"]
        counts["tshark"] += j["tshark"]
        counts["tshark_lag"] += j["tshark_lag"]
        counts["tshark_nested_only"] += j["tshark_nested_only"]
        if j["tshark_nested_only"]:
            print(f"P0_EXIT_NOTE {t['protocol']} {t['pdu']}: tshark reads the PDU; it complains only inside a "
                  f"carried container of generated content (KS-PLAT-B10)")
        if t["protocol"] in SECOND_SOURCE:
            counts["second"] += j["reader"]
            counts["second_types"] += 1
        else:
            counts["pycrate"] += j["reader"]
            counts["pycrate_types"] += 1
        for k, ok in (("round trip", j["roundtrip"]), ("tshark", j["tshark"] or j["tshark_lag"]),
                      ("pycrate or second source", j["reader"])):
            if not ok:
                problems.append(f"{t['protocol']} {t['pdu']}: {k}")
    sets, kat_ok = kat_sets()
    unhandled = constructs_unhandled()
    caught, cases, missed = mustfail()
    n = len(v1)
    print(f"V1_PDU_TYPES={n}")
    print(f"ROUNDTRIP_OK={counts['roundtrip']}/{n}")
    print(f"TSHARK_OK={counts['tshark']}/{n} TSHARK_LAG={counts['tshark_lag']} "
          f"(of the OK, nested-container complaints only: {counts['tshark_nested_only']})")
    print(f"PYCRATE_OK={counts['pycrate']}/{counts['pycrate_types']}")
    print(f"SECOND_SOURCE_OK={counts['second']}/{counts['second_types']}")
    print(f"KAT_OK={sets if kat_ok else 0}/{sets}")
    print(f"ASN1_CONSTRUCTS_UNHANDLED={unhandled}")
    print(f"GUARDS_MUSTFAIL_OK={caught}/{cases}")
    for p in problems:
        print(f"P0_EXIT_PROBLEM {p}")
    for m in missed:
        print(f"P0_EXIT_PROBLEM must-fail case not caught: {m}")
    ok = (not problems and kat_ok and unhandled == 0 and caught == cases
          and counts["roundtrip"] == n and counts["tshark"] + counts["tshark_lag"] == n)
    print(f"P0_EXIT={'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
