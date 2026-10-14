#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Oracle harness CLI (plan M8). Run with the oracle venv: .venv/bin/python -I.

    oracle.py gen     --proto ngap --pdu NGSetupRequest --mode min   hex + JER of a generated PDU
    oracle.py check   --proto ngap --hex <hex> --jer <file|->         verdict for an encoding
    oracle.py sweep   [--proto ngap ...]                              every v1 AP type, min and max
    oracle.py allowlists                                              write spec/oracle/*.tsv (derived)
    oracle.py selftest                                                must-fail checks

Output is KEY=value lines (cli.md style). Exit 0 when the verdict is PASS or a
classified, recorded status (ORACLE_LAG, NESTED_FILLER for generated values),
and 1 otherwise.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ksimoracle import asn, compare, pcap, tshark  # noqa: E402
from ksimoracle.valuegen import Gen, Omit  # noqa: E402

ROOT = asn.ROOT
AP = ("ngap", "f1ap", "e1ap", "xnap")


def v1_types(proto: str) -> list[str]:
    rows = [ln.rstrip("\n").split("\t") for ln in (ROOT / "spec" / "v1-pdus.tsv").open() if not ln.startswith("#")]
    return [r[1] for r in rows[1:] if r[0] == proto]


def generate(proto: str, pdu: str, mode: str):
    o, enc = asn.top(proto)
    value = Gen(mode).procedure_message(o, pdu)
    return value, asn.encode(o, value, enc)


def cmd_gen(a) -> int:
    value, data = generate(a.proto, a.pdu, a.mode)
    o, _ = asn.top(a.proto)
    o.set_val(value)
    print(f"PROTO={a.proto}\nPDU={a.pdu}\nMODE={a.mode}\nHEX={data.hex()}\nJER={json.dumps(json.loads(o.to_jer()))}")
    return 0


def cmd_check(a) -> int:
    o, _ = asn.top(a.proto)
    jer = sys.stdin.read() if a.jer == "-" else Path(a.jer).read_text()
    o.from_jer(jer)
    intended = o.get_val()
    v = compare.check_ap(a.proto, bytes.fromhex(a.hex), intended, generated=a.generated)
    print(f"STATUS={v.status}\nPYCRATE_ROUNDTRIP={int(v.pycrate_roundtrip)}\n"
          f"PYCRATE_VALUE_MATCH={int(v.pycrate_value_match)}\nTSHARK_CLEAN={int(v.tshark_clean)}")
    for n in v.notes:
        print(f"NOTE={n}")
    return 0 if v.status in ("PASS", "ORACLE_LAG", "NESTED_FILLER") else 1


def cmd_sweep(a) -> int:
    total = collections.Counter()
    failures = []
    for proto in a.proto or AP:
        c = collections.Counter()
        for pdu in v1_types(proto):
            for mode in ("min", "max"):
                try:
                    value, data = generate(proto, pdu, mode)
                except (Omit, KeyError, Exception) as e:  # noqa: BLE001
                    c["GEN_ERROR"] += 1
                    failures.append(f"{proto} {pdu} {mode} GEN_ERROR {type(e).__name__}: {str(e)[:100]}")
                    continue
                v = compare.check_ap(proto, data, value, generated=True)
                c[v.status] += 1
                if v.status == "FAIL":
                    failures.append(f"{proto} {pdu} {mode} FAIL {'; '.join(v.notes)[:200]}")
        total += c
        print(f"SWEEP proto={proto} " + " ".join(f"{k}={n}" for k, n in sorted(c.items())))
    for f in failures:
        print(f"FAILURE {f}")
    print("SWEEP_TOTAL " + " ".join(f"{k}={n}" for k, n in sorted(total.items())))
    return 0


def cmd_allowlists(a) -> int:
    import io
    out = ROOT / "spec" / "oracle"
    path = out / "tshark_unknown_ie_ids.tsv"
    buf = io.StringIO()
    buf.write(f"# Derived by tests/oracles/oracle.py allowlists: Rel-19 IE ids that {tshark.version()} "
              f"has no name for. Do not edit.\n")
    w = csv.writer(buf, delimiter="\t", lineterminator="\n")
    w.writerow(["protocol", "id", "name"])
    for proto in AP:
        for i, n in sorted(compare.unknown_to_tshark(proto).items()):
            w.writerow([proto, i, n])
    if a.check:
        current = path.is_file() and path.read_text() == buf.getvalue()
        print(f"ALLOWLIST={'CURRENT' if current else 'STALE'}")
        return 0 if current else 1
    out.mkdir(parents=True, exist_ok=True)
    path.write_text(buf.getvalue())
    for proto in AP:
        print(f"ALLOWLIST proto={proto} spec_ids={len(compare.spec_ie_ids(proto))} "
              f"unknown_to_tshark={len(compare.unknown_to_tshark(proto))}")
    return 0


def cmd_selftest(a) -> int:
    """Must-fail: the harness has to reject a flipped bit and a wrong-width field."""
    failed = 0
    value, data = generate("ngap", "NGSetupRequest", "min")
    good = compare.check_ap("ngap", data, value, generated=True)
    if good.status != "PASS":
        print(f"SELFTEST oracle: FAIL (valid NGSetupRequest judged {good.status}: {good.notes})")
        failed += 1
    flipped = bytearray(data)
    flipped[-3] ^= 0x01                         # inside the last IE's value
    v = compare.check_ap("ngap", bytes(flipped), value, generated=True)
    if v.status != "FAIL":
        print(f"SELFTEST oracle: FAIL (a flipped bit was judged {v.status})")
        failed += 1
    # Wrong width: insert one zero bit after the PDU header, shifting the rest.
    bits = "".join(f"{b:08b}" for b in data)
    shifted = bits[:40] + "0" + bits[40:]
    shifted += "0" * ((-len(shifted)) % 8)
    wide = bytes(int(shifted[i:i + 8], 2) for i in range(0, len(shifted), 8))
    v2 = compare.check_ap("ngap", wide, value, generated=True)
    if v2.status != "FAIL":
        print(f"SELFTEST oracle: FAIL (a wrong-width field was judged {v2.status})")
        failed += 1
    if not failed:
        print("SELFTEST oracle: OK (valid PDU passes; a flipped bit and a wrong-width field fail)")
    return 1 if failed else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("--proto", required=True, choices=AP)
    g.add_argument("--pdu", required=True)
    g.add_argument("--mode", default="min", choices=("min", "max"))
    c = sub.add_parser("check")
    c.add_argument("--proto", required=True, choices=AP)
    c.add_argument("--hex", required=True)
    c.add_argument("--jer", required=True)
    c.add_argument("--generated", action="store_true")
    s = sub.add_parser("sweep")
    s.add_argument("--proto", action="append", choices=AP)
    al = sub.add_parser("allowlists")
    al.add_argument("--check", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args()
    sys.exit({"gen": cmd_gen, "check": cmd_check, "sweep": cmd_sweep, "allowlists": cmd_allowlists,
              "selftest": cmd_selftest}[a.cmd](a))


if __name__ == "__main__":
    main()
