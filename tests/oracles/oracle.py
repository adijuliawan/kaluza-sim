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
from ksimoracle import asn, compare, pcap, roundtrip, tshark  # noqa: E402
from ksimoracle.codec import Codec  # noqa: E402
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
    return 0 if v.status in ("PASS", "ORACLE_LAG", "NESTED_FILLER", "NESTED_PAYLOAD") else 1


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


def corpus(proto: str) -> list[dict]:
    """External-origin vectors of a protocol: tests/vectors/<proto>/index.tsv and,
    where this machine has them, the local-only tests/vectors/local/<proto>/index.tsv."""
    out = []
    for path in (ROOT / "tests" / "vectors" / proto / "index.tsv",
                 ROOT / "tests" / "vectors" / "local" / proto / "index.tsv"):
        if not path.is_file():
            continue
        lines = [ln.rstrip("\n") for ln in path.open() if not ln.startswith("#")]
        head = lines[0].split("\t")
        out += [dict(zip(head, ln.split("\t"))) for ln in lines[1:] if ln]
    return out


def corpus_v1_name(proto: str, pdu: str, v1: list[str]) -> str | None:
    """The v1 type a corpus row's pdu names: the procedure for AP; for RRC,
    '<Channel>-Message.<arm>' or a container name."""
    if proto != "rrc":
        return pdu if pdu in v1 else None
    if pdu in v1:
        return pdu
    for name in v1:
        try:
            pl = roundtrip.rrc.place(name)
        except KeyError:
            continue
        if pl.path and pdu == f"{pl.top}.{pl.path[-1][1]}":
            return name
    return None


def cmd_roundtrip(a) -> int:
    report = ROOT / "build" / "oracle" / "roundtrip.tsv"
    report.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    totals = collections.Counter()
    types_seen = {}
    with Codec(Path(a.codec) if a.codec else None) as codec:
        for proto in a.proto or ("ngap", "f1ap", "e1ap", "xnap", "rrc"):
            v1 = v1_types(proto)
            if a.pdu:
                v1 = [p for p in v1 if p in a.pdu]
            by_type = collections.defaultdict(list)
            for row in corpus(proto):
                name = corpus_v1_name(proto, row["pdu"], v1)
                if name:
                    by_type[name].append(row)
            c = collections.Counter()
            for pdu in v1:
                cases = [(row["id"], bytes.fromhex(row["hex"]), None, False) for row in by_type[pdu]]
                for mode in ("min", "max"):
                    try:
                        value, data = roundtrip.generate(proto, pdu, mode)
                        cases.append((f"gen-{mode}", data, value, True))
                    except Exception as e:  # noqa: BLE001
                        c["GEN_ERROR"] += 1
                        rows.append([proto, pdu, f"gen-{mode}", "GEN_ERROR", "", "", "", "", "",
                                     f"{type(e).__name__}: {str(e)[:160]}"])
                indep = 0
                for src, data, value, gen in cases:
                    r = roundtrip.check(codec, proto, pdu, data, value, gen)
                    c[r.status] += 1
                    if not gen and r.status != "FAIL":
                        indep += 1
                    rows.append([proto, pdu, src, r.status, int(r.asn1c_roundtrip), int(r.jer_match),
                                 int(r.pycrate_ok), int(r.tshark_clean),
                                 "" if r.encoders_agree is None else int(r.encoders_agree),
                                 "; ".join(dict.fromkeys(r.notes))[:400]])
                types_seen[(proto, pdu)] = indep
            totals += c
            no_indep = sum(1 for (p, _), n in types_seen.items() if p == proto and n == 0)
            print(f"ROUNDTRIP proto={proto} types={len(v1)} without_independent_vector={no_indep} "
                  + " ".join(f"{k}={n}" for k, n in sorted(c.items())))
    with report.open("w") as f:
        f.write("# tests/oracles/oracle.py roundtrip (plan M10). Generated; not committed.\n")
        f.write("protocol\tpdu\tsource\tstatus\tasn1c_roundtrip\tjer_match\tpycrate_ok\ttshark_clean"
                "\tencoders_agree\tnotes\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
    fails = [r for r in rows if r[3] in ("FAIL", "GEN_ERROR")]
    for r in fails[: a.show]:
        print(f"FAILURE {r[0]} {r[1]} {r[2]} {r[3]} {r[9][:220]}")
    print("ROUNDTRIP_TOTAL " + " ".join(f"{k}={n}" for k, n in sorted(totals.items()))
          + f" types={len(types_seen)} without_independent_vector="
          + str(sum(1 for n in types_seen.values() if n == 0)) + f" report={report.relative_to(ROOT)}")
    return 0 if not fails else 1


def cmd_localize(a) -> int:
    from ksimoracle.localize import localize
    value, _ = roundtrip.generate(a.proto, a.pdu, a.mode)
    o, _, top, _ = roundtrip.target(a.proto, a.pdu)
    with Codec(Path(a.codec) if a.codec else None) as codec:
        found = localize(codec, a.proto, o, top, value)
    for name, why in dict.fromkeys(found):
        print(f"DISAGREE {a.proto} {name}: {why}")
    print(f"LOCALIZE {a.proto} {a.pdu} {a.mode} deepest={len(set(found))}")
    return 0


def cmd_probes(a) -> int:
    from ksimoracle import probes
    bad = 0
    with Codec(Path(a.codec) if a.codec else None) as codec:
        for name, n, ok, fails in probes.run(codec):
            print(f"PROBE {'PASS' if ok == n else 'FAIL'} {ok}/{n} {name}")
            for f in fails:
                print(f"  {f}")
            bad += n - ok
    print(f"PROBES={'PASS' if not bad else 'FAIL'} failures={bad}")
    return 0 if not bad else 1


def cmd_l3roundtrip(a) -> int:
    """The M11 check: every v1 NAS and SMS type, corpus vectors and generated values."""
    from ksimoracle import nasrt
    report = ROOT / "build" / "oracle" / "l3roundtrip.tsv"
    report.parent.mkdir(parents=True, exist_ok=True)
    rows, totals = [], collections.Counter()
    by_type = collections.defaultdict(list)
    for proto in ("nas", "sms"):
        for row in corpus(proto):
            by_type[row["pdu"]].append(row)
    with Codec(Path(a.codec) if a.codec else None) as codec:
        if a.selftest:
            results = nasrt.selftest(codec)
            for name, caught in results:
                print(f"L3SELFTEST {'CAUGHT' if caught else 'MISSED'} {name}")
            ok = all(c for _, c in results)
            print(f"L3SELFTEST={'PASS' if ok else 'FAIL'} cases={len(results)}")
            return 0 if ok else 1
        ie_checked = field_checked = epco_checked = 0
        for proto in ("5gmm", "5gsm", "sms"):
            c = collections.Counter()
            types = v1_types(proto)
            if a.pdu:
                types = [t for t in types if t in a.pdu]
            no_indep = 0
            for name in types:
                kind = "nas" if proto != "sms" else nasrt.SMS_CLASSES[name][0]
                rows_for = by_type.get(name) or by_type.get(name.split(" (")[0], [])
                cases = [(r["id"], bytes.fromhex(r["hex"]), False) for r in rows_for]
                if not cases:
                    no_indep += 1
                modes = ("min", "max", "table") if kind == "nas" and "PROTECTED" not in name else ("min", "max")
                for mode in modes:
                    try:
                        cases.append((f"gen-{mode}", nasrt.generate(kind, name, mode), True))
                    except Exception as e:  # noqa: BLE001
                        c["GEN_ERROR"] += 1
                        rows.append([proto, name, f"gen-{mode}", "GEN_ERROR", "", "", "", "", f"{type(e).__name__}: {e}"[:200]])
                for src, data, gen in cases:
                    r = nasrt.check(codec, kind, name, data, gen, use_pycrate=src != "gen-table")
                    c[r.status] += 1
                    ie_checked += r.tshark_ie_count
                    field_checked += r.field_count
                    epco_checked += r.epco_count
                    rows.append([proto, name, src, r.status, int(r.ours_roundtrip), int(r.pycrate_ok),
                                 "" if r.ies_match is None else int(r.ies_match), int(r.tshark_clean),
                                 "; ".join(dict.fromkeys(r.notes))[:400]])
            totals += c
            print(f"L3ROUNDTRIP proto={proto} types={len(types)} without_independent_vector={no_indep} "
                  + " ".join(f"{k}={n}" for k, n in sorted(c.items())))
    with report.open("w") as f:
        f.write("# tests/oracles/oracle.py l3roundtrip (plan M11). Generated; not committed.\n")
        f.write("protocol\tpdu\tsource\tstatus\tours_roundtrip\tpycrate_ok\ties_match\ttshark_clean\tnotes\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
    fails = [r for r in rows if r[3] in ("FAIL", "GEN_ERROR")]
    for r in fails[: a.show]:
        print(f"FAILURE {r[0]} {r[1]} {r[2]} {r[3]} {r[8][:200]}")
    print("L3ROUNDTRIP_TOTAL " + " ".join(f"{k}={n}" for k, n in sorted(totals.items()))
          + f" tshark_ies_matched={ie_checked} epco_units_matched={epco_checked} sms_fields_matched={field_checked}"
          + f" report={report.relative_to(ROOT)}")
    return 0 if not fails else 1


def cmd_m12roundtrip(a) -> int:
    """The M12 check: every v1 GTP-U, PSC, NR-U and APDU type, and FCP templates."""
    from ksimoracle import m12rt
    report = ROOT / "build" / "oracle" / "m12roundtrip.tsv"
    report.parent.mkdir(parents=True, exist_ok=True)
    rows, totals = [], collections.Counter()
    pysim = m12rt.PySim() if m12rt.PySim.available() else None
    if pysim is None:
        print(f"M12ROUNDTRIP note: no pySim at {m12rt.PYSIM_DIR}; APDU and FCP checked by tshark only")
    try:
        with Codec(Path(a.codec) if a.codec else None) as codec:
            if a.selftest:
                results = m12rt.selftest(codec, pysim)
                for name, caught in results:
                    print(f"M12SELFTEST {'CAUGHT' if caught else 'MISSED'} {name}")
                ok = all(c for _, c in results)
                print(f"M12SELFTEST={'PASS' if ok else 'FAIL'} cases={len(results)}")
                return 0 if ok else 1
            fields = 0
            for proto in ("gtpu", "psc", "nru", "apdu", "fcp"):
                c = collections.Counter()
                types = v1_types(proto) if proto != "fcp" else list(m12rt.gen_fcps())
                by_type = collections.defaultdict(list)
                for row in corpus(proto) if proto in ("gtpu", "psc", "nru") else []:
                    by_type[row["pdu"]].append(row)
                outside = sum(len(v) for k, v in by_type.items() if k not in types
                              and not any("expects refusal" in r["locator"] for r in v))
                no_indep = 0
                cases = []
                for name in types:
                    corp = [(name, r["id"], bytes.fromhex(r["hex"]), False, "expects refusal" in r["locator"])
                            for r in by_type.get(name, [])]
                    if not [x for x in corp if not x[4]]:
                        no_indep += 1
                    cases += corp
                    if proto == "gtpu":
                        cases += [(name, f"gen-{m}", m12rt.gen_gtpu(name, m), True, False) for m in ("min", "max")]
                    elif proto in ("psc", "nru"):
                        t = m12rt.FRAME_TYPES[proto][name]
                        cases += [(name, f"gen-{m}", m12rt.gen_frame(proto, t, m), True, False) for m in ("min", "max")]
                if proto in ("psc", "nru"):   # the producer's refused vectors that name no v1 type
                    cases += [(r["pdu"], r["id"], bytes.fromhex(r["hex"]), False, True)
                              for k, v in by_type.items() if k not in types for r in v if "expects refusal" in r["locator"]]
                if proto == "apdu":
                    cases = [(n, f"gen: {label}", (cmd, rsp), True, False) for n, label, cmd, rsp in m12rt.gen_apdus()
                             if not a.pdu or n in a.pdu]
                    no_indep = len(types)
                if proto == "fcp":
                    cases = [(n, "gen", f, True, False) for n, f in m12rt.gen_fcps().items()]
                    no_indep = len(types)
                for name, src, data, gen, refused in cases:
                    if a.pdu and name not in a.pdu:
                        continue
                    if proto == "gtpu":
                        r = m12rt.check_gtpu(codec, data, gen)
                    elif proto in ("psc", "nru"):
                        r = m12rt.check_frame(codec, proto, data, gen, refused)
                    elif proto == "apdu":
                        r = m12rt.check_apdu(codec, pysim, *data)
                    else:
                        r = m12rt.check_fcp(codec, pysim, data)
                    c[r.status] += 1
                    fields += r.fields
                    rows.append([proto, name, src, r.status, int(r.ours), "" if r.second is None else int(r.second),
                                 int(r.tshark_clean), r.fields, "; ".join(dict.fromkeys(r.notes))[:400]])
                totals += c
                print(f"M12ROUNDTRIP proto={proto} types={len(types)} without_independent_vector={no_indep}"
                      + (f" outside_v1={outside}" if outside else "") + " "
                      + " ".join(f"{k}={n}" for k, n in sorted(c.items())))
    finally:
        if pysim is not None:
            pysim.__exit__()
    with report.open("w") as f:
        f.write("# tests/oracles/oracle.py m12roundtrip (plan M12). Generated; not committed.\n")
        f.write("protocol\tpdu\tsource\tstatus\tours_roundtrip\tsecond_reader\ttshark_clean\tfields\tnotes\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
    fails = [r for r in rows if r[3] == "FAIL"]
    for r in fails[: a.show]:
        print(f"FAILURE {r[0]} {r[1]} {r[2]} {r[8][:220]}")
    print("M12ROUNDTRIP_TOTAL " + " ".join(f"{k}={n}" for k, n in sorted(totals.items()))
          + f" fields_compared={fields} report={report.relative_to(ROOT)}")
    return 0 if not fails else 1


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
    rt = sub.add_parser("roundtrip")
    rt.add_argument("--proto", action="append", choices=("ngap", "f1ap", "e1ap", "xnap", "rrc"))
    rt.add_argument("--pdu", action="append")
    rt.add_argument("--codec", help="ksim-codec binary (default: build/dev, or $KSIM_CODEC)")
    rt.add_argument("--show", type=int, default=40)
    l3 = sub.add_parser("l3roundtrip")
    l3.add_argument("--pdu", action="append")
    l3.add_argument("--codec")
    l3.add_argument("--show", type=int, default=40)
    l3.add_argument("--selftest", action="store_true", help="the must-fail mutations only")
    m12 = sub.add_parser("m12roundtrip")
    m12.add_argument("--pdu", action="append")
    m12.add_argument("--codec")
    m12.add_argument("--show", type=int, default=40)
    m12.add_argument("--selftest", action="store_true", help="the must-fail mutations only")
    pr = sub.add_parser("probes")
    pr.add_argument("--codec")
    lo = sub.add_parser("localize")
    lo.add_argument("proto")
    lo.add_argument("pdu")
    lo.add_argument("mode", choices=("min", "max"))
    lo.add_argument("--codec")
    al = sub.add_parser("allowlists")
    al.add_argument("--check", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args()
    sys.exit({"gen": cmd_gen, "check": cmd_check, "sweep": cmd_sweep, "roundtrip": cmd_roundtrip, "localize": cmd_localize, "probes": cmd_probes, "l3roundtrip": cmd_l3roundtrip, "m12roundtrip": cmd_m12roundtrip,
              "allowlists": cmd_allowlists, "selftest": cmd_selftest}[a.cmd](a))


if __name__ == "__main__":
    main()
