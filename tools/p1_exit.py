#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""P1's exit check (plan N16/N19; verification.md section 7).

  tools/p1_exit.py [--stub <run dir>] [--runs <dir>] [--stub-only]

Accounts for every row of gates/rows/p1.tsv marked p1=yes on each core that
scores it, from the run directories' rows.tsv (for a real core, each row's
newest result across its runs):
  stub      every row PASS; a row the stub run SKIPs because it needs the TUN
            data plane counts when that row PASSes in netns mode on a real core
  open5gs   PASS, or allowed: gates/allow/open5gs.tsv, or open5gs=allow in
            the row's cores column (D3)
  kaluza    PASS, or a kaluza-core finding docs/findings/KF-*.md that names
            the row (acknowledged by the core session)
and the rest of the exit: MUTANTS_KILLED=n/n (tools/mutants.sh),
PYSIM_EF_READ=n/n (tests/oracles/pysim_shell.py), PCAP_MALFORMED=0 and
CANARY_HITS=0 (the component run), netns mode on both real cores, and at least
one KF (or the user's acceptance of none: --no-kf-accepted).

Prints KEY=value lines and P1_EXIT=PASS|PENDING|FAIL. --stub-only checks the
parts CI can see (the stub, mutants, pySim, captures); exit 0 when they pass.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def p1_rows() -> list[dict]:
    with (ROOT / "gates/rows/p1.tsv").open() as f:
        rows = [r for r in csv.DictReader((l for l in f if not l.startswith("#")), delimiter="\t")]
    return [r for r in rows if r["p1"] == "yes"]


def results(run: Path) -> dict[str, tuple[str, str]]:
    out = {}
    f = run / "rows.tsv"
    if f.is_file():
        for line in f.read_text().splitlines():
            c = line.split("\t")
            if len(c) >= 2:
                out[c[0]] = (c[1], c[3] if len(c) > 3 else "")
    return out


def newest_per_row(runs: list[Path]) -> tuple[dict[str, tuple[str, str, str]], list[str]]:
    """Each row's result from the newest run that scored it, and the runs read."""
    out: dict[str, tuple[str, str, str]] = {}
    used = []
    for run in sorted(runs, key=lambda p: p.name):
        r = results(run)
        if r:
            used.append(run.name)
        for k, (res, why) in r.items():
            out[k] = (res, why, run.name)
    return out, used


def kv_file(p: Path) -> dict[str, str]:
    out = {}
    if p.is_file():
        for line in p.read_text().splitlines():
            for part in line.split():
                if "=" in part:
                    k, v = part.split("=", 1)
                    out.setdefault(k, v)
    return out


def allowed_open5gs() -> set[str]:
    f = ROOT / "gates/allow/open5gs.tsv"
    if not f.is_file():
        return set()
    return {l.split("\t")[0] for l in f.read_text().splitlines() if l and not l.startswith("#")}


def kf_rows() -> dict[str, str]:
    out = {}
    for f in sorted((ROOT / "docs/findings").glob("KF-*.md")):
        for rid in re.findall(r"\b((?:amf|smf)-ueransim\.\d+|smsf\.\d+|ksim-p1\.[a-z0-9-]+)\b", f.read_text()):
            out.setdefault(rid, f.stem)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stub", type=Path, default=ROOT / "build/component/last")
    ap.add_argument("--runs", type=Path, default=ROOT / "runs")
    ap.add_argument("--stub-only", action="store_true")
    ap.add_argument("--no-kf-accepted", action="store_true", help="the user accepted an exit with no KF")
    a = ap.parse_args()
    rows = p1_rows()
    problems: list[str] = []
    pending: list[str] = []

    real = {}
    for core in ("open5gs", "kaluza"):
        runs = [d for d in list(a.runs.glob(f"{core}-*")) + list((a.runs / "lab").glob(f"{core}-*")) if d.is_dir()]
        real[core] = newest_per_row(runs)
    netns_pass = {k for core in real for k, (res, _, _) in real[core][0].items() if res == "PASS"}

    # stub
    stub = results(a.stub)
    s_rows = [r for r in rows if "stub" in r["cores"].split(",")]
    s_pass = sum(1 for r in s_rows if stub.get(r["id"], ("",))[0] == "PASS")
    s_netns = [r["id"] for r in s_rows if stub.get(r["id"], ("", ""))[0] == "SKIP" and "inject mode" in stub[r["id"]][1]]
    s_netns_ok = [x for x in s_netns if x in netns_pass]
    s_bad = [r["id"] for r in s_rows if stub.get(r["id"], ("",))[0] not in ("PASS",) and r["id"] not in s_netns]
    print(f"STUB={s_pass}/{len(s_rows)} NETNS_ONLY={len(s_netns)} NETNS_COVERED={len(s_netns_ok)} UNACCOUNTED={len(s_bad)}")
    if s_bad:
        problems.append(f"stub rows not passing: {' '.join(s_bad)}")
    if len(s_netns_ok) < len(s_netns):
        pending.append(f"stub netns-only rows without a netns PASS: {' '.join(x for x in s_netns if x not in s_netns_ok)}")

    # mutants, pySim, captures
    m = kv_file(ROOT / "build/mutants-run/last/summary.txt").get("MUTANTS_KILLED", "")
    print(f"MUTANTS={m or 'none'}")
    if not m or m.split("/")[0] != m.split("/")[-1]:
        problems.append(f"mutants: {m or 'no run (tools/mutants.sh)'}")
    py = kv_file(ROOT / "build/pysim/last/summary.txt").get("PYSIM_EF_READ", "")
    print(f"PYSIM_EF_READ={py or 'none'}")
    if not py or py.split("/")[0] != py.split("/")[-1]:
        problems.append(f"pySim: {py or 'no run (tools/ci.d/55-pysim.sh)'}")
    ck = kv_file(a.stub / "checks.txt")
    hits = re.search(r"hits=(\d+)", (a.stub / "checks.txt").read_text()) if (a.stub / "checks.txt").is_file() else None
    print(f"PCAP_MALFORMED={ck.get('PCAP_MALFORMED', '?')} CANARY_HITS={hits.group(1) if hits else '?'}")
    if ck.get("PCAP_MALFORMED") != "0" or not hits or hits.group(1) != "0":
        problems.append("captures or canary: not clean in the component run")

    if not a.stub_only:
        allow = allowed_open5gs()
        kfs = kf_rows()
        for core in ("open5gs", "kaluza"):
            res, used = real[core]
            c_rows = [r for r in rows if core in r["cores"].replace(";", ",").split(",") or f"{core}=allow" in r["cores"]]
            ok = acc = 0
            missing = []
            for r in c_rows:
                got = res.get(r["id"], ("", "", ""))[0]
                if got == "PASS":
                    ok += 1
                elif core == "open5gs" and (r["id"] in allow or "open5gs=allow" in r["cores"]):
                    acc += 1
                elif core == "kaluza" and r["id"] in kfs:
                    acc += 1
                else:
                    missing.append(r["id"])
            label = "ALLOWED" if core == "open5gs" else "KF"
            print(f"{core.upper()}={ok}/{len(c_rows)} {label}={acc} UNACCOUNTED={len(missing)} RUNS={len(used)}")
            if missing:
                pending.append(f"{core}: {len(missing)} rows not yet accounted for")
            # Netns mode: the TUN rows (those the stub run skips in inject mode) pass on this core.
            netns = bool(s_netns) and all(res.get(x, ("",))[0] == "PASS" for x in s_netns if x in {r["id"] for r in c_rows})
            print(f"{core.upper()}_NETNS={'yes' if netns else 'no'}")
            if not netns:
                pending.append(f"{core}: no data-plane row passed in netns mode")
        n_kf = len(list((ROOT / "docs/findings").glob("KF-*.md")))
        print(f"KF={n_kf}")
        if n_kf == 0 and not a.no_kf_accepted:
            pending.append("no KF handed over (stop and ask: is no finding acceptable?)")

    for p in problems:
        print(f"PROBLEM {p}")
    for p in pending:
        print(f"PENDING {p}")
    if a.stub_only:
        print(f"P1_EXIT_STUB={'PASS' if not problems else 'FAIL'}")
        return 0 if not problems else 1
    verdict = "FAIL" if problems else "PENDING" if pending else "PASS"
    print(f"P1_EXIT={verdict}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
