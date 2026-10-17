#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""P3's exit check (plan R21; verification.md section 7; ADR 0013 point 12).

  tools/p3_exit.py [--runs <dir>] [--build <dir>] [--stub-only]

Accounts for the rows of gates/rows/p3.tsv (p3=yes) from the run directories' rows.tsv, each
row's newest result per (core, mode, topology). A row counts from its milestone on: REACHED
names the last milestone committed, and a row of a later milestone is NOT_YET (named, not
required). The counts, as the plan's R21 lists them:
  STUB_P3       every stub row of its modes PASS
  OPEN5GS_P3    PASS, or allowed (gates/allow/open5gs.tsv, open5gs=allow in the row's cores)
  KALUZA_P3     PASS, a kaluza-core finding docs/findings/KF-*.md naming the row, or CORE_GAP:
                a row marked kaluza=gap is named, never counted (D1, D5; design point g)
  OCUDU_MOB     C6, C7 and C8 rows: PASS or allowed (gates/allow/ocudu.tsv)
  KEYCHAIN      ksim-p3.keychain on the stub and Open5GS, the oracle's verdict in the run
  HO_LOSS       the loss rows from the dev-PC and kaluza-uesim reports
  FAULTS        the fault rows PASS; FAULTS=0 in every other exit run's manifest
  V1_REQS       v1 requirements not in docs/compliance/built.tsv (UNBUILT=0 at the exit)
  MUTANTS       killed / total (tools/mutants.sh)
  PCAP_MALFORMED, CANARY_HITS, NULL_AS_RUNS
                0, as in P2
The regression part (the P1 and P2 rows in the 3-gNB topology) is read from p2.tsv once R7's
topologies exist. Prints KEY=value lines and P3_EXIT=PASS|PENDING|FAIL; --stub-only checks what
CI can see and exits 0 when it passes.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from p2_exit import Results, account, allow_ids, kv_file, mode_of, null_as  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
# The last P3 milestone committed: rows of later milestones are not required yet.
REACHED = "R2"
OCUDU_MODES = ("C6", "C7", "C8")


def ms_key(ms: str) -> int:
    m = re.fullmatch(r"R(\d+)", ms)
    return int(m.group(1)) if m else 99


def p3_rows() -> list[dict]:
    with (ROOT / "gates/rows/p3.tsv").open() as f:
        rows = list(csv.DictReader((l for l in f if not l.startswith("#")), delimiter="\t"))
    return [r for r in rows if r["p3"] == "yes"]


def cores_of(r: dict) -> dict[str, str]:
    """core -> its qualifier ('' plain, 'allow', 'gap')."""
    out = {}
    for c in r["cores"].split(","):
        name, _, q = c.partition("=")
        out[name] = q
    return out


def kf_rows() -> dict[str, str]:
    out = {}
    for f in sorted((ROOT / "docs/findings").glob("KF-*.md")):
        text = f.read_text()
        if re.search(r"\*\*Status:\*\* closed", text):
            continue
        for rid in re.findall(r"\b(ksim-p3\.[a-z0-9.-]+[a-z0-9])\b", text):
            out.setdefault(rid, f.stem)
    return out


def unbuilt_v1() -> list[str]:
    built = set()
    for l in (ROOT / "docs/compliance/built.tsv").read_text().splitlines():
        if l.startswith("KS-"):
            built.add(l.split("\t")[0])
    out = []
    for l in (ROOT / "docs/requirements.md").read_text().splitlines():
        m = re.match(r"^\| (KS-[A-Z0-9]+-\d+) \|(.*)$", l)
        if not m:
            continue
        cells = [c.strip() for c in m.group(2).split("|")]
        if any(c == "v1" for c in cells) and m.group(1) not in built:
            out.append(m.group(1))
    return out


def collect(build: Path, runs: Path, stub_only: bool) -> Results:
    rs = Results()
    comp = build / "component"
    for d in sorted(comp.glob("p3-*-last")):
        rs.add("stub", mode_of(d), f"~ci/{d.name}", d / "rows.tsv", d)
    if not stub_only:
        for core in ("open5gs", "kaluza", "uesim"):
            for run in sorted(list(runs.glob(f"{core}-*")) + list((runs / "lab").glob(f"{core}-*"))):
                if run.is_dir():
                    rs.add(core, mode_of(run), run.name, run / "rows.tsv", run)
    return rs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, default=ROOT / "runs")
    ap.add_argument("--build", type=Path, default=ROOT / "build")
    ap.add_argument("--stub-only", action="store_true")
    a = ap.parse_args()
    rows = p3_rows()
    due = [r for r in rows if ms_key(r["milestone"]) <= ms_key(REACHED)]
    later = len(rows) - len(due)
    rs = collect(a.build, a.runs, a.stub_only)
    problems: list[str] = []
    pending: list[str] = []
    print(f"P3_ROWS={len(rows)} REACHED={REACHED} DUE={len(due)} NOT_YET={later}")

    def need(core: str, modes: tuple[str, ...]) -> list[tuple[dict, str]]:
        return [(r, m) for r in due if core in cores_of(r) for m in r["modes"].split(",") if m in modes]

    def tally(label: str, core: str, modes: tuple[str, ...], ok_extra, gate: list[str]) -> None:
        total = passed = other = 0
        missing: list[str] = []
        for mode in modes:
            want = [r for r, m in need(core, modes) if m == mode]
            p, o, inj, miss = account(want, rs.newest(core, mode), ok_extra)
            total += len(want)
            passed += p
            other += o
            missing += [f"{mode}:{x}" for x in miss + [f"{i}=inject" for i in inj]]
        print(f"{label}={passed}/{total} OTHER={other} UNACCOUNTED={len(missing)}")
        for m in missing:
            print(f"  {label} {m}")
        if missing:
            gate.append(f"{label}: {len(missing)} rows not accounted for")

    tally("STUB_P3", "stub", ("aio", "split"), lambda r, g, w: False, problems)
    allow_oc = {m: allow_ids("ocudu.tsv", m) for m in OCUDU_MODES}
    tally("OCUDU_MOB", "stub", OCUDU_MODES,
          lambda r, g, w: g == "ALLOWED" and any(r["id"] in allow_oc[m] for m in OCUDU_MODES), problems)
    if not a.stub_only:
        allow_o = allow_ids("open5gs.tsv")
        tally("OPEN5GS_P3", "open5gs", ("aio", "split"),
              lambda r, g, w: r["id"] in allow_o or cores_of(r).get("open5gs") == "allow", pending)
        kfs = kf_rows()
        gap = sorted(r["id"] for r in due if cores_of(r).get("kaluza") == "gap")
        served = [r for r in due if "kaluza" in cores_of(r) and cores_of(r)["kaluza"] != "gap"]
        res = rs.newest("kaluza", "split")
        p, o, inj, miss = account(served, res, lambda r, g, w: r["id"] in kfs)
        print(f"KALUZA_P3={p}/{len(served)} KF={o} CORE_GAP={len(gap)} UNACCOUNTED={len(miss) + len(inj)}")
        for m in miss + inj:
            print(f"  KALUZA_P3 {m}")
        if miss or inj:
            pending.append(f"KALUZA_P3: {len(miss) + len(inj)} rows not accounted for")

    unbuilt = unbuilt_v1()
    print(f"V1_REQS UNBUILT={len(unbuilt)}{' ' + ' '.join(unbuilt) if unbuilt else ''}")
    if unbuilt and ms_key(REACHED) >= ms_key("R18"):
        problems.append(f"V1_REQS: {len(unbuilt)} v1 requirements not built")

    m = kv_file(a.build / "mutants-run/last/summary.txt").get("MUTANTS_KILLED", "")
    print(f"MUTANTS={m or 'none'}")
    if not m or m.split("/")[0] != m.split("/")[-1]:
        problems.append(f"mutants: {m or 'no run (tools/mutants.sh)'}")
    malformed = hits = 0
    checked = []
    for f in sorted((a.build / "component").glob("*last/checks.txt")):
        text = f.read_text()
        checked.append(f.parent.name)
        malformed += sum(int(v) for v in re.findall(r"^PCAP_MALFORMED=(\d+)", text, re.M))
        hits += sum(int(v) for v in re.findall(r"CANARY_RUN=\w+ .*?hits=(\d+)", text))
    print(f"PCAP_MALFORMED={malformed} CANARY_HITS={hits} CHECKED={len(checked)}")
    if malformed or hits:
        problems.append("captures or canary: not clean in the CI runs")
    nulls = sorted({run.name for run in rs.runs if null_as(run)})
    print(f"NULL_AS_RUNS={len(nulls)}{' ' + ' '.join(nulls) if nulls else ''}")
    if nulls:
        problems.append("a run allowed NULL AS security")

    for p in problems:
        print(f"PROBLEM {p}")
    for p in pending:
        print(f"PENDING {p}")
    if a.stub_only:
        print(f"P3_EXIT_STUB={'PASS' if not problems else 'FAIL'}")
        return 0 if not problems else 1
    verdict = "FAIL" if problems else "PENDING" if pending or later else "PASS"
    print(f"P3_EXIT={verdict}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
