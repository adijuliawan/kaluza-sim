#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""P2's exit check (plan Q16; verification.md section 7).

  tools/p2_exit.py [--runs <dir>] [--build <dir>] [--stub-only]

Accounts for the rows of gates/rows/p2.tsv marked p2=yes, keyed by (core, mode), from the run
directories' rows.tsv. Each row's newest result per (core, mode) counts. A run's mode comes from
its manifest: aio, split, or the OCUDU combination the missing roles show (C3 neither CU,
C4 no CU-UP of ours, C5 no CU-CP of ours). The counts:
  STUB_SPLIT        every stub row of split mode PASS; a row the stub run SKIPs in inject mode
                    (no TUN) counts when it PASSes in split mode on a real core (netns)
  OPEN5GS_SPLIT     PASS, or allowed (gates/allow/open5gs.tsv, open5gs=allow in the row's cores)
  KALUZA_SPLIT      PASS, or a kaluza-core finding docs/findings/KF-*.md that names the row
  OCUDU_C3          the stub's C3 rows: PASS, allowed (gates/allow/ocudu.tsv for C3), or an
                    inject-mode SKIP that PASSes in C3 on a real core
  OCUDU_C3_KALUZA   kaluza-core's C3 rows: PASS or a KF
  OCUDU_E1          C4 and C5 on the stub (plan Q5): each E1 row of the mode, and every row the
                    C4 and C5 runs scored, PASS or allowed; their inject-mode SKIPs are named
                    (no core runs C4 or C5 in netns mode: design point b)
  PERF              each requirements.md §3.5 target from kaluza-uesim's report (LW3)
  SCALE_100         the 100-UE rows, inside the counts above
  CARD_PCSC         the PC/SC path and the bridge's refusals (hook 57, vpcd)
  CARD_REAL         the real card: through PC/SC on the stub and Open5GS, through the bridge
                    on kaluza-core (its PC/SC row is met there by the bridge row), the burn
  MUTANTS           killed / total (tools/mutants.sh)
  PCAP_MALFORMED, CANARY_HITS
                    0 in the CI runs: component aio and split, OCUDU C3/C4/C5, PC/SC
  NULL_AS_RUNS      runs read here whose manifest allowed NULL AS security: must be 0
  KF                kaluza-core findings handed over (informational)
The card rows are counted in CARD_*, not in the per-mode counts: a card is a UE's card in any
mode. The rows of other (core, mode) pairs the modes column allows are not required (the
plan's exit names the pairs above). Prints KEY=value lines and P2_EXIT=PASS|PENDING|FAIL;
--stub-only checks what CI can see (the stub, mutants, captures) and exits 0 when it passes.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODES = ("aio", "split", "C3", "C4", "C5")
INJECT = "inject mode"
CARD_ROWS = ("ksim-p2.pcsc-register", "ksim-p2.bridge-refuses-admin", "ksim-p2.burn-verify",
             "ksim-p2.real-card-register", "ksim-p2.real-card-bridge")
SCALE_ROWS = ("ksim-p2.scale-100-attach", "ksim-p2.scale-100-memory", "ksim-p2.ocudu-100")
# tools/perf/perf_report.py's target labels for each performance row.
PERF_ROWS = {
    "ksim-p2.perf-dl-nea2": ["one UE with NEA2, DL Mbit/s"],
    "ksim-p2.perf-ul-nea2": ["one UE with NEA2, UL Mbit/s"],
    "ksim-p2.perf-nia2": ["with NIA2 UP integrity, DL Mbit/s"],
    "ksim-p2.perf-100-dl": ["100 UEs, aggregate DL Mbit/s"],
    "ksim-p2.perf-latency": ["added latency median, ms (half the RTT)", "added latency p99, ms (half the RTT)"],
    "ksim-p2.perf-attach-100": ["100 UEs registered with a session, 10 at a time, s"],
    "ksim-p2.perf-memory": ["memory with 100 UEs under load, MiB"],
}


def p2_rows() -> list[dict]:
    with (ROOT / "gates/rows/p2.tsv").open() as f:
        rows = list(csv.DictReader((l for l in f if not l.startswith("#")), delimiter="\t"))
    return [r for r in rows if r["p2"] == "yes"]


def cores_of(r: dict) -> list[str]:
    return [c.split("=")[0] for c in r["cores"].replace(";", ",").split(",") if c]


def results(f: Path) -> dict[str, tuple[str, str]]:
    out = {}
    if f.is_file():
        for line in f.read_text().splitlines():
            c = line.split("\t")
            if len(c) >= 2:
                out[c[0]] = (c[1], c[3] if len(c) > 3 else "")
    return out


def manifests(run: Path) -> list[dict]:
    out = []
    for m in [run / "manifest.json"] + sorted(run.glob("*/manifest.json")):
        try:
            out.append(json.loads(m.read_text()))
        except (OSError, ValueError):
            pass
    return out


def mode_of(run: Path) -> str | None:
    try:
        m = json.loads((run / "manifest.json").read_text())
    except (OSError, ValueError):
        return None
    if "roles" not in m:
        return "aio"
    roles = set(m["roles"])
    if {"cucp", "cuup"} <= roles:
        return "split"
    if "cucp" not in roles and "cuup" not in roles:
        return "C3"
    return "C4" if "cuup" not in roles else "C5"


def null_as(run: Path) -> bool:
    return any(m.get("security", {}).get("allow_null") is True for m in manifests(run))


def kv_file(p: Path) -> dict[str, str]:
    out = {}
    if p.is_file():
        for line in p.read_text().splitlines():
            for part in line.split():
                if "=" in part:
                    k, v = part.split("=", 1)
                    out.setdefault(k, v)
    return out


def allow_ids(name: str, mode: str | None = None) -> set[str]:
    f = ROOT / "gates/allow" / name
    out = set()
    if f.is_file():
        for l in f.read_text().splitlines():
            c = l.split("\t")
            if l.startswith("#") or len(c) < 2:
                continue
            # ocudu.tsv's third column lists the modes; open5gs.tsv has none.
            if mode is None or (len(c) > 2 and mode in c[2].split(",")):
                out.add(c[1])
    return out


def kf_rows() -> dict[str, str]:
    out = {}
    for f in sorted((ROOT / "docs/findings").glob("KF-*.md")):
        text = f.read_text()
        if re.search(r"\*\*Status:\*\* closed", text):
            continue   # a closed finding accounts for nothing now: its rows must pass
        for rid in re.findall(r"\b((?:amf|smf)-ueransim\.\d+|smsf\.\d+|ksim-p[12]\.[a-z0-9-]+)\b", text):
            out.setdefault(rid, f.stem)
    return out


class Results:
    """Each (core, mode)'s newest result per row, and the runs read."""

    def __init__(self) -> None:
        self.sets: dict[tuple[str, str], list[tuple[str, dict]]] = {}
        self.runs: list[Path] = []

    def add(self, core: str, mode: str | None, key: str, rows_file: Path, run: Path | None = None) -> None:
        r = results(rows_file)
        if not r or mode is None:
            return
        self.sets.setdefault((core, mode), []).append((key, r))
        if run is not None:
            self.runs.append(run)

    def newest(self, core: str, mode: str) -> dict[str, tuple[str, str, str]]:
        out: dict[str, tuple[str, str, str]] = {}
        for key, r in sorted(self.sets.get((core, mode), []), key=lambda x: x[0]):
            for rid, (res, why) in r.items():
                out[rid] = (res, why, key)
        return out


def collect(build: Path, runs: Path, stub_only: bool) -> Results:
    rs = Results()
    # The stub, from what the CI hooks kept (the key orders them after any real-core run).
    comp = build / "component"
    for d in ("last", "split-last", "e1-last", "scale-last", "nea1-aio-last", "nea1-split-last"):
        run = comp / d
        mode = mode_of(run) or ("split" if d in ("e1-last", "scale-last") else None)
        rs.add("stub", mode, f"~ci/{d}", run / "rows.tsv", run)
    oc = build / "ocudu/last"
    for name, mode in (("c3", "C3"), ("c3-100", "C3"), ("c3-nea1", "C3"), ("c4", "C4"), ("c5", "C5")):
        rs.add("stub", mode, f"~ci/ocudu-{name}", oc / f"{name}.rows.tsv", oc / name)
    if not stub_only:
        for core in ("open5gs", "kaluza"):
            for run in sorted(list(runs.glob(f"{core}-*")) + list((runs / "lab").glob(f"{core}-*"))):
                if run.is_dir():
                    rs.add(core, mode_of(run), run.name, run / "rows.tsv", run)
    return rs


def account(rows: list[dict], res: dict[str, tuple[str, str, str]], ok_extra, covered=None) -> tuple[int, int, list[str], list[str]]:
    """PASS count, accounted-otherwise count, the inject-only SKIPs, the unaccounted rows."""
    passed = other = 0
    inject: list[str] = []
    missing: list[str] = []
    for r in rows:
        got, why, _ = res.get(r["id"], ("", "", ""))
        if got == "PASS":
            passed += 1
        elif got and ok_extra(r, got, why):   # an allow-list or a finding covers a row that ran
            other += 1
        elif got == "SKIP" and INJECT in why:
            if covered is not None and covered(r["id"]):
                other += 1
            else:
                inject.append(r["id"])
        else:
            missing.append(f"{r['id']}={got or 'none'}")
    return passed, other, inject, missing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, default=ROOT / "runs")
    ap.add_argument("--build", type=Path, default=ROOT / "build")
    ap.add_argument("--stub-only", action="store_true")
    a = ap.parse_args()
    rows = [r for r in p2_rows() if r["id"] not in CARD_ROWS and r["id"] not in PERF_ROWS]
    by_id = {r["id"]: r for r in p2_rows()}
    rs = collect(a.build, a.runs, a.stub_only)
    problems: list[str] = []
    pending: list[str] = []

    def need(core: str, mode: str) -> list[dict]:
        return [r for r in rows if core in cores_of(r) and mode in r["modes"].split(",")]

    def netns_pass(mode: str):
        real = {c: rs.newest(c, mode) for c in ("open5gs", "kaluza")}
        return lambda rid: any(real[c].get(rid, ("",))[0] == "PASS" for c in real)

    def report(label: str, n: int, p: int, o: int, olabel: str, inject: list[str], missing: list[str], gate: list[str]) -> None:
        line = f"{label}={p}/{n} {olabel}={o}"
        if inject:
            line += f" INJECT_ONLY={len(inject)}"
        print(f"{line} UNACCOUNTED={len(missing)}")
        for m in missing:
            print(f"  {label} {m}")
        if missing:
            gate.append(f"{label}: {len(missing)} rows not accounted for")

    # The stub in split mode, and C3/C4/C5.
    stub_split = rs.newest("stub", "split")
    n = need("stub", "split")
    p, o, inj, miss = account(n, stub_split, lambda r, g, w: False,
                              None if a.stub_only else netns_pass("split"))
    if a.stub_only:   # CI cannot see the real cores: the inject-only rows are counted, not judged
        o, inj = o + len(inj), []
    report("STUB_SPLIT", len(n), p, o, "NETNS_COVERED", inj, miss, problems)
    if inj:
        pending.append(f"STUB_SPLIT: {len(inj)} inject-mode rows with no netns PASS on a real core")

    allow_c3 = allow_ids("ocudu.tsv", "C3")
    c3 = rs.newest("stub", "C3")
    n = need("stub", "C3")
    p, o, inj, miss = account(n, c3, lambda r, g, w: g == "ALLOWED" and r["id"] in allow_c3,
                              None if a.stub_only else netns_pass("C3"))
    if a.stub_only:
        o, inj = o + len(inj), []
    report("OCUDU_C3", len(n), p, o, "ALLOWED_OR_NETNS", inj, miss, problems)
    if inj:
        pending.append(f"OCUDU_C3: {len(inj)} inject-mode rows with no netns PASS in C3 on a real core")

    e1_total = e1_ok = 0
    e1_inject: list[str] = []
    for mode in ("C4", "C5"):
        res = rs.newest("stub", mode)
        allow = allow_ids("ocudu.tsv", mode)
        scored = {rid for rid, (g, _, _) in res.items() if g != "SKIP" or INJECT in res[rid][1]}
        want = [r for r in rows if mode in r["modes"].split(",") and r["milestone"] == "Q5" and "stub" in cores_of(r)]
        want += [by_id[rid] for rid in sorted(scored) if rid in by_id and by_id[rid] not in want and rid not in CARD_ROWS]
        p, o, inj, miss = account(want, res, lambda r, g, w, allow=allow: g == "ALLOWED" and r["id"] in allow)
        e1_total += len(want)
        e1_ok += p + o
        e1_inject += [f"{mode}:{x}" for x in inj]
        for m in miss:
            print(f"  OCUDU_E1 {mode} {m}")
        if miss:
            problems.append(f"OCUDU_E1 {mode}: {len(miss)} rows not accounted for")
    print(f"OCUDU_E1={e1_ok}/{e1_total - len(e1_inject)} INJECT_ONLY={len(e1_inject)}"
          f"{' (' + ' '.join(e1_inject) + ')' if e1_inject else ''}")

    # The real cores.
    kfs = kf_rows()
    if not a.stub_only:
        allow_o = allow_ids("open5gs.tsv")
        res = rs.newest("open5gs", "split")
        n = need("open5gs", "split")
        p, o, inj, miss = account(n, res, lambda r, g, w: r["id"] in allow_o or "open5gs=allow" in r["cores"])
        report("OPEN5GS_SPLIT", len(n), p, o, "ALLOWED", inj, miss + [f"{x}=inject" for x in inj], pending)
        for label, mode in (("KALUZA_SPLIT", "split"), ("OCUDU_C3_KALUZA", "C3")):
            res = rs.newest("kaluza", mode)
            n = need("kaluza", mode)
            p, o, inj, miss = account(n, res, lambda r, g, w: r["id"] in kfs)
            report(label, len(n), p, o, "KF", inj, miss + [f"{x}=inject" for x in inj], pending)

    # The 100-UE rows, as each (core, mode) scored them.
    scale = []
    for rid in SCALE_ROWS:
        r = by_id.get(rid)
        if r is None:
            continue
        for core in cores_of(r):
            if a.stub_only and core != "stub":
                continue
            for mode in r["modes"].split(","):
                if mode in ("split", "C3"):
                    scale.append((rid, core, mode, rs.newest(core, mode).get(rid, ("none",))[0]))
    s_ok = sum(1 for x in scale if x[3] == "PASS")
    print(f"SCALE_100={s_ok}/{len(scale)}")
    for rid, core, mode, got in scale:
        if got != "PASS":
            print(f"  SCALE_100 {rid} {core} {mode}={got}")
            (problems if core == "stub" else pending).append(f"SCALE_100: {rid} on {core} {mode}")

    # The cards.
    pc = results(a.build / "pcsc/last/rows.tsv")
    card_pcsc = [(rid, pc.get(rid, ("none",))[0]) for rid in ("ksim-p2.pcsc-register", "ksim-p2.bridge-refuses-admin")]
    c_ok = sum(1 for _, g in card_pcsc if g == "PASS")
    print(f"CARD_PCSC={c_ok}/{len(card_pcsc)}")
    if c_ok < len(card_pcsc):
        problems.append(f"CARD_PCSC: {card_pcsc}")
    if not a.stub_only:
        card_runs = Results()
        for run in sorted((a.runs / "card").glob("stub-*")):
            card_runs.add("stub", mode_of(run), run.name, run / "rows.tsv", run)
        def real_card(core: str, rid: str) -> str:
            src = card_runs if core == "stub" else rs
            return "PASS" if any(src.newest(core, m).get(rid, ("",))[0] == "PASS" for m in MODES) else "none"
        real = [("ksim-p2.real-card-register", "stub", real_card("stub", "ksim-p2.real-card-register")),
                ("ksim-p2.real-card-register", "open5gs", real_card("open5gs", "ksim-p2.real-card-register")),
                ("ksim-p2.real-card-bridge", "kaluza", rs.newest("kaluza", "split").get("ksim-p2.real-card-bridge", ("none",))[0]),
                # The burn tool's own check is CI's (vpcd soft card); the real burn is shown by the
                # real card's registrations with range-derived keys (KS-UICC-T8).
                ("ksim-p2.burn-verify", "card", pc.get("ksim-p2.burn-verify", ("none",))[0])]
        r_ok = sum(1 for x in real if x[2] == "PASS")
        print(f"CARD_REAL={r_ok}/{len(real)}")
        for rid, core, got in real:
            if got != "PASS":
                print(f"  CARD_REAL {rid} {core}={got}")
                pending.append(f"CARD_REAL: {rid} on {core}")

    # Performance on kaluza-uesim (LW3): the newest report that names the VM.
    if not a.stub_only:
        reports = sorted(a.runs.glob("lab/perf-*/last/report.txt"))
        reports = [r for r in reports if "on kaluza-uesim" in r.read_text()]
        targets: dict[str, tuple[str, str]] = {}
        if reports:
            for line in reports[-1].read_text().splitlines():
                m = re.match(r"TARGET (.+): (\S+) (?:>=|<=) \S+ (PASS|MISS)$", line)
                if m:
                    targets[m.group(1)] = (m.group(2), m.group(3))
        met = []
        for rid, labels in PERF_ROWS.items():
            ok = all(targets.get(l, ("", ""))[1] == "PASS" for l in labels)
            met.append(ok)
            vals = ",".join(targets.get(l, ("?",))[0] for l in labels)
            print(f"  PERF {rid}={'PASS' if ok else 'MISS'} value={vals}")
        print(f"PERF={sum(met)}/{len(met)} REPORT={reports[-1].parent.parent.name if reports else 'none'}")
        if not all(met):
            pending.append("PERF: a §3.5 target is not met on kaluza-uesim (resizing VM 105 is the user's call)")

    # Mutants, captures, canary, NULL.
    m = kv_file(a.build / "mutants-run/last/summary.txt").get("MUTANTS_KILLED", "")
    print(f"MUTANTS={m or 'none'}")
    if not m or m.split("/")[0] != m.split("/")[-1]:
        problems.append(f"mutants: {m or 'no run (tools/mutants.sh)'}")
    malformed = hits = 0
    checked = []
    for f in [a.build / "component/last/checks.txt", a.build / "component/split-last/checks.txt"] + \
             sorted((a.build / "ocudu/last").glob("*.pcap.out")) + sorted((a.build / "ocudu/last").glob("*.canary.out")):
        if not f.is_file():
            continue
        text = f.read_text()
        checked.append(f.name)
        for v in re.findall(r"^PCAP_MALFORMED=(\d+)", text, re.M):
            malformed += int(v)
        for v in re.findall(r"CANARY_RUN=\w+ .*?hits=(\d+)", text):
            hits += int(v)
        if "CANARY_RUN=FAIL" in text or "PCAP_CHECK=FAIL" in text:
            problems.append(f"captures or canary: {f.relative_to(a.build)}")
    print(f"PCAP_MALFORMED={malformed} CANARY_HITS={hits} CHECKED={len(checked)}")
    if malformed or hits or len(checked) < 2:
        problems.append("captures or canary: not clean in the CI runs")
    nulls = sorted({run.name for run in rs.runs if null_as(run)})
    print(f"NULL_AS_RUNS={len(nulls)}{' ' + ' '.join(nulls) if nulls else ''}")
    if nulls:
        problems.append("a run allowed NULL AS security")
    print(f"KF={len(list((ROOT / 'docs/findings').glob('KF-*.md')))} OPEN_KF_ROWS={' '.join(sorted(kfs)) or '-'}")

    for p in problems:
        print(f"PROBLEM {p}")
    for p in pending:
        print(f"PENDING {p}")
    if a.stub_only:
        print(f"P2_EXIT_STUB={'PASS' if not problems else 'FAIL'}")
        return 0 if not problems else 1
    verdict = "FAIL" if problems else "PENDING" if pending else "PASS"
    print(f"P2_EXIT={verdict}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
