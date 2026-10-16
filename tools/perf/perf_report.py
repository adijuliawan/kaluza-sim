#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The performance report (P2 Q12): tools/perf/perf.sh's numbers against requirements.md §3.5.

    perf_report.py <perf.tsv> --commit SHA --host NAME

perf.tsv lines are "case<TAB>metric<TAB>value<TAB>unit". Each §3.5 target is scored from the
case that measures it; a target with no number is MISSING. Latency is the ping RTT through
the whole user plane with the link delay at 0: it holds both directions, so half of it is
an upper bound on one direction's added processing, which is what §3.5 bounds. The
attach target is scored on registration and session together, a stricter count. The last
lines are PERF=PASS|MISS and the text for a -T row."""

import argparse
import sys

# (case, metric, target, at least, what §3.5 says, transform)
TARGETS = [
    ("nea2", "tcp_dl", 200.0, True, "one UE with NEA2, DL Mbit/s", None),
    ("nea2", "tcp_ul", 100.0, True, "one UE with NEA2, UL Mbit/s", None),
    ("nea2", "tcp_dl_nia", 50.0, True, "with NIA2 UP integrity, DL Mbit/s", None),
    ("many", "tcp_dl_aggregate", 400.0, True, "100 UEs, aggregate DL Mbit/s", None),
    ("nea2", "rtt_median", 1.0, False, "added latency median, ms (half the RTT)", lambda v: v / 2),
    ("nea2", "rtt_p99", 5.0, False, "added latency p99, ms (half the RTT)", lambda v: v / 2),
    ("many", "attach_and_session", 60.0, False, "100 UEs registered with a session, 10 at a time, s", None),
    ("many", "rss_loaded", 2048.0, False, "memory with 100 UEs under load, MiB", None),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tsv")
    ap.add_argument("--commit", default="?")
    ap.add_argument("--host", default="?")
    a = ap.parse_args()
    values: dict[tuple[str, str], tuple[float, str]] = {}
    with open(a.tsv, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                continue
            try:
                values[(parts[0], parts[1])] = (float(parts[2]), parts[3])
            except ValueError:
                values[(parts[0], parts[1])] = (float("nan"), parts[3])
    for (case, metric), (v, unit) in sorted(values.items()):
        print(f"PERF.{case}.{metric}={v:g} {unit}")
    met = 0
    seen = []
    for case, metric, target, at_least, what, tf in TARGETS:
        got = values.get((case, metric))
        if got is None:
            print(f"TARGET {what}: MISSING ({case}.{metric})")
            seen.append(f"{what} missing")
            continue
        v = tf(got[0]) if tf else got[0]
        ok = v >= target if at_least else v <= target
        met += ok
        sign = ">=" if at_least else "<="
        print(f"TARGET {what}: {v:.2f} {sign} {target:g} {'PASS' if ok else 'MISS'}")
        seen.append(f"{what} {v:.2f} ({'met' if ok else 'missed'}, {sign} {target:g})")
    extra = [f"{c}.{m} {v:g} {u}" for (c, m), (v, u) in sorted(values.items())
             if not any(c == t[0] and m == t[1] for t in TARGETS)]
    print(f"PERF_TARGETS_MET={met}/{len(TARGETS)}")
    print(f"PERF={'PASS' if met == len(TARGETS) else 'MISS'}")
    print("T_ROW=" + f"§3.5 on {a.host} at {a.commit}: " + "; ".join(seen)
          + (". Also: " + "; ".join(extra) if extra else ""))
    return 0 if met == len(TARGETS) else 1


if __name__ == "__main__":
    sys.exit(main())
