#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N8): the component run. ksim in real time against ksim-corestub
# on loopback SCTP, unprivileged, with throwaway range keys made for this run:
#   1. ksim-sim range init and derive (a master, a KEK, three sealed cards);
#   2. gates/run.sh stub: every P1 gate, rows scored from the sim's evidence;
#   3. the stub's own verdicts: FAILURES=0;
#   4. tools/pcap_check.py on the run's captures (tshark and pycrate), the card
#      traces of every UE among them (sim.pcapng, N14);
#   5. the canary over the run directory, the gates' ksim-ctl output and
#      ksim-sim's output (derive, a kaluza dry run) included.
# The run directory (no keys in it) is kept as build/component/last; the split run (P2 Q3) as
# build/component/split-last; the split E1 run (P2 Q5) as build/component/e1-last.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
B="$ROOT/build/dev/apps"
PY="$ROOT/.venv/bin/python"
for x in "$B/ksim/ksim" "$B/ksim-ctl/ksim-ctl" "$B/ksim-corestub/ksim-corestub" "$B/ksim-sim/ksim-sim"; do
    [[ -x "$x" ]] || { echo "COMPONENT=SKIP (no $x; build the dev preset)"; exit 77; }
done
command -v tshark >/dev/null || { echo "COMPONENT=SKIP (no tshark)"; exit 77; }
[[ -x "$PY" ]] || { echo "COMPONENT=SKIP (no oracle venv)"; exit 77; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
BLOCK=001010000300001/12
"$B/ksim-sim/ksim-sim" range init --master "$T/keys/master.key" --kek "$T/keys/kek.key" >/dev/null || exit 1
"$B/ksim-sim/ksim-sim" range derive --block "$BLOCK" --master "$T/keys/master.key" --kek "$T/keys/kek.key" \
    --out "$T/cards" > "$T/derive.out" || exit 1
# What ksim-sim prints is scanned too (ADR 0008): derive, and a kaluza dry run.
"$B/ksim-sim/ksim-sim" range provision --target kaluza --block "$BLOCK" --master "$T/keys/master.key" --dry-run \
    > "$T/kaluza-dryrun.out" || exit 1

rc=0
KSIM_RUNS="$T/runs" KSIM_MASTER="$T/keys/master.key" KSIM_KEK="$T/keys/kek.key" KSIM_SEALED="$T/cards" \
    KSIM_SIM_TRACE=1 sh "$ROOT/gates/run.sh" stub > "$T/gates.out" 2>&1 || rc=1
cat "$T/gates.out"
RUN="$(sed -n 's/^RUN_DIR=//p' "$T/gates.out")"
[[ -n "$RUN" && -d "$RUN" ]] || { echo "COMPONENT=FAIL (no run directory)"; exit 1; }
cp "$T/gates.out" "$RUN/gates.out"
cp "$T/derive.out" "$T/kaluza-dryrun.out" "$RUN/"

echo "-- the stub's verdicts"
cat "$RUN/stub.txt"
grep -qx 'FAILURES=0' "$RUN/stub.txt" || rc=1
grep -qx 'NG_SETUP=1' "$RUN/stub.txt" || rc=1

echo "-- captures"
"$PY" -I "$ROOT/tools/pcap_check.py" "$RUN" | tee "$T/pcap.out" || rc=1
# Every UE's card was traced (KSIM_SIM_TRACE): sim.pcapng has frames, and the canary below scans it.
[[ "$(sed -n 's/^PCAP_SIM_FRAMES=//p' "$T/pcap.out")" -gt 0 ]] 2>/dev/null || { echo "COMPONENT: no SIM trace"; rc=1; }

echo "-- canary"
"$PY" -I "$ROOT/tools/secret_canary.py" --run-dir "$RUN" --master "$T/keys/master.key" --block "$BLOCK" | tee "$T/canary.out" || rc=1
# What tools/p1_exit.py reads back (N16): the capture check and the canary's verdicts.
grep -E '^(PCAP_[A-Z_]+|PYCRATE_FAILED|CANARY_RUN)=' "$T/pcap.out" "$T/canary.out" | sed 's/^[^:]*://' > "$RUN/checks.txt"

mkdir -p "$ROOT/build/component"
rm -rf "$ROOT/build/component/last"
cp -r "$RUN" "$ROOT/build/component/last"
rm -f "$ROOT/build/component/last/ctl.sock"

# P2 Q3 (ADR 0011): the same P1 gates, and the split gate, with the roles as processes of their
# own (topologies/split-stub.yaml), scored against the P2 row set; captures and canary as above.
echo "-- the split run"
KSIM_RUNS="$T/runs-split" KSIM_MASTER="$T/keys/master.key" KSIM_KEK="$T/keys/kek.key" KSIM_SEALED="$T/cards" \
    KSIM_SIM_TRACE=1 KSIM_PHASE=p2 KSIM_TOPOLOGY_FILE="$ROOT/topologies/split-stub.yaml" \
    sh "$ROOT/gates/run.sh" stub "$ROOT"/gates/verification/ksim-p1-*.sh "$ROOT/gates/verification/ksim-p2-split.sh" \
    > "$T/split.out" 2>&1 || rc=1
cat "$T/split.out"
SRUN="$(sed -n 's/^RUN_DIR=//p' "$T/split.out")"
if [[ -n "$SRUN" && -d "$SRUN" ]]; then
    grep -qx 'FAILURES=0' "$SRUN/stub.txt" || rc=1
    "$PY" -I "$ROOT/tools/pcap_check.py" "$SRUN" | tee "$T/split-pcap.out" || rc=1
    "$PY" -I "$ROOT/tools/secret_canary.py" --run-dir "$SRUN" --master "$T/keys/master.key" --block "$BLOCK" \
        | tee "$T/split-canary.out" || rc=1
    grep -E '^(PCAP_[A-Z_]+|PYCRATE_FAILED|CANARY_RUN)=' "$T/split-pcap.out" "$T/split-canary.out" | sed 's/^[^:]*://' > "$SRUN/checks.txt"
    rm -rf "$ROOT/build/component/split-last"
    cp -r "$SRUN" "$ROOT/build/component/split-last"
    find "$ROOT/build/component/split-last" -name ctl.sock -delete
    find "$ROOT/build/component/split-last" -name kair.sock -delete
else
    echo "COMPONENT: no split run directory"; rc=1
fi

# P2 Q5: the E1 gate in split mode (topologies/split-stub-e1.yaml, a 15 s UE
# Inactivity Timer): the CU-UP's inactivity report and the release it leads to.
echo "-- the split E1 run"
KSIM_RUNS="$T/runs-e1" KSIM_MASTER="$T/keys/master.key" KSIM_KEK="$T/keys/kek.key" KSIM_SEALED="$T/cards" \
    KSIM_PHASE=p2 KSIM_TOPOLOGY_FILE="$ROOT/topologies/split-stub-e1.yaml" \
    sh "$ROOT/gates/run.sh" stub "$ROOT/gates/verification/ksim-p2-e1.sh" > "$T/e1.out" 2>&1 || rc=1
cat "$T/e1.out"
ERUN="$(sed -n 's/^RUN_DIR=//p' "$T/e1.out")"
if [[ -n "$ERUN" && -d "$ERUN" ]]; then
    "$PY" -I "$ROOT/tools/pcap_check.py" "$ERUN" | tee "$T/e1-pcap.out" || rc=1
    "$PY" -I "$ROOT/tools/secret_canary.py" --run-dir "$ERUN" --master "$T/keys/master.key" --block "$BLOCK" \
        | tee "$T/e1-canary.out" || rc=1
    rm -rf "$ROOT/build/component/e1-last"
    cp -r "$ERUN" "$ROOT/build/component/e1-last"
    find "$ROOT/build/component/e1-last" \( -name ctl.sock -o -name kair.sock \) -delete
else
    echo "COMPONENT: no split E1 run directory"; rc=1
fi
echo "COMPONENT=$([[ $rc -eq 0 ]] && echo PASS || echo FAIL) RUN=build/component/last"
exit "$rc"
