#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N8): the component run. ksim in real time against ksim-corestub
# on loopback SCTP, unprivileged, with throwaway range keys made for this run:
#   1. ksim-sim range init and derive (a master, a KEK, three sealed cards);
#   2. gates/run.sh stub: every P1 gate, rows scored from the sim's evidence;
#   3. the stub's own verdicts: FAILURES=0;
#   4. tools/pcap_check.py on the run's captures (tshark and pycrate);
#   5. the canary over the run directory, the gates' ksim-ctl output and
#      ksim-sim's output (derive, a kaluza dry run) included.
# The run directory (no keys in it) is kept as build/component/last.
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
BLOCK=001010000300001/5
"$B/ksim-sim/ksim-sim" range init --master "$T/keys/master.key" --kek "$T/keys/kek.key" >/dev/null || exit 1
"$B/ksim-sim/ksim-sim" range derive --block "$BLOCK" --master "$T/keys/master.key" --kek "$T/keys/kek.key" \
    --out "$T/cards" > "$T/derive.out" || exit 1
# What ksim-sim prints is scanned too (ADR 0008): derive, and a kaluza dry run.
"$B/ksim-sim/ksim-sim" range provision --target kaluza --block "$BLOCK" --master "$T/keys/master.key" --dry-run \
    > "$T/kaluza-dryrun.out" || exit 1

rc=0
KSIM_RUNS="$T/runs" KSIM_MASTER="$T/keys/master.key" KSIM_KEK="$T/keys/kek.key" KSIM_SEALED="$T/cards" \
    sh "$ROOT/gates/run.sh" stub > "$T/gates.out" 2>&1 || rc=1
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
"$PY" -I "$ROOT/tools/pcap_check.py" "$RUN" || rc=1

echo "-- canary"
"$PY" -I "$ROOT/tools/secret_canary.py" --run-dir "$RUN" --master "$T/keys/master.key" --block "$BLOCK" || rc=1

mkdir -p "$ROOT/build/component"
rm -rf "$ROOT/build/component/last"
cp -r "$RUN" "$ROOT/build/component/last"
rm -f "$ROOT/build/component/last/ctl.sock"
echo "COMPONENT=$([[ $rc -eq 0 ]] && echo PASS || echo FAIL) RUN=build/component/last"
exit "$rc"
