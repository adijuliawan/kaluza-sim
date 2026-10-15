#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The scale gate (P2 Q7): 100 UEs, 10 at a time (agreed with kaluza-core-df for the
# lab), each registered with one internet session. Rows of gates/rows/p2.tsv
# (KSIM_ROWS) whose milestone is Q7:
#   ksim-p2.scale-100-attach  split, C3: all registered with a session within 60 s
#   ksim-p2.scale-100-memory  split: the run's processes stay within 2 GiB resident
#   ksim-p2.ocudu-100         C3: the same through OCUDU's CU-CP
# Every session is released and every UE switched off at the end. The run's
# topology has the UEs (split-stub-100.yaml, split-lab-100.yaml,
# ocudu-c3-stub-100.yaml); against the stub its block holds them (STUB_BLOCK
# 001010000300000/100).
#
#   RUN=<run dir> CORE=stub|kaluza gates/verification/ksim-p2-scale.sh
#
# topology: topologies/split-stub-100.yaml
# SCALE_UES (default 100), SCALE_PARALLEL (default 10).

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

: "${SCALE_UES:=100}"
: "${SCALE_PARALLEL:=10}"
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
have=$(ctl ues | kv UES)
if [ "${have:-0}" -lt "$SCALE_UES" ]; then
    for id in ksim-p2.scale-100-attach ksim-p2.scale-100-memory ksim-p2.ocudu-100; do
        skip_row "$id" "the run has ${have:-0} UEs, not $SCALE_UES (a -100 topology)"
    done
    summary "ksim-p2-scale"
    exit $?
fi
all="1-$SCALE_UES"
p() { "$KSIM_CTL" --run "$RUN" --parallel "$SCALE_PARALLEL" "$@"; }

# An earlier gate of the run may have left some on: switched off first, cleanly.
p ue "$all" ps-release --all --wait 15s >/dev/null 2>&1
p ue "$all" power off --switch-off --wait 10s >/dev/null 2>&1
p ue "$all" power off --abrupt >/dev/null 2>&1   # on but not registered: nothing to deregister

echo "-- $SCALE_UES UEs, $SCALE_PARALLEL at a time"
t0=$(date +%s%N)
p ue "$all" power on --wait 60s > "$RUN/scale-power.out" 2>&1
p ue "$all" ps-establish ipv4 --dnn internet $SLICE --wait 30s > "$RUN/scale-ps.out" 2>&1
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
registered=$(grep -c '^RESULT=ACCEPT$' "$RUN/scale-power.out")
sessions=$(grep -c '^PSI=[0-9]' "$RUN/scale-ps.out")

# The run's processes: its roles (split), or the one node (aio: the manifest's pid).
pids=$(ctl nodes | sed -n 's/^NODE\.[0-9]*\.PID=//p' | grep -v '^-1$')
[ -n "$pids" ] || pids=$(sed -n 's/^ *"pid": *\([0-9]*\).*/\1/p' "$RUN/manifest.json" | head -n 1)
rss=0
for pid in $pids; do
    kb=$(sed -n 's/^VmRSS:[[:space:]]*\([0-9]*\) kB/\1/p' "/proc/$pid/status" 2>/dev/null)
    rss=$((rss + ${kb:-0}))
done
mib=$((rss / 1024))

row ksim-p2.scale-100-attach "^registered=$SCALE_UES sessions=$SCALE_UES within_60s=1\$" \
    "registered=$registered sessions=$sessions within_60s=$([ "$ms" -le 60000 ] && echo 1 || echo 0)"
row ksim-p2.scale-100-memory '^rss_mib=[0-9]+ within_2gib=1$' "rss_mib=$mib within_2gib=$([ "$mib" -le 2048 ] && echo 1 || echo 0)"
row ksim-p2.ocudu-100 "^registered=$SCALE_UES sessions=$SCALE_UES\$" "registered=$registered sessions=$sessions"
echo "   $SCALE_UES UEs registered with a session in ${ms} ms; ${mib} MiB resident"

echo "-- release and switch off"
p ue "$all" ps-release --all --wait 15s >/dev/null 2>&1
p ue "$all" power off --switch-off --wait 10s >/dev/null 2>&1

summary "ksim-p2-scale"
