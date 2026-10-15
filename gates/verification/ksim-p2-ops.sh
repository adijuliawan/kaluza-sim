#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The operations gate (P2 Q7; ADR 0011 point 6): the watchdog and metrics v0.
# Rows of gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q7, aio and split:
#   ksim-p2.metrics         /v1/metrics gives per-QFI bytes and per-hop latency for a
#                           running session
#   ksim-p2.loop-lag-abort  a loop stalled past the watchdog's threshold raises
#                           platform.loop_lag, and a gate then ABORTs (exit 7) rather
#                           than scoring rows
# The stall is ksim-ctl debug stall (the DU's loop in a split run, which has timers
# coming due); the topology's watchdog_ms is the default 250.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p2-ops.sh
#
# UE OPS_UE (default 10).

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
: "${OPS_UE:=10}"
u=$OPS_UE
st=$(ctl ue "$u" status 2>/dev/null)
[ "$(printf '%s\n' "$st" | kv POWER)" = on ] && ctl ue "$u" power off --abrupt >/dev/null 2>&1

echo "-- metrics for a running session (UE $u)"
ctl ue "$u" power on --wait 30s >/dev/null || abort "UE $u did not register"
psi=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
[ -n "$psi" ] || abort "UE $u got no session"
ctl ue "$u" ping "${DN_ADDR:-10.60.0.1}" --psi "$psi" -c 3 --interval 200 >/dev/null
m=$(ctl metrics)
ul=$(printf '%s\n' "$m" | sed -n 's/^ksim_qfi_bytes_total{\(role="[a-z]*",\)\{0,1\}qfi="1",direction="ul"} //p' | head -n 1)
dl=$(printf '%s\n' "$m" | sed -n 's/^ksim_qfi_bytes_total{\(role="[a-z]*",\)\{0,1\}qfi="1",direction="dl"} //p' | head -n 1)
up=$(printf '%s\n' "$m" | sed -n 's/^ksim_hop_latency_ms_count{\(role="[a-z]*",\)\{0,1\}hop="kair_ul"} //p' | head -n 1)
down=$(printf '%s\n' "$m" | sed -n 's/^ksim_hop_latency_ms_count{\(role="[a-z]*",\)\{0,1\}hop="kair_dl"} //p' | head -n 1)
row ksim-p2.metrics '^ul_bytes=[1-9][0-9]* dl_bytes=[1-9][0-9]* kair_ul=[1-9][0-9]* kair_dl=[1-9][0-9]*$' \
    "ul_bytes=${ul:-0} dl_bytes=${dl:-0} kair_ul=${up:-0} kair_dl=${down:-0}"
release_all "$u"
ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1

echo "-- the watchdog"
seq=$(ctl info | kv EVENT_SEQ)
ctl debug stall 600 >/dev/null || abort "the run took no stall"
lag=$(ctl wait platform.loop_lag --since "$seq" --timeout 5s | kv EVENT)
# A gate scoring a row now ABORTs: lag_guard, in a subshell so this gate goes on.
( KSIM_GATE_SEQ=$seq; lag_guard ) >/dev/null 2>&1
code=$?
KSIM_GATE_SEQ=$(ctl info | kv EVENT_SEQ)   # this gate's own rows count from here
row ksim-p2.loop-lag-abort '^lag=platform.loop_lag abort=7$' "lag=$lag abort=$code"

summary "ksim-p2-ops"
