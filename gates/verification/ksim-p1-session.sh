#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P1 session gate (P1 N10): IPv4 PDU sessions end to end (5GSM, the
# CU-CP's resource setup, E1, F1-U, N3), a second session, UE- and
# network-requested release, a fresh UE's session, and the 5GSM back-off.
# Rows of gates/rows/p1.tsv whose milestone is N10, scored from kaluza-sim's own
# evidence. The network-requested release needs a network-side trigger: the
# stub's (STUB_CTL); on the real cores it waits for its grant (SKIP).
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza [STUB_CTL=<stub socket>] gates/verification/ksim-p1-session.sh
#   [DN_ADDR=<IPv4>]   the address pinged (default 10.60.0.1, the stub's DN)
#
# UE 3 is used, and UE 4 as the fresh UE (never registered in the run); both
# must be off at the start.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
: "${DN_ADDR:=10.60.0.1}"
UE=3

echo "-- registration (UE $UE)"
reg=$(ctl ue "$UE" power on --wait 30s)
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE $UE did not register: $(printf '%s\n' "$reg" | kv CAUSE)"
supi=$(printf '%s\n' "$reg" | kv UE)

echo "-- establishment: internet"
est=$(ctl ue "$UE" ps-establish ipv4 --dnn internet $SLICE --wait 15s)
row amf-ueransim.016 '^ACCEPT psi=[0-9]+ ip=[0-9.]+ qfi=[0-9]+$' \
    "$(printf '%s\n' "$est" | kv RESULT) psi=$(printf '%s\n' "$est" | kv PSI) ip=$(printf '%s\n' "$est" | kv IP) qfi=$(printf '%s\n' "$est" | kv QFI)"
psi1=$(printf '%s\n' "$est" | kv PSI)
list=$(ctl ue "$UE" ps-list)
row smf-ueransim.032 '^sessions=1 dnn=internet$' \
    "sessions=$(printf '%s\n' "$list" | kv PDU_SESSIONS) dnn=$(printf '%s\n' "$list" | kv "PS.$psi1.DNN")"

# The user plane: an inject-mode ping on the session (rows of its own come with
# the TUN data plane, N11); the stub's UPF counts the echoes it answered.
png=$(ctl ue "$UE" ping "$DN_ADDR" --psi "$psi1" -c 3 --interval 200)
echo "   ping $DN_ADDR: sent=$(printf '%s\n' "$png" | kv SENT) received=$(printf '%s\n' "$png" | kv RECEIVED) rtt_avg_ms=$(printf '%s\n' "$png" | kv RTT_AVG_MS)"

echo "-- a second session: ims"
est2=$(ctl ue "$UE" ps-establish ipv4 --dnn ims $SLICE --wait 15s)
psi2=$(printf '%s\n' "$est2" | kv PSI)
list=$(ctl ue "$UE" ps-list)
row amf-ueransim.044 '^sessions=2 dnns=internet,ims$' \
    "sessions=$(printf '%s\n' "$list" | kv PDU_SESSIONS) dnns=$(printf '%s\n' "$list" | kv "PS.$psi1.DNN"),$(printf '%s\n' "$list" | kv "PS.$psi2.DNN")"

echo "-- UE-requested release: ims"
seq=$(ctl info | kv EVENT_SEQ)
rel=$(ctl ue "$UE" ps-release "$psi2" --wait 15s)
cmd=$(ctl ue "$UE" wait nas.sm.rel.command --since "$seq" --where "psi=$psi2" --timeout 5s)
got="$(printf '%s\n' "$cmd" | kv EVENT) network=$(printf '%s\n' "$cmd" | kv NETWORK) released=$(printf '%s\n' "$rel" | kv RESULT)"
row amf-ueransim.060 '^nas.sm.rel.command network=0 released=ACCEPT$' "$got"
row smf-ueransim.023 '^nas.sm.rel.command network=0 released=ACCEPT$' "$got"

echo "-- network-requested release: internet"
if [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; then
    seq=$(ctl info | kv EVENT_SEQ)
    "$KSIM_CTL" --socket "$STUB_CTL" stub release --ue "$supi" --psi "$psi1" --cause 36 >/dev/null ||
        abort "the stub did not take the release trigger"
    ncmd=$(ctl ue "$UE" wait nas.sm.rel.command --since "$seq" --where "psi=$psi1" --timeout 10s)
    row smf-ueransim.034 '^nas.sm.rel.command network=1 cause=36$' \
        "$(printf '%s\n' "$ncmd" | kv EVENT) network=$(printf '%s\n' "$ncmd" | kv NETWORK) cause=$(printf '%s\n' "$ncmd" | kv CAUSE)"
    rrc=$(ctl wait ran.session.release --since "$seq" --where "psi=$psi1" --timeout 10s | kv EVENT)
    nas=$(ctl ue "$UE" wait nas.sm.release --since "$seq" --where "psi=$psi1" --timeout 10s | kv WHY)
    row smf-ueransim.036 '^rrc=ran.session.release nas=release command$' "rrc=$rrc nas=$nas"
else
    skip_row smf-ueransim.034 "no network-side release trigger on $CORE in P1"
    skip_row smf-ueransim.036 "no network-side release trigger on $CORE in P1"
    ctl ue "$UE" ps-release "$psi1" --wait 15s >/dev/null
fi

echo "-- the 5GSM back-off"
if [ "$CORE" = stub ]; then
    first=$(ctl ue "$UE" ps-establish ipv4 --dnn ksim-backoff $SLICE --wait 15s)
    bo=$(ctl ue "$UE" wait nas.sm.backoff --timeout 5s)
    ctl ue "$UE" ps-establish ipv4 --dnn ksim-backoff $SLICE >/dev/null 2>&1
    again=$?   # 6: refused while the timer runs
    secs=$(printf '%s\n' "$bo" | kv SECONDS)
    ctl ue "$UE" wait nas.sm.backoff.expiry --timeout "$((secs + 5))s" >/dev/null
    after=$(ctl ue "$UE" ps-establish ipv4 --dnn ksim-backoff $SLICE --wait 15s | kv RESULT)
    row ksim-p1.backoff '^reject=29 seconds=[1-9][0-9]* during=6 after=ACCEPT$' \
        "reject=$(printf '%s\n' "$first" | kv CAUSE) seconds=$secs during=$again after=$after"
else
    skip_row ksim-p1.backoff "needs a core-side #29 with a back-off timer (N17/N18 triage)"
fi

release_all "$UE"

ctl ue "$UE" power off --switch-off --wait 10s >/dev/null

echo "-- a fresh UE (UE 4)"
ctl ue 4 power on --wait 30s >/dev/null
est3=$(ctl ue 4 ps-establish ipv4 --dnn internet $SLICE --wait 15s)
list=$(ctl ue 4 ps-list)
row smf-ueransim.040 '^ACCEPT sessions=1$' \
    "$(printf '%s\n' "$est3" | kv RESULT) sessions=$(printf '%s\n' "$list" | kv PDU_SESSIONS)"
release_all 4
ctl ue 4 power off --switch-off --wait 10s >/dev/null

summary ksim-p1-session
