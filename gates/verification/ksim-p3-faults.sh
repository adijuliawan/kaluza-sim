#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The fault gate (P3 R3; ADR 0013 point 9; architecture.md section 9): fault injection is off
# until a rule is set, every rule is recorded with the row it serves, and what it does is seen.
# Rows of gates/rows/p3.tsv whose milestone is R3, aio and split:
#   ksim-p3.faults.zero       a run with no fault set prints FAULTS=0 and records none
#   ksim-p3.faults.msg-drop   n3.dl msg=G-PDU drop x2: a 5-ping run loses 2 replies, 2 hits are
#                             evented, the rule is spent and its record says so
#   ksim-p3.faults.link-loss  a UE's air link: 40 ms each way adds 80 ms (75..149) to a ping's round trip;
#                             30 % loss loses no ping (RLC AM retransmits); every UL frame lost is
#                             RLC AM's max retransmissions, the UE's radio link failure, the DU no
#                             longer hears it and the network releases it; with the link back the
#                             UE recovers (KS-L2R-001)
#   ksim-p3.faults.ue-rlf     ue rlf: the UE loses the radio link at once (KS-L2R-005); it recovers
#                             its NAS signalling connection with a mobility registration (TS
#                             24.501 5.5.1.3.2 f) and the network releases the old context
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p3-faults.sh
#   [DN_ADDR=<IPv4>]   the address pinged (default 10.60.0.1, the stub's DN)
#
# UEs 1 and 2; they must be off at the start.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

: "${DN_ADDR:=10.60.0.1}"

echo "-- no fault set"
n=$(ctl faults list | kv FAULTS)
rec=$(find "$RUN" -name faults.tsv -exec cat {} + 2>/dev/null | grep -c '^set' || true)
row ksim-p3.faults.zero '^faults=0 recorded=0$' "faults=${n:-?} recorded=$rec"
[ "${n:-1}" = 0 ] || abort "the run has faults set"

up_with_session() {
    ctl ue "$1" power on --wait 30s >/dev/null || abort "UE $1 did not register"
    _psi=$(ctl ue "$1" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
    [ -n "$_psi" ] || abort "UE $1 got no session"
    echo "$_psi"
}
# ping_of UE PSI COUNT: the ping's received count and average round trip (ms)
ping_of() {
    _p=$(ctl ue "$1" ping "$DN_ADDR" --psi "$2" -c "$3" --interval 200)
    echo "$(printf '%s\n' "$_p" | kv RECEIVED) $(printf '%s\n' "$_p" | kv RTT_AVG_MS)"
}

echo "-- a message rule (UE 1)"
psi=$(up_with_session 1)
seq=$(ctl info | kv EVENT_SEQ)
id=$(ctl faults set "n3.dl msg=G-PDU drop x2" --row ksim-p3.faults.msg-drop | kv FAULT_ID)
[ -n "$id" ] || abort "the rule was refused"
set -- $(ping_of 1 "$psi" 5)
hits=$(ctl events --since "$seq" | grep -c '"fault.hit"' || true)
left=$(ctl faults list | kv FAULTS)
recd=$(find "$RUN" -name faults.tsv -exec cat {} + 2>/dev/null |
    awk -F '\t' -v id="$id" '$2 == id && $3 == "ksim-p3.faults.msg-drop" { printf "%s%s", s, $1; s = "," }')
row ksim-p3.faults.msg-drop '^received=3/5 hits=2 faults=0 recorded=set,spent$' \
    "received=$1/5 hits=$hits faults=$left recorded=$recd"

echo "-- the air link (UE 1)"
set -- $(ping_of 1 "$psi" 3)
base=${2:-0}
a=$(ctl faults set "uu.any ue=1 delay=40 x*" --row ksim-p3.faults.link-loss | kv FAULT_ID)
set -- $(ping_of 1 "$psi" 3)
delayed=${2:-0}
ctl faults clear "$a" >/dev/null
b=$(ctl faults set "uu.any ue=1 drop x* pct=30" --row ksim-p3.faults.link-loss | kv FAULT_ID)
set -- $(ping_of 1 "$psi" 5)
lossy=$1
ctl faults clear "$b" >/dev/null
seq=$(ctl info | kv EVENT_SEQ)
c=$(ctl faults set "uu.ul ue=1 drop x*" --row ksim-p3.faults.link-loss | kv FAULT_ID)
ctl ue 1 ping "$DN_ADDR" --psi "$psi" -c 1 >/dev/null 2>&1
lost=$(ctl ue 1 wait rrc.connection_lost --since "$seq" --timeout 5s | kv REASON)
du=$(ctl wait ran.du.rlf --since "$seq" --timeout 5s | kv REASON)
rel=$(ctl wait ran.ue.released --since "$seq" --timeout 10s | kv EVENT)
ctl faults clear "$c" >/dev/null
back=$(ctl ue 1 wait nas.reg.complete --since "$seq" --timeout 30s | kv EVENT)
added=$(awk -v d="$delayed" -v b="$base" 'BEGIN { printf "%.0f", d - b }')
row ksim-p3.faults.link-loss \
    '^added_ms=(7[5-9]|8[0-9]|9[0-9]|1[0-4][0-9]) lossy=5/5 rlf=rlc-max-retransmissions du=no-uplink released=ran.ue.released back=nas.reg.complete$' \
    "added_ms=$added lossy=$lossy/5 rlf=$(printf '%s' "$lost" | tr ' ' '-') du=$(printf '%s' "$du" | tr ' ' '-') released=$rel back=$back"
release_all 1
ctl ue 1 power off --switch-off --wait 10s >/dev/null 2>&1

echo "-- a sudden radio link failure (UE 2)"
ctl ue 2 power on --wait 30s >/dev/null || abort "UE 2 did not register"
seq=$(ctl info | kv EVENT_SEQ)
ctl ue 2 rlf >/dev/null || abort "ue rlf was refused"
lost=$(ctl ue 2 wait rrc.connection_lost --since "$seq" --timeout 2s | kv REASON)
rec=$(ctl ue 2 wait nas.reg.request --since "$seq" --timeout 5s | kv TYPE)
back=$(ctl ue 2 wait nas.reg.complete --since "$seq" --timeout 15s | kv EVENT)
rel=$(ctl wait ran.ue.released --since "$seq" --timeout 10s | kv EVENT)
row ksim-p3.faults.ue-rlf '^ue=radio-link-failure recovery=mobility back=nas.reg.complete released=ran.ue.released$' \
    "ue=$(printf '%s' "$lost" | tr ' ' '-') recovery=$rec back=$back released=$rel"
ctl ue 2 power off --switch-off --wait 10s >/dev/null 2>&1

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the gate left a fault set"
summary "ksim-p3-faults"
