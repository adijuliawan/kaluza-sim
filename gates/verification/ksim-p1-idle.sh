#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P1 idle gate (P1 N12): CM-IDLE after a RAN release, the service request
# for uplink data, paging for downlink data, the periodic registration, the
# 5G-GUTI kept on the USIM across a power cycle, radio loss, a session asked
# for again after an abrupt power cycle, and network de-registration with
# re-registration. Rows of gates/rows/p1.tsv whose milestone is N12 (the
# restart rows are ksim-p1-restart.sh's).
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza [STUB_CTL=<stub socket>] gates/verification/ksim-p1-idle.sh
#   [DN_ADDR=<IPv4>]     the address pinged (default 10.60.0.1, the stub's DN)
#   [T3512_S=<s>]        the T3512 the core gives (default 3600: the stub's, the bundles' subsRegTimer)
#   [DN_PING=<command>]  on a real core, a command that pings the address given as its argument from
#                        the DN host (kaluza-core: 172.30.61.1); without it the DN rows SKIP
#
# UEs 6, 7 and 8 are used; all must be off at the start.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

command -v tshark >/dev/null 2>&1 || abort "tshark is needed for the pcap rows"
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
: "${DN_ADDR:=10.60.0.1}"
: "${T3512_S:=3600}"
GNB=$(ctl info | kv GNB)
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }

# release UE: the gNB releases the UE (user inactivity); the UE's nas.mm.cm_idle event is printed.
release() {
    _seq=$(ctl info | kv EVENT_SEQ)
    ctl gnb "$GNB" ue-release "$1" >/dev/null || abort "gnb ue-release $1 refused"
    ctl ue "$1" wait nas.mm.cm_idle --since "$_seq" --timeout 10s
    ctl wait ran.ue.released --since "$_seq" --timeout 10s >/dev/null
}

# dn_ping UE SUPI PSI IP: a ping from the DN to the UE; prints answered=<0|1>.
dn_ping() {
    _seq=$(ctl info | kv EVENT_SEQ)
    if on_stub; then
        stub ping-ue --ue "$2" --psi "$3" --seq 1 >/dev/null || abort "the stub did not take ping-ue"
    else
        $DN_PING "$4" >/dev/null 2>&1
    fi
    _ans=$(ctl ue "$1" wait ue.ping.answered --since "$_seq" --timeout 10s | kv EVENT)
    echo "answered=$([ "$_ans" = ue.ping.answered ] && echo 1 || echo 0)"
}

echo "-- CM-IDLE after a RAN release (UE 6)"
reg=$(ctl ue 6 power on --wait 30s)
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE 6 did not register"
supi=$(printf '%s\n' "$reg" | kv UE)
est=$(ctl ue 6 ps-establish ipv4 --dnn internet --sst 1 --wait 15s)
psi=$(printf '%s\n' "$est" | kv PSI); ip=$(printf '%s\n' "$est" | kv IP)
[ -n "$psi" ] || abort "UE 6 has no session"
seq=$(ctl info | kv EVENT_SEQ)
idle=$(release 6)
t3512=$(ctl ue 6 wait nas.mm.t3512 --since "$seq" --timeout 5s | kv SECONDS)
cause=$(ctl wait ran.ue.release_request --since "$seq" --timeout 5s | kv CAUSE)
got="$(printf '%s\n' "$idle" | kv EVENT) cause=$cause"
row amf-ueransim.023 '^nas.mm.cm_idle cause=user-inactivity$' "$got"
row smf-ueransim.041 '^nas.mm.cm_idle cause=user-inactivity$' "$got"
row amf-ueransim.024 "^t3512=$T3512_S\$" "t3512=$t3512"

echo "-- an uplink ping from idle"
seq=$(ctl info | kv EVENT_SEQ)
png=$(ctl ue 6 ping "$DN_ADDR" --psi "$psi" -c 3 --interval 300)
sr=$(ctl ue 6 wait nas.sr.accept --since "$seq" --timeout 5s)
row amf-ueransim.025 '^nas.sr.accept pending_uplink=1 received=[1-9]' \
    "$(printf '%s\n' "$sr" | kv EVENT) pending_uplink=$(printf '%s\n' "$sr" | kv PENDING_UPLINK) received=$(printf '%s\n' "$png" | kv RECEIVED)"

echo "-- a downlink ping to the idle UE"
release 6 >/dev/null
if on_stub || [ -n "${DN_PING:-}" ]; then
    seq=$(ctl info | kv EVENT_SEQ)
    ans=$(dn_ping 6 "$supi" "$psi" "$ip")
    paged=$(ctl wait ran.ngap.paging --since "$seq" --timeout 5s | kv EVENT)
    sreq=$(ctl ue 6 wait nas.sr.request --since "$seq" --timeout 5s | kv TYPE)
    row amf-ueransim.027 '^answered=1 service_type=2$' "$ans service_type=$sreq"
    row amf-ueransim.028 '^answered=[1-9]' "$ans"
    row amf-ueransim.029 '^ran.ngap.paging$' "$paged"
else
    for r in amf-ueransim.027 amf-ueransim.028 amf-ueransim.029; do
        skip_row "$r" "no DN-side ping on $CORE (DN_PING)"
    done
fi
release_all 6
ctl ue 6 power off --switch-off --wait 10s >/dev/null

echo "-- the periodic registration and the 5G-GUTI across a power cycle (UE 7)"
reg=$(ctl ue 7 power on --wait 30s)
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE 7 did not register"
supi=$(printf '%s\n' "$reg" | kv UE)
ctl ue 7 ps-establish ipv4 --dnn internet --sst 1 --wait 15s >/dev/null
if on_stub; then
    stub t3512 --seconds 8 >/dev/null || abort "the stub did not take t3512"
fi
seq=$(ctl info | kv EVENT_SEQ)
release_all 7
ctl ue 7 power off --switch-off --wait 10s >/dev/null
ctl ue 7 power on --wait 30s | grep -q '^RESULT=ACCEPT$' || abort "UE 7 did not register again"
req=$(ctl ue 7 wait nas.reg.request --since "$seq" --timeout 5s)
# The REGISTRATION REQUEST after the power cycle in the Uu capture: integrity
# protected (security header type 1), with the 5G-GUTI (identity type 2).
mine="frame.comment contains \"$supi\""
wire=$(tshark_fields "$RUN/uu.pcapng" \
    "nas-5gs.mm.message_type == 0x41 && nas-5gs.mm.5gs_reg_type == 1 && nas-5gs.security_header_type == 1 && $mine" \
    nas-5gs.security_header_type nas-5gs.mm.type_id | tail -n 1)
sht=$(printf '%s' "$wire" | cut -f1 | cut -d, -f1); tid=$(printf '%s' "$wire" | cut -f2 | cut -d, -f1)
row ksim-p1.guti-after-power-cycle '^identity=5g-guti protected=integrity wire=sht1,id2$' \
    "identity=$(printf '%s\n' "$req" | kv IDENTITY) protected=$(printf '%s\n' "$req" | kv PROTECTED) wire=sht$sht,id$tid"
if on_stub; then
    est=$(ctl ue 7 ps-establish ipv4 --dnn internet --sst 1 --wait 15s)
    psi=$(printf '%s\n' "$est" | kv PSI)
    seq=$(ctl info | kv EVENT_SEQ)
    release 7 >/dev/null
    t3512=$(ctl ue 7 wait nas.mm.t3512 --since "$seq" --timeout 5s | kv SECONDS)
    row amf-ueransim.036 '^t3512=8$' "t3512=$t3512"
    preq=$(ctl ue 7 wait nas.reg.request --since "$seq" --where type=periodic --timeout 20s)
    pseq=$(printf '%s\n' "$preq" | kv SEQ)
    acc=$(ctl ue 7 wait nas.reg.accept --since "$seq" --where type=periodic --timeout 10s | kv TYPE)
    row amf-ueransim.037 '^accept=periodic$' "accept=$acc"
    ctl ue 7 wait nas.auth.response --since "${pseq:-$seq}" --timeout 1ms >/dev/null 2>&1
    auth=$?   # 3: none since the periodic request
    row amf-ueransim.038 '^authentication=none$' "authentication=$([ "$auth" -eq 3 ] && echo none || echo found)"
    png=$(ctl ue 7 ping "$DN_ADDR" --psi "$psi" -c 2 --interval 300)
    row amf-ueransim.039 '^received=[1-9]' "received=$(printf '%s\n' "$png" | kv RECEIVED)"
    stub t3512 --seconds "$T3512_S" >/dev/null
else
    skip_row amf-ueransim.036 "needs a subscription change on $CORE (no trigger grant in P1)"
    for r in amf-ueransim.037 amf-ueransim.038 amf-ueransim.039; do
        skip_row "$r" "needs the short subsRegTimer sub-block's UE on $CORE (N17/N18)"
    done
fi
release_all 7
ctl ue 7 power off --switch-off --wait 10s >/dev/null

echo "-- radio loss and a session asked for again (UE 8)"
reg=$(ctl ue 8 power on --wait 30s)
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE 8 did not register"
supi=$(printf '%s\n' "$reg" | kv UE)
ctl ue 8 ps-establish ipv4 --dnn internet --sst 1 --wait 15s | grep -q '^PSI=1$' || abort "UE 8's first session is not PSI 1"
ctl ue 8 ps-establish ipv4 --dnn ims --sst 1 --wait 15s >/dev/null
seq=$(ctl info | kv EVENT_SEQ)
ctl ue 8 power off --abrupt >/dev/null
rr=$(ctl wait ran.ue.release_request --since "$seq" --timeout 10s)
ctl wait ran.ue.released --since "$seq" --timeout 10s >/dev/null
rlf=$(ctl wait ran.du.rlf --since "$seq" --timeout 1ms | kv EVENT)
row ksim-p1.radio-loss-release '^ran.du.rlf cause=radio-connection-with-ue-lost$' \
    "$rlf cause=$(printf '%s\n' "$rr" | kv CAUSE)"
ctl ue 8 power on --wait 30s | grep -q '^RESULT=ACCEPT$' || abort "UE 8 did not register again"
est=$(ctl ue 8 ps-establish ipv4 --dnn internet --sst 1 --wait 15s)
row amf-ueransim.047 '^ACCEPT psi=1$' "$(printf '%s\n' "$est" | kv RESULT) psi=$(printf '%s\n' "$est" | kv PSI)"
t0=$(date +%s)
ims=$(ctl ue 8 ps-establish ipv4 --dnn ims --sst 1 --wait 30s | kv RESULT)
el=$(($(date +%s) - t0))
row amf-ueransim.049 '^ACCEPT within=yes ' "$ims within=$([ "$el" -lt 10 ] && echo yes || echo no) (${el}s; T3580 16 s)"

echo "-- network de-registration, re-registration required"
if on_stub; then
    seq=$(ctl info | kv EVENT_SEQ)
    stub deregister --ue "$supi" --rereg >/dev/null || abort "the stub did not take deregister"
    dn=$(ctl ue 8 wait nas.dereg.network --since "$seq" --timeout 10s)
    rc=$(ctl ue 8 wait nas.reg.complete --since "$(printf '%s\n' "$dn" | kv SEQ)" --timeout 20s | kv EVENT)
    row ksim-p1.reregistration-required '^reregistration=1 then=nas.reg.complete$' \
        "reregistration=$(printf '%s\n' "$dn" | kv REREGISTRATION) then=$rc"
else
    skip_row ksim-p1.reregistration-required "no network-side de-registration trigger on $CORE in P1"
fi
release_all 8
ctl ue 8 power off --switch-off --wait 10s >/dev/null

summary ksim-p1-idle
