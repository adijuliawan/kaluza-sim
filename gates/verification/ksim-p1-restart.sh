#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P1 restart gate (P1 N12): the gNB restarted (ksim-ctl gnb restart) and
# the AMF restarted under the gNB. After the gNB's restart the UE recovers its
# NAS signalling connection with a mobility registration (TS 24.501 5.5.1.3.2 f)
# and a downlink ping still pages it; after the AMF's, the gNB re-associates
# (L11) and the UE carries on registered, with no new authentication. The AMF
# restart needs a core-side trigger: the stub's (STUB_CTL); on the real cores
# those rows SKIP until their runs (N17).
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza [STUB_CTL=<stub socket>] gates/verification/ksim-p1-restart.sh
#   [DN_ADDR=<IPv4>]     the address pinged (default 10.60.0.1, the stub's DN)
#   [DN_PING=<command>]  on a real core, a command that pings the address given as its argument from
#                        the DN host; without it the DN rows SKIP
#
# UE 9 is used; it must be off at the start. The gNB is left set up again.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
: "${DN_ADDR:=10.60.0.1}"
GNB=$(ctl info | kv GNB)
UE=9
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }

reg=$(ctl ue "$UE" power on --wait 30s)
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE $UE did not register"
supi=$(printf '%s\n' "$reg" | kv UE)
est=$(ctl ue "$UE" ps-establish ipv4 --dnn internet $SLICE --wait 15s)
psi=$(printf '%s\n' "$est" | kv PSI); ip=$(printf '%s\n' "$est" | kv IP)
[ -n "$psi" ] || abort "UE $UE has no session"

echo "-- the gNB restarted"
seq=$(ctl info | kv EVENT_SEQ)
ctl gnb "$GNB" restart >/dev/null || abort "gnb restart refused"
ng=$(ctl wait ran.ng.setup --since "$seq" --timeout 30s | kv EVENT)
row amf-ueransim.032 '^ran.ng.setup$' "$ng"
# The UE lost the cell (radio link failure) and recovers by a mobility registration
# that brings its session's user plane back (the Uplink data status).
ctl ue "$UE" wait nas.reg.accept --since "$seq" --where type=mobility --timeout 30s >/dev/null ||
    abort "UE $UE did not recover after the gNB restart"
ctl ue "$UE" wait rrc.reconfiguration.complete --since "$seq" --where added=drb1 --timeout 10s >/dev/null ||
    abort "UE $UE's user plane did not come back after the gNB restart"
if on_stub || [ -n "${DN_PING:-}" ]; then
    seq=$(ctl info | kv EVENT_SEQ)
    ctl gnb "$GNB" ue-release "$UE" >/dev/null || abort "gnb ue-release refused"
    ctl ue "$UE" wait nas.mm.cm_idle --since "$seq" --timeout 10s >/dev/null || abort "UE $UE not idle"
    ctl wait ran.ue.released --since "$seq" --timeout 10s >/dev/null
    seq=$(ctl info | kv EVENT_SEQ)
    rc=1
    if on_stub; then
        stub ping-ue --ue "$supi" --psi "$psi" --seq 1 >/dev/null || abort "the stub did not take ping-ue"
    else
        $DN_PING "$ip" >/dev/null 2>&1
        rc=$?   # netns mode: the UE's own stack answers; the DN side's replies are the evidence (N18)
    fi
    ans=$(ctl ue "$UE" wait ue.ping.answered --since "$seq" --timeout "$([ "$rc" = 0 ] && echo 1ms || echo 10s)" | kv EVENT)
    paged=$(ctl wait ran.ngap.paging --since "$seq" --timeout 1ms | kv EVENT)
    row amf-ueransim.033 '^answered=1$' "answered=$([ "$ans" = ue.ping.answered ] || [ "$rc" = 0 ] && echo 1 || echo 0)"
    row amf-ueransim.034 '^ran.ngap.paging$' "$paged"
else
    skip_row amf-ueransim.033 "no DN-side ping on $CORE (DN_PING)"
    skip_row amf-ueransim.034 "no DN-side ping on $CORE (DN_PING)"
fi

echo "-- the AMF restarted"
if on_stub; then
    seq=$(ctl info | kv EVENT_SEQ)
    stub restart >/dev/null || abort "the stub did not take restart"
    st=$(ctl wait ran.amf.status --since "$seq" --timeout 10s | kv EVENT)
    row amf-ueransim.063 '^ran.amf.status$' "$st"
    ng=$(ctl wait ran.ng.setup --since "$seq" --timeout 30s | kv EVENT)
    row amf-ueransim.064 '^ran.ng.setup$' "$ng"
    png=$(ctl ue "$UE" ping "$DN_ADDR" --psi "$psi" -c 3 --interval 300)
    ctl ue "$UE" wait nas.reg.request --since "$seq" --timeout 1ms >/dev/null 2>&1
    rereg=$?   # 3: none since the restart
    ctl ue "$UE" wait nas.auth.response --since "$seq" --timeout 1ms >/dev/null 2>&1
    auth=$?
    sr=$(ctl ue "$UE" wait nas.sr.accept --since "$seq" --timeout 1ms | kv EVENT)
    row amf-ueransim.065 '^registration_request=none then=nas.sr.accept$' \
        "registration_request=$([ "$rereg" -eq 3 ] && echo none || echo found) then=$sr"
    row amf-ueransim.066 '^authentication=none$' "authentication=$([ "$auth" -eq 3 ] && echo none || echo found)"
    row amf-ueransim.069 '^received=[1-9]' "received=$(printf '%s\n' "$png" | kv RECEIVED)"
else
    for r in amf-ueransim.063 amf-ueransim.064 amf-ueransim.065 amf-ueransim.066 amf-ueransim.069; do
        skip_row "$r" "no AMF restart trigger on $CORE in this run (Open5GS: N17)"
    done
fi
release_all "$UE"
ctl ue "$UE" power off --switch-off --wait 10s >/dev/null

summary ksim-p1-restart
