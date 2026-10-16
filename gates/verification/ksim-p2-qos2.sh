#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The QoS gate, part II (P2 Q11; TS 24.501 6.2.5.1.4, TS 37.324 5.3, TS 38.413 8.2.1, 8.2.4).
# Rows of gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q11:
#   ksim-p2.rqos-capability     the UE offers reflective QoS in its 5GSM capability
#   ksim-p2.rqos-derived-rule   a DL packet with an RQI derives a QoS rule; the reply rides its QFI
#   ksim-p2.rqos-timer          the derived rule goes when T3583 (the RQ timer) expires
#   ksim-p2.unknown-qfi         a DL packet on a QFI the UE was never told of is discarded and counted
#   ksim-p2.sdap-end-marker     a flow moved to another DRB leaves an end-marker on the old one
#   ksim-p2.gbr-setup           a GBR flow is admitted with its rates and gets a DRB of its own
#   ksim-p2.gbr-refused         a GBR flow over the cell's budget is refused with the TS 38.413 cause
#   ksim-p2.gbr-notify          notification control: not fulfilled, then fulfilled again
# The stub's UPF sends the UDP datagrams (ksim-ctl stub udp-ue, to the UE's echo port), with an
# RQI and a QFI where a row needs them, and checks the replies' QFIs itself; its SMF sends the
# flows and the RQ timer (stub qos). The cell's GBR budget is set for the GBR rows (gnb
# gbr-budget) and put back. On kaluza-core only the capability row runs.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p2-qos2.sh
#
# UE QOS2_UE (default 7). On open5gs, QOS2_PCC_GBR=1 when the rig provisioned its GBR PCC rule (Q13).

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
GNB=$(ctl info | kv GNB)
: "${QOS2_UE:=7}"
u=$QOS2_UE
DN=${DN_ADDR:-10.60.0.1}
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }

off() {
    release_all "$u"
    ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1
    ctl ue "$u" power off --abrupt >/dev/null 2>&1
}
up() {
    psi=""
    ctl ue "$u" power on --wait 30s >/dev/null || return 0
    psi=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
}
num() { _v=$(cat); echo "${_v:-0}"; }
ps() { ctl ue "$u" ps-list | kv "PS.$psi.$1"; }
stub_kv() { stub | kv "$1" | num; }
pings() { ctl ue "$u" ping "$1" --psi "$psi" -c 3 --interval 200 | kv RECEIVED; }
udp() { stub udp-ue --ue "$supi" --psi "${psi:-1}" "$@" >/dev/null; }
STUB_FAILS=0
on_stub && STUB_FAILS=$(stub_kv FAILURES)
new_failures() { if on_stub; then echo $(( $(stub_kv FAILURES) - STUB_FAILS )); else echo 0; fi; }

echo "-- reflective QoS in the 5GSM capability (UE $u)"
off
seq=$(ctl info | kv EVENT_SEQ)
rq0=0
on_stub && rq0=$(stub_kv SM_RQOS)
up
rqos=$(ctl wait nas.sm.est.request --since "$seq" --timeout 5s | kv RQOS)
smf=1
on_stub && smf=$(( $(stub_kv SM_RQOS) - rq0 ))
row ksim-p2.rqos-capability '^rqos=1 smf_saw=1 session=[0-9]+$' "rqos=${rqos:-none} smf_saw=$smf session=${psi:-none}"
off

if ! on_stub; then
    for id in ksim-p2.rqos-derived-rule ksim-p2.rqos-timer ksim-p2.unknown-qfi ksim-p2.sdap-end-marker \
              ksim-p2.gbr-refused ksim-p2.gbr-notify; do
        skip_row "$id" "the RQI, the QFIs and the GBR flows are the core's ($CORE): only the stub's are set by a row"
    done
    if [ "$CORE" = open5gs ] && [ "${QOS2_PCC_GBR:-0}" = 1 ]; then
        # P2 Q13 (D2): the rig's UE $u has a GBR PCC rule (ksim-sim range provision --pcc-gbr 1000:
        # 5QI 1, GFBR 1000 kbit/s each way, ICMP with the DN reflector), and the fork's PCF and SMF
        # add its GBR flow to the session, by a modification after the establishment.
        echo "-- the core's GBR flow (UE $u, the rig's PCC rule)"
        up
        qos=""; drb=""; _t=0
        while [ -n "$psi" ] && [ -z "$drb" ] && [ "$_t" -lt 20 ]; do
            qos=$(ctl gnb "$GNB" qos "$u")
            drb=$(printf '%s\n' "$qos" | sed -n "s/^PS\.$psi\.DRB\.\([0-9]*\)\.GFBR=.*/\1/p" | head -n 1)
            [ -n "$drb" ] || sleep 0.5
            _t=$((_t + 1))
        done
        q=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.${drb:-0}.QFIS")
        gfbr=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.${drb:-0}.GFBR")
        c=$(ctl ue "$u" status | kv C_RNTI)
        du=$(ctl du "$GNB-du" ue-list | sed -n "s/^UE\.$c\.DRB\.${drb:-0}\.GFBR=//p")
        cuup=$(ctl cuup "$GNB-cuup" bearers | sed -n "s/^DRB\.[0-9]*\.$psi\.${drb:-0}\.GFBR=//p" | head -n 1)
        rx=0
        [ -n "$psi" ] && rx=$(pings "$DN")
        got="drb=${drb:-none} qfis=${q:-none} gfbr=${gfbr:-none} du=${du:-none} cuup=${cuup:-none}"
        got="$got ue_qfi=$(ps "UL_QFI.${q:-0}" | num) received=${rx:-0}"
        row ksim-p2.gbr-setup '^drb=[0-9]+ qfis=[0-9]+ gfbr=1000000/1000000 du=1000000/1000000 cuup=1000000/1000000 ue_qfi=([3-9]|[1-9][0-9]+) received=3$' "$got"
        off
    elif [ "$CORE" = open5gs ]; then
        skip_row ksim-p2.gbr-setup "the rig's UE $u has no GBR PCC rule (provision it with --pcc-gbr 1000, then QOS2_PCC_GBR=1)"
    else
        skip_row ksim-p2.gbr-setup "no GBR flow on $CORE without an IMS UA or a core PCC rule (D2)"
    fi
    summary "ksim-p2-qos2"
    exit 0
fi
stub qos flows-clear >/dev/null
N='([1-9][0-9]*)'

echo "-- an RQI on QFI 2 from 10.60.0.9:40001 (UE $u)"
stub qos rq-timer --seconds 60 >/dev/null
up
supi=$(ctl ue "$u" status | kv UE)
seq=$(ctl info | kv EVENT_SEQ)
from=$(stub_kv UPF_UDP_FROM_UE); upf2=$(stub_kv UPF_UL_QFI.2)
udp --src 10.60.0.9 --sport 40001 --qfi 2 --rqi
derived=$(ctl wait ue.qos.derived --since "$seq" --timeout 5s | kv QFI)
ctl wait ue.udp.echoed --since "$seq" --timeout 5s >/dev/null
got="derived=${derived:-none} rules=$(ps DERIVED) ue_qfi2=$(ps UL_QFI.2 | num) upf_qfi2=$(( $(stub_kv UPF_UL_QFI.2) - upf2 ))"
got="$got replies=$(( $(stub_kv UPF_UDP_FROM_UE) - from )) new_failures=$(new_failures)"
row ksim-p2.rqos-derived-rule '^derived=2 rules=1 ue_qfi2=1 upf_qfi2=1 replies=1 new_failures=0$' "$got"

echo "-- a datagram on QFI 9, which the UE was never told of (UE $u)"
seq=$(ctl info | kv EVENT_SEQ)
from=$(stub_kv UPF_UDP_FROM_UE)
udp --src 10.60.0.5 --sport 40002 --qfi 9
told=$(ctl wait ue.sdap.unknown_qfi --since "$seq" --timeout 5s | kv QFI)
sleep 1
got="told=${told:-none} discarded=$(ps DL_UNKNOWN_QFI) replies=$(( $(stub_kv UPF_UDP_FROM_UE) - from ))"
row ksim-p2.unknown-qfi '^told=9 discarded=1 replies=0$' "$got"
off

echo "-- T3583 at 4 s (UE $u)"
stub qos rq-timer --seconds 4 >/dev/null
up
seq=$(ctl info | kv EVENT_SEQ)
udp --src 10.60.0.9 --sport 40003 --qfi 2 --rqi
ctl wait ue.qos.derived --since "$seq" --timeout 5s >/dev/null
timer=$(ps RQ_TIMER_MS)
expired=$(ctl wait ue.qos.derived_expired --since "$seq" --timeout 10s | kv QFI)
row ksim-p2.rqos-timer '^timer=4000 expired=2 rules=0$' "timer=$timer expired=${expired:-none} rules=$(ps DERIVED)"
off
stub qos rq-timer --seconds 60 >/dev/null

echo "-- QFI 2 and 3 share DRB 2 (5QI 7); a modify gives QFI 2 5QI 9 (UE $u)"
stub qos flows-add --qfi 2 --5qi 7 --precedence 10 --filter remote=10.60.0.9/32 >/dev/null
stub qos flows-add --qfi 3 --5qi 7 --precedence 11 --filter remote=10.60.0.8/32 >/dev/null
up
supi=$(ctl ue "$u" status | kv UE)
[ -n "$psi" ] && pings 10.60.0.9 >/dev/null   # QFI 2's packets on DRB 2
seq=$(ctl info | kv EVENT_SEQ)
stub qos mod --ue "$supi" --psi "${psi:-1}" --qfi 2 --5qi 9 >/dev/null || abort "the stub sent no modification"
marker=$(ctl wait ran.cuup.end_marker --since "$seq" --where qfi=2 --timeout 10s)
ue_marker=$(ctl wait rrc.sdap.end_marker --since "$seq" --where qfi=2 --timeout 5s | kv DRB)
qos=$(ctl gnb "$GNB" qos "$u")
got="cuup_drb=$(printf '%s\n' "$marker" | kv DRB) ue_drb=${ue_marker:-none} drb1=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.1.QFIS")"
got="$got drb2=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.2.QFIS") received=$(pings 10.60.0.9)"
row ksim-p2.sdap-end-marker '^cuup_drb=2 ue_drb=2 drb1=1,2 drb2=3 received=3$' "$got"
off
stub qos flows-clear >/dev/null

echo "-- a GBR flow (QFI 2, 5QI 1, GFBR 1000 kbit/s both ways) (UE $u)"
stub qos flows-add --qfi 2 --5qi 1 --precedence 10 --filter remote=10.60.0.9/32 --gfbr 1000 --mfbr 2000 >/dev/null
up
qos=$(ctl gnb "$GNB" qos "$u")
c=$(ctl ue "$u" status | kv C_RNTI)
du=$(ctl du "$GNB-du" ue-list | sed -n "s/^UE\.$c\.DRB\.2\.GFBR=//p")
cuup=$(ctl cuup "$GNB-cuup" bearers | sed -n "s/^DRB\.[0-9]*\.$psi\.2\.GFBR=//p" | head -n 1)
r9=0
[ -n "$psi" ] && r9=$(pings 10.60.0.9)
got="drbs=$(printf '%s\n' "$qos" | kv "PS.$psi.DRBS") drb2=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.2.QFIS")"
got="$got gfbr=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.2.GFBR") du=${du:-none} cuup=${cuup:-none} ue_qfi2=$(ps UL_QFI.2 | num) received=$r9"
row ksim-p2.gbr-setup "^drbs=1,2 drb2=2 gfbr=1000000/1000000 du=1000000/1000000 cuup=1000000/1000000 ue_qfi2=3 received=3\$" "$got"
off

echo "-- the same flow with the cell's budget at 1000 kbit/s (UE $u)"
ctl gnb "$GNB" gbr-budget 1000 >/dev/null || abort "the CU-CP took no gbr-budget"
refused0=$(stub_kv SETUPS_WITH_REFUSED_FLOWS)
seq=$(ctl info | kv EVENT_SEQ)
up
cause=$(tshark_fields "$RUN/ngap.pcapng" "ngap.qosFlowFailedToSetupList" ngap.radioNetwork | tail -n 1)
refused=$(ctl wait ran.gbr.refused --since "$seq" --timeout 5s | kv QFI)
sleep 1
got="refused=${refused:-none} stub=$(( $(stub_kv SETUPS_WITH_REFUSED_FLOWS) - refused0 )) cause=${cause:-none}"
got="$got drbs=$(ctl gnb "$GNB" qos "$u" | kv "PS.$psi.DRBS") rules=$(ps RULES)"
# cause: tshark's index of the radioNetwork cause, 22 radio-resources-not-available (TS 38.413 9.3.1.2)
row ksim-p2.gbr-refused '^refused=2 stub=1 cause=22 drbs=1 rules=1$' "$got"
off
ctl gnb "$GNB" gbr-budget 100000 >/dev/null

echo "-- notification control: the budget at 1000 kbit/s, then back (UE $u)"
stub qos flows-clear >/dev/null
stub qos flows-add --qfi 2 --5qi 1 --precedence 10 --filter remote=10.60.0.9/32 --gfbr 1000 --mfbr 2000 --notify >/dev/null
up
nf0=$(stub_kv NOTIFY_NOT_FULFILLED); f0=$(stub_kv NOTIFY_FULFILLED)
seq=$(ctl info | kv EVENT_SEQ)
ctl gnb "$GNB" gbr-budget 1000 >/dev/null
ctl wait ran.gbr.fulfilment --since "$seq" --where fulfilled=0 --timeout 5s >/dev/null
sleep 1
nf=$(( $(stub_kv NOTIFY_NOT_FULFILLED) - nf0 ))
held=$(ctl gnb "$GNB" qos "$u" | kv "PS.$psi.DRB.2.NOT_FULFILLED")
seq=$(ctl info | kv EVENT_SEQ)
ctl gnb "$GNB" gbr-budget 100000 >/dev/null
ctl wait ran.gbr.fulfilment --since "$seq" --where fulfilled=1 --timeout 5s >/dev/null
sleep 1
got="not_fulfilled=$nf held=${held:-none} fulfilled=$(( $(stub_kv NOTIFY_FULFILLED) - f0 ))"
got="$got after=$(ctl gnb "$GNB" qos "$u" | kv "PS.$psi.DRB.2.NOT_FULFILLED")"
row ksim-p2.gbr-notify '^not_fulfilled=1 held=2 fulfilled=1 after=-$' "$got"
off
stub qos flows-clear >/dev/null

summary "ksim-p2-qos2"
