#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The QoS gate, part I (P2 Q10; TS 24.501 6.2.5.1.1.2, 9.11.4.13; TS 23.501 5.7.1.5; TS 38.413
# 8.2.3). Rows of gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q10:
#   ksim-p2.core-default-rule          the core's default QoS rule alone: every UL packet on its QFI
#   ksim-p2.ul-classifier              a UL packet a QoS rule's filter matches goes on that rule's QFI
#   ksim-p2.multi-drb                  two QoS flows (two 5QIs) on two DRBs, each with its traffic
#   ksim-p2.ul-classifier-precedence   of two matching rules, the lower precedence value wins
#   ksim-p2.modify-add-flow            a modify adding a flow reconfigures E1, F1 and the UE; the
#                                      flow carries traffic on its own DRB
#   ksim-p2.modify-release-flow        a modify releasing it removes it at the UE, CU-UP and DU
# The QFIs are read at three points: the UE's classifier (ksim-ctl ue ps-list), the CU-UP's DRBs
# (cuup bearers) and, on the stub, the UPF, which classifies every UL packet with the session's
# rules itself and records a failure when the QFI differs. The stub's SMF sends the flows each
# row needs (ksim-ctl stub qos); on a real core only the first row runs. The stub's profile is
# put back and every session released and the UE switched off at the end.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p2-qos.sh
#
# UE QOS_UE (default 6); the DN reflector DN_ADDR (10.60.0.1); the further addresses the
# stub's UPF answers too: 10.60.0.5, 10.60.0.7, 10.60.0.9.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
GNB=$(ctl info | kv GNB)
: "${QOS_UE:=6}"
u=$QOS_UE
DN=${DN_ADDR:-10.60.0.1}
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }

off() {
    release_all "$u"
    ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1
    ctl ue "$u" power off --abrupt >/dev/null 2>&1
}
# up: registers the UE and sets an internet session up; sets psi (empty on failure).
up() {
    psi=""
    ctl ue "$u" power on --wait 30s >/dev/null || return 0
    psi=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
}
pings() { ctl ue "$u" ping "$1" --psi "$psi" -c 3 --interval 200 | kv RECEIVED; }
ps() { ctl ue "$u" ps-list | kv "PS.$psi.$1"; }
num() { _v=$(cat); echo "${_v:-0}"; }
# The CU-UP's packets on DRB $1 of the session (any CU-UP UE ID: one UE has sessions now).
cuup_ul() { ctl cuup "$GNB-cuup" bearers | sed -n "s/^DRB\.[0-9]*\.$psi\.$1\.UL_PACKETS=//p" | sort -n | tail -n 1 | num; }
cuup_has() { ctl cuup "$GNB-cuup" bearers | grep -c "^DRB\.[0-9]*\.$psi\.$1\.QFIS="; }
du_qfis() {
    _c=$(ctl ue "$u" status | kv C_RNTI)
    ctl du "$GNB-du" ue-list | sed -n "s/^UE\.$_c\.DRB\.$1\.QFIS=//p"
}
stub_kv() { stub | kv "$1" | num; }
STUB_FAILS=0
on_stub && STUB_FAILS=$(stub_kv FAILURES)
new_failures() { if on_stub; then echo $(( $(stub_kv FAILURES) - STUB_FAILS )); else echo 0; fi; }

echo "-- the core's default QoS rule alone (UE $u)"
on_stub && stub qos flows-clear >/dev/null
off
up
rx=0
[ -n "$psi" ] && rx=$(pings "$DN")
q=$(ps QFI)
got="rules=$(ps RULES) qfi=$q ul=$(ps "UL_QFI.$q" | num) unmatched=$(ps UL_UNMATCHED | num) received=${rx:-0}"
row ksim-p2.core-default-rule '^rules=[1-9] qfi=[0-9]+ ul=([3-9]|[1-9][0-9]+) unmatched=0 received=3$' "$got"
off

if ! on_stub; then
    for id in ksim-p2.ul-classifier ksim-p2.multi-drb ksim-p2.ul-classifier-precedence ksim-p2.modify-add-flow \
              ksim-p2.modify-release-flow; do
        skip_row "$id" "the QoS rules are the core's ($CORE): only the stub's SMF sends the ones these rows need"
    done
    summary "ksim-p2-qos"
    exit 0
fi

N='([3-9]|[1-9][0-9]+)'   # three pings or more

echo "-- a second flow (QFI 2, 5QI 7) for 10.60.0.9 (UE $u)"
stub qos flows-add --qfi 2 --5qi 7 --precedence 10 --filter remote=10.60.0.9/32 >/dev/null || abort "the stub took no flow"
seq=$(ctl info | kv EVENT_SEQ)
up
upf2=$(stub_kv UPF_UL_QFI.2)
r9=0; r1=0
[ -n "$psi" ] && { r9=$(pings 10.60.0.9); r1=$(pings "$DN"); }
rule=$(ctl wait ue.qos.classified --since "$seq" --where qfi=2 --timeout 5s | kv RULE)
got="ue_qfi2=$(ps UL_QFI.2 | num) ue_qfi1=$(ps UL_QFI.1 | num) upf_qfi2=$(( $(stub_kv UPF_UL_QFI.2) - upf2 ))"
got="$got rule=${rule:-none} new_failures=$(new_failures) received=${r9:-0}/${r1:-0}"
row ksim-p2.ul-classifier "^ue_qfi2=3 ue_qfi1=$N upf_qfi2=3 rule=2 new_failures=0 received=3/3\$" "$got"
qos=$(ctl gnb "$GNB" qos "$u")
got="drbs=$(printf '%s\n' "$qos" | kv "PS.$psi.DRBS") drb1=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.1.QFIS")"
got="$got drb2=$(printf '%s\n' "$qos" | kv "PS.$psi.DRB.2.QFIS") du_drb2=$(du_qfis 2) cuup_ul1=$(cuup_ul 1) cuup_ul2=$(cuup_ul 2)"
row ksim-p2.multi-drb "^drbs=1,2 drb1=1 drb2=2 du_drb2=2 cuup_ul1=$N cuup_ul2=$N\$" "$got"
off

echo "-- two matching rules: 10.60.0.0/24 at 20 (QFI 2), 10.60.0.9 at 10 (QFI 3) (UE $u)"
stub qos flows-clear >/dev/null
stub qos flows-add --qfi 2 --precedence 20 --filter remote=10.60.0.0/24 >/dev/null
stub qos flows-add --qfi 3 --precedence 10 --filter remote=10.60.0.9/32 >/dev/null
up
r9=0; r5=0
[ -n "$psi" ] && { r9=$(pings 10.60.0.9); r5=$(pings 10.60.0.5); }
got="ue_qfi3=$(ps UL_QFI.3 | num) ue_qfi2=$(ps UL_QFI.2 | num) ue_qfi1=$(ps UL_QFI.1 | num)"
got="$got new_failures=$(new_failures) received=${r9:-0}/${r5:-0}"
row ksim-p2.ul-classifier-precedence '^ue_qfi3=3 ue_qfi2=3 ue_qfi1=0 new_failures=0 received=3/3$' "$got"
off
stub qos flows-clear >/dev/null

echo "-- a modify adds QFI 4 (5QI 8) for 10.60.0.7, then releases it (UE $u)"
up
supi=$(ctl ue "$u" status | kv UE)
seq=$(ctl info | kv EVENT_SEQ)
stub qos add --ue "$supi" --psi "${psi:-1}" --qfi 4 --5qi 8 --precedence 5 --filter remote=10.60.0.7/32 >/dev/null \
    || abort "the stub sent no modification"
mod=$(ctl wait ran.session.modify --since "$seq" --timeout 10s)
ctl ue "$u" wait nas.sm.mod.command --since "$seq" --timeout 10s >/dev/null
r7=0
[ -n "$psi" ] && r7=$(pings 10.60.0.7)
got="by=$(printf '%s\n' "$mod" | kv BY) added=$(printf '%s\n' "$mod" | kv ADDED) drbs_added=$(printf '%s\n' "$mod" | kv DRBS_ADDED)"
got="$got rules=$(ps RULES) ue_qfi4=$(ps UL_QFI.4 | num) drbs=$(ctl gnb "$GNB" qos "$u" | kv "PS.$psi.DRBS")"
got="$got du_drb2=$(du_qfis 2) cuup_ul2=$(cuup_ul 2) received=${r7:-0}"
row ksim-p2.modify-add-flow "^by=amf added=4 drbs_added=2 rules=2 ue_qfi4=3 drbs=1,2 du_drb2=4 cuup_ul2=$N received=3\$" "$got"

seq=$(ctl info | kv EVENT_SEQ)
ul1=$(ps UL_QFI.1 | num)
stub qos del --ue "$supi" --psi "${psi:-1}" --qfi 4 >/dev/null || abort "the stub sent no modification"
mod=$(ctl wait ran.session.modify --since "$seq" --where released=4 --timeout 10s)
ctl ue "$u" wait nas.sm.mod.command --since "$seq" --timeout 10s >/dev/null
r7=0
[ -n "$psi" ] && r7=$(pings 10.60.0.7)
got="released=$(printf '%s\n' "$mod" | kv RELEASED) drbs_removed=$(printf '%s\n' "$mod" | kv DRBS_REMOVED) rules=$(ps RULES)"
got="$got drbs=$(ctl gnb "$GNB" qos "$u" | kv "PS.$psi.DRBS") du_drb2=$(du_qfis 2) cuup_drb2=$(cuup_has 2)"
got="$got ul1=$(( $(ps UL_QFI.1 | num) - ul1 )) received=${r7:-0}"
row ksim-p2.modify-release-flow '^released=4 drbs_removed=2 rules=1 drbs=1 du_drb2= cuup_drb2=0 ul1=3 received=3$' "$got"
off

summary "ksim-p2-qos"
