#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The two-DU gate (P3 R4; ADR 0013 points 1-3, D7): one gNB whose CU-CP serves two DUs of one
# cell each (topologies/*-stub-2du.yaml: DU 1's cell on TAC 1, DU 2's on TAC 7; UEs 1-6 hear
# DU 1 best, UEs 7-12 DU 2). Rows of gates/rows/p3.tsv whose topology is 1g2d, aio and split:
#   ksim-p3.multi-du.f1          two DUs complete F1 Setup with one CU-CP, each its own cell
#   ksim-p3.camp.cell-selection  each UE camps on the strongest suitable cell it hears
#   ksim-p3.camp.tai-from-cell   the UE's TAI is its cell's
#   ksim-p3.cell.announce        each DU announces its cell; the CU-CP's INITIAL UE MESSAGEs
#                                carry each cell's NCI and TAC in the user location
#   ksim-p3.cell.sfn-epoch       the DUs' SFNs follow one CLOCK_REALTIME epoch
#   ksim-p3.multi-du.f1-loss     DU 2 restarting releases only its UE (the CU-CP asks the AMF);
#                                DU 1's keeps its session
#   ksim-p3.ng.ran-config-update the TAs change as DU 2 goes and comes back: RAN CONFIGURATION
#                                UPDATE each time, acknowledged, and the AMF holds both TACs
#   ksim-p3.faults.cell-off-on   du cell off: DU 2's UE loses its cell, the DU asks for its
#                                release; cell on: it camps there again
#   ksim-p3.multi-du.p1-regression  the P1 gates pass in this run, with UEs on both cells
# A run of another topology scores none of them (gates/lib/ksim.sh, row_in_topology).
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p3-multidu.sh
#   [DN_ADDR=<IPv4>]   the address pinged (default 10.60.0.1, the stub's DN)
#
# UEs 1 and 7 for its own rows, then the P1 gates' UEs; all off at the start.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

: "${DN_ADDR:=10.60.0.1}"
if ! row_in_topology ksim-p3.multi-du.f1; then
    echo "-- not a 1g2d run ($KSIM_RUN_TOPOLOGY): the two-DU rows are scored by a two-DU run"
    summary "ksim-p3-multidu"
    exit 0
fi
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
GNB=$(ctl info | kv GNB)
DU1="${GNB:?}-du"
DU2="${GNB}-du2"

# ev NAME [SINCE]: the run's events of that name since SINCE (default 0), one JSON line each.
ev() { ctl events --since "${2:-0}" | grep "\"event\":\"$1\""; }
# field KEY: KEY's value in the JSON event lines on stdin (the last one).
field() { sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" | tail -n 1; }

echo "-- two DUs, one CU-CP"
info=$(ctl info)
tac1=$(ev ran.f1.setup | grep "\"subject\":\"gnb:$GNB\"" | grep "\"du\":\"$DU1\"" | field tac)
tac2=$(ev ran.f1.setup | grep "\"subject\":\"gnb:$GNB\"" | grep "\"du\":\"$DU2\"" | field tac)
h1=$(ctl du "$DU1" ue-list | kv CELL_HANDLE)
h2=$(ctl du "$DU2" ue-list | kv CELL_HANDLE)
row ksim-p3.multi-du.f1 '^f1_dus=2 cells=2 du=1/1 du2=2/7$' \
    "f1_dus=$(printf '%s\n' "$info" | kv F1_DUS) cells=$(printf '%s\n' "$info" | kv CELLS_ACTIVE) du=$h1/$tac1 du2=$h2/$tac2"

echo "-- each UE on the strongest cell it hears (UE 1: DU 1, UE 7: DU 2)"
for u in 1 7; do
    ctl ue "$u" power on --wait 30s >/dev/null || abort "UE $u did not register"
done
psi1=$(ctl ue 1 ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
psi7=$(ctl ue 7 ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
[ -n "$psi1" ] && [ -n "$psi7" ] || abort "UE 1 or 7 got no session"
c1=$(ev rrc.camped | grep "\"subject\":\"ue:$(ctl ue 1 status | kv UE)\"")
c7=$(ev rrc.camped | grep "\"subject\":\"ue:$(ctl ue 7 status | kv UE)\"")
row ksim-p3.camp.cell-selection '^ue1=cell1/-60 ue7=cell2/-60 camps=[12],[12]$' \
    "ue1=cell$(printf '%s\n' "$c1" | field cell)/$(printf '%s\n' "$c1" | field rsrp) ue7=cell$(printf '%s\n' "$c7" | field cell)/$(printf '%s\n' "$c7" | field rsrp) camps=$(printf '%s\n' "$c1" | grep -c .),$(printf '%s\n' "$c7" | grep -c .)"
row ksim-p3.camp.tai-from-cell '^ue1=00101-000001 ue7=00101-000007$' \
    "ue1=$(ctl ue 1 status | kv CELL_TAI) ue7=$(ctl ue 7 status | kv CELL_TAI)"
uli=$(tshark_fields "$RUN/ngap.pcapng" "ngap.procedureCode == 15" ngap.NRCellIdentity ngap.tAC |
    awk -F '\t' '{ print $1 "/" $2 }' | sort -u | tr '\n' ',' | sed 's/,$//')
row ksim-p3.cell.announce '^announces=[1-9][0-9]*,[1-9][0-9]* uli=0x0*680001/1,0x0*680002/7$' \
    "announces=$(ctl du "$DU1" ue-list | kv ANNOUNCES),$(ctl du "$DU2" ue-list | kv ANNOUNCES) uli=$uli"

echo "-- the SFN epoch"
# Each DU's SFN with the CLOCK_REALTIME ms it was read at: on the epoch, SFN = (ms / 10) mod 1024
# (ledger A-09), so each is off it by at most a frame, and the two by what the reads' times say.
l1=$(ctl du "$DU1" ue-list)
l2=$(ctl du "$DU2" ue-list)
s1=$(printf '%s\n' "$l1" | kv SFN); a1=$(printf '%s\n' "$l1" | kv SFN_AT_MS)
s2=$(printf '%s\n' "$l2" | kv SFN); a2=$(printf '%s\n' "$l2" | kv SFN_AT_MS)
sfn_d() { awk -v a="$1" -v b="$2" 'BEGIN { d = (a - b) % 1024; if (d < 0) d += 1024; if (d > 512) d = 1024 - d; print d }'; }
e1=$(sfn_d "$s1" "$(( (a1 / 10) % 1024 ))")
e2=$(sfn_d "$s2" "$(( (a2 / 10) % 1024 ))")
drift=$(sfn_d "$(( s2 - s1 ))" "$(( ((a2 / 10) - (a1 / 10)) % 1024 ))")
row ksim-p3.cell.sfn-epoch '^du1_frames=[01] du2_frames=[01] drift_frames=[0-2]$' \
    "du1_frames=$e1 du2_frames=$e2 drift_frames=$drift"

echo "-- DU 2 restarts: only its UE goes (UE 7); the TAs change and come back"
seq=$(ctl info | kv EVENT_SEQ)
ctl du "$DU2" restart >/dev/null || abort "du $DU2 restart refused"
lost=$(ctl wait ran.f1.lost --since "$seq" --timeout 10s | kv UES)
ctl wait ran.ue.released --since "$seq" --timeout 15s >/dev/null
asked=$(ev ran.ue.release_request "$seq" | grep -c '"cause":"radio-connection-with-ue-lost"')
cm1=$(ctl ue 1 status | kv CM_STATE)
p1=$(ctl ue 1 ping "$DN_ADDR" --psi "$psi1" -c 3 --interval 200 | kv RECEIVED)
row ksim-p3.multi-du.f1-loss '^lost_ues=1 released=1 ue1=CM-CONNECTED ping=3/3$' \
    "lost_ues=$lost released=$asked ue1=$cm1 ping=$p1/3"
back=$(ctl wait ran.f1.setup --where du="$DU2" --since "$seq" --timeout 30s | kv EVENT)
ctl wait ran.ng.config_update.ack --since "$seq" --timeout 10s >/dev/null
sleep 1
updates=$(ev ran.ng.config_update "$seq" | grep -v '\.ack' | sed -n 's/.*"tacs":"\([0-9]*\)".*/\1/p' | tr '\n' ',' | sed 's/,$//')
acks=$(ev ran.ng.config_update.ack "$seq" | grep -c '"result":"ack"')
tacs=$("$KSIM_CTL" --socket "${STUB_CTL:-/nonexistent}" stub 2>/dev/null | kv "GNB.0x1a0.TACS")
row ksim-p3.ng.ran-config-update '^du2=ran.f1.setup updates=1,2 acks=2 amf_tacs=(1,7|core)$' \
    "du2=$back updates=$updates acks=$acks amf_tacs=${tacs:-core}"

echo "-- DU 2's cell off the air and back (UE 7)"
# UE 7 lost its link with DU 2 and recovered (TS 24.501 5.5.1.3.2 f), perhaps through DU 1 while
# DU 2 was off the air: once idle it camps on DU 2 again, and a ping connects it there.
ctl ue 7 wait nas.reg.complete --since "$seq" --timeout 30s >/dev/null
[ "$(ctl ue 7 status | kv CM_STATE)" = CM-CONNECTED ] && ran_release 7 >/dev/null
i=0
until [ "$(ctl ue 7 status | kv CELL)" = 2 ]; do
    i=$((i + 1)); [ "$i" -gt 50 ] && abort "UE 7 did not camp on DU 2 again"
    sleep 0.2
done
ctl ue 7 ping "$DN_ADDR" --psi "$psi7" -c 2 --interval 200 >/dev/null 2>&1   # connected again, on DU 2
seq=$(ctl info | kv EVENT_SEQ)
off=$(ctl du "$DU2" cell off | kv CELL)
rel=$(ctl wait ran.du.cell_off --since "$seq" --timeout 5s | kv RELEASED)
rlf=$(ctl ue 7 wait rrc.connection_lost --since "$seq" --timeout 5s | kv REASON)
gone=$(ctl ue 7 wait rrc.cell_lost --since "$seq" --timeout 10s | kv CELL)
ctl du "$DU2" cell on >/dev/null
again=$(ctl ue 7 wait rrc.camped --where cell=2 --since "$seq" --timeout 10s | kv CELL)
row ksim-p3.faults.cell-off-on '^off=off released=1 ue7=radio-link-failure lost=2 camped=2$' \
    "off=$off released=$rel ue7=$(printf '%s' "$rlf" | tr ' ' '-') lost=$gone camped=$again"

for u in 1 7; do
    release_all "$u"
    ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1
done

echo "-- the P1 gates in this run (UEs on both cells)"
seq=$(ctl info | kv EVENT_SEQ)
gates=0; failed=0; aborted=0
for g in "$KSIM_ROOT"/gates/verification/ksim-p1-*.sh; do
    gates=$((gates + 1))
    KSIM_ROWS="$KSIM_ROOT/gates/rows/p2.tsv" sh "$g" > "$RUN/p1-regression-$(basename "$g" .sh).out" 2>&1
    rc=$?
    n=$(grep -c '^  FAIL ' "$RUN/p1-regression-$(basename "$g" .sh).out")
    failed=$((failed + n))
    [ "$rc" -ne 0 ] && [ "$n" -eq 0 ] && aborted=$((aborted + 1))
done
cells=$(ctl events --since "$seq" | grep '"rrc.camped"' | sed -n 's/.*"cell":"\([0-9]*\)".*/\1/p' | sort -u | tr '\n' ',' | sed 's/,$//')
row ksim-p3.multi-du.p1-regression '^gates=6 failed=0 aborted=0 cells=1,2$' \
    "gates=$gates failed=$failed aborted=$aborted cells=$cells"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the gate left a fault set"
summary "ksim-p3-multidu"
