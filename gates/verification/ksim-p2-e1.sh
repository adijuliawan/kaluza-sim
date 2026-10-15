#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The E1 gate (P2 Q5; ADR 0012): E1 with OCUDU on either side, and the CU-UP's
# inactivity report. Rows of gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q5:
#   ksim-p2.ocudu-e1-cuup  C4: OCUDU's CU-UP with our CU-CP (topologies/ocudu-c4-stub.yaml)
#   ksim-p2.ocudu-e1-cucp  C5: our CU-UP with OCUDU's CU-CP (topologies/ocudu-c5-stub.yaml)
#   ksim-p2.e1-inactivity  split, C4, C5: the CU-UP's BEARER CONTEXT INACTIVITY NOTIFICATION
#                          leads the CU-CP to release the UE with user-inactivity
# The mode comes from the run (info ROLE, PEER_CUCP, PEER_CUUP); a row not for it is
# skipped. The UE Inactivity Timer is 15 s in each of the three topologies.
#
#   RUN=<run dir> CORE=stub [STUB_CTL=<stub socket>] gates/verification/ksim-p2-e1.sh
#
# topology: topologies/split-stub-e1.yaml
# UE E1_UE (default 1).

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

info=$(ctl info)
role=$(printf '%s\n' "$info" | kv ROLE)
pcp=$(printf '%s\n' "$info" | kv PEER_CUCP)
pup=$(printf '%s\n' "$info" | kv PEER_CUUP)
GNB=$(printf '%s\n' "$info" | kv GNB)
mode=aio
[ "$role" = split ] && mode=split
[ "$pcp" = ocudu ] && [ -z "$pup" ] && mode=C5
[ "$pup" = ocudu ] && [ -z "$pcp" ] && mode=C4
[ "$pcp" = ocudu ] && [ "$pup" = ocudu ] && mode=C3
echo "-- mode $mode"
case "$mode" in
    C3|C4|C5) PEER_ALLOW="$KSIM_ROOT/gates/allow/ocudu.tsv"; PEER_MODE=$mode ;;
esac
[ "$mode" = C4 ] || skip_row ksim-p2.ocudu-e1-cuup "a $mode run (the row is C4's)"
[ "$mode" = C5 ] || skip_row ksim-p2.ocudu-e1-cucp "a $mode run (the row is C5's)"
case "$mode" in
    split|C4|C5) ;;
    *)
        skip_row ksim-p2.e1-inactivity "a $mode run (the row is split's, C4's and C5's)"
        summary "ksim-p2-e1"
        exit $?
        ;;
esac
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
[ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ] || abort "the E1 gate runs against the stub"
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
: "${E1_UE:=1}"
u=$E1_UE
# e1ap PDUs of a procedure (code) and kind in our E1AP capture: the CU-CP's (C4,
# split) or the CU-UP's (C5).
e1_count() {
    tshark_fields "$RUN/e1ap.pcapng" "e1ap.procedureCode == $1 && e1ap.$2_element" frame.number | wc -l
}

echo "-- E1 Setup"
e1=$(ctl wait ran.e1.setup --timeout 15s)
setup_event=$(printf '%s\n' "$e1" | kv EVENT)
setup_name=$(printf '%s\n' "$e1" | kv CU_UP)   # C4: the name OCUDU's CU-UP gave (its gNB-CU-CP Name is optional, C5)

echo "-- a session over E1 (UE $u)"
reg=$(ctl ue "$u" power on --wait 30s)
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE $u did not register"
ps=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s)
psi=$(printf '%s\n' "$ps" | kv PSI)
[ -n "$psi" ] || abort "UE $u got no session"
ping=$(ctl ue "$u" ping "${DN_ADDR:-10.60.0.1}" --psi "$psi" -c 3 --interval 200 | kv RECEIVED)

echo "-- the CU-UP's inactivity report (up to 40 s)"
seq=$(ctl info | kv EVENT_SEQ)
idle=$(ctl ue "$u" wait nas.mm.cm_idle --since "$seq" --timeout 40s | kv EVENT)
# Our CU-UP's report (split, C5) or our CU-CP's taking OCUDU's (C4).
reported=0
ctl wait ran.e1.inactivity --where active=0 --since "$seq" --timeout 1s >/dev/null && reported=1
cause=$(stub | kv LAST_RELEASE_CAUSE)
row ksim-p2.e1-inactivity '^reported=1 idle=nas.mm.cm_idle cause=user-inactivity$' \
    "reported=$reported idle=$idle cause=$cause"

echo "-- release"
ctl ue "$u" deregister normal --wait 15s >/dev/null
sleep 1
case "$mode" in
    C4)
        # Our CU-CP's capture: OCUDU's E1 SETUP REQUEST, and the bearer context set up,
        # modified (the DU's F1-U end) and released, each answered. Lead O-4 (the allow
        # entry) stands for the user data only: with any E1 part missing it is not looked up.
        e1_part="cu_up=$setup_name setup=$(e1_count 8 successfulOutcome) modified=$(e1_count 9 successfulOutcome) released=$(e1_count 11 successfulOutcome)"
        printf '%s\n' "$e1_part" | grep -Eq '^cu_up=ocuup_[0-9]+ setup=[1-9][0-9]* modified=[1-9][0-9]* released=[1-9][0-9]*$' || ROW_NO_ALLOW=1
        row ksim-p2.ocudu-e1-cuup '^cu_up=ocuup_[0-9]+ setup=[1-9][0-9]* modified=[1-9][0-9]* released=[1-9][0-9]* received=[1-9]$' \
            "$e1_part received=$ping"
        ROW_NO_ALLOW=0
        ;;
    C5)
        # Our CU-UP took OCUDU's E1 SETUP RESPONSE, and its capture holds the bearer
        # contexts we answered.
        row ksim-p2.ocudu-e1-cucp '^e1setup=ran.e1.setup setup=[1-9][0-9]* released=[1-9][0-9]* received=[1-9]$' \
            "e1setup=$setup_event setup=$(e1_count 8 successfulOutcome) released=$(e1_count 11 successfulOutcome) received=$ping"
        ;;
esac
ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1

summary "ksim-p2-e1"
