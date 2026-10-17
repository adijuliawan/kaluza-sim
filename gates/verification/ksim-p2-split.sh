#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P2 split gate (P2 Q3; ADR 0011): the roles as processes of their own over
# real links. F1-C and E1 over SCTP with the CU-CP listening, F1-U over UDP,
# KAIR over the run's SEQPACKET socket; each UE's F1AP on its own stream; the
# DU's process restarted under a UE (the CU-CP asks the AMF to release it); the
# CU-CP's process restarted (the DU sets F1 up again). Rows of
# gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q2 or Q3, in split mode; an
# all-in-one run SKIPs them.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p2-split.sh
#
# topology: topologies/split-stub.yaml
# UEs SPLIT_UE1 and SPLIT_UE2 (default 11 and 12) are used, switched off first
# if an earlier gate left them on. The restart rows run on the stub only (rows'
# cores), never against a real core.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
GNB=$(ctl info | kv GNB)
: "${GNB:=ksim-gnb1}"
set_run_mode
PEER_CUUP=$(ctl info | kv PEER_CUUP)
: "${SPLIT_UE1:=11}"
: "${SPLIT_UE2:=12}"
for u in "$SPLIT_UE1" "$SPLIT_UE2"; do
    st=$(ctl ue "$u" status 2>/dev/null)
    if [ "$(printf '%s\n' "$st" | kv RM_STATE)" = RM-REGISTERED ]; then
        release_all "$u"
        ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1
    elif [ "$(printf '%s\n' "$st" | kv POWER)" = on ]; then
        ctl ue "$u" power off --abrupt >/dev/null 2>&1
    fi
done

if [ "$(ctl info | kv ROLE)" != split ]; then
    for id in ksim-p2.roles-separate ksim-p2.f1-setup-sctp ksim-p2.e1-setup-sctp ksim-p2.kair-seqpacket \
              ksim-p2.per-ue-stream ksim-p2.f1u-udp ksim-p2.f1-loss-release ksim-p2.f1-reassociation; do
        skip_row "$id" "an all-in-one run (mode aio)"
    done
    summary "ksim-p2-split"
    exit $?
fi

# established SCTP associations on PORT, from ss, in the namespace NS when the run has it: in the
# lab ksim-netd made the role's sockets there (split-lab.yaml's ksim-du, ksim-cuup, ksim-cucp), and
# ss here would not see them (P2 Q14, LW5), so ss runs there through netd's exec, as the caller.
# On the dev PC the roles' sockets are in this namespace.
sctp_estab() {
    if [ -n "${2:-}" ] && ip netns list 2>/dev/null | grep -q "^$2\( \|\$\)"; then
        _log="$RUN/ss-$2-$1.txt"
        _pid=$("$KSIM_CTL" netd exec "$2" --log "$_log" -- ss -S -n state established \
            "( sport = :$1 or dport = :$1 )" | sed -n 's/^PID=//p')
        _i=0
        while [ -n "$_pid" ] && ps -p "$_pid" >/dev/null 2>&1 && [ "$_i" -lt 50 ]; do
            sleep 0.1; _i=$((_i + 1))
        done
        _c=$(grep -c ":$1" "$_log" 2>/dev/null)
        echo "${_c:-0}"
    else
        ss -S -n state established "( sport = :$1 or dport = :$1 )" 2>/dev/null | grep -c ":$1"
    fi
}

echo "-- the roles"
nodes=$(ctl nodes)
n=$(printf '%s\n' "$nodes" | kv NODES)
up=$(printf '%s\n' "$nodes" | grep -c '^NODE\.[0-9]*\.UP=1$')
pids=$(printf '%s\n' "$nodes" | sed -n 's/^NODE\.[0-9]*\.PID=//p' | sort -u | grep -vc '^-1$')
dirs=0
for r in cucp cuup du ue; do
    [ -f "$RUN/$r/manifest.json" ] && [ -f "$RUN/$r/events.ndjson" ] && dirs=$((dirs + 1))
done
row ksim-p2.roles-separate '^nodes=4 up=4 pids=4 dirs=4$' "nodes=$n up=$up pids=$pids dirs=$dirs"

echo "-- F1-C and E1 over SCTP"
# Our CU-CP's event names the DU; with OCUDU's CU-CP (C3, C5) the DU's own names the cell.
case "$KSIM_RUN_MODE" in
    C3|C5) f1=$(ctl wait ran.f1.setup --where cell_active=1 --timeout 15s | kv EVENT) ;;
    *) f1=$(ctl wait ran.f1.setup --where du=$GNB-du --timeout 15s | kv EVENT) ;;
esac
row ksim-p2.f1-setup-sctp '^f1setup=ran.f1.setup sctp=[1-9][0-9]* wrong_ppid=0$' \
    "f1setup=$f1 sctp=$(sctp_estab 38472 "${SPLIT_DU_NETNS:-ksim-du}") wrong_ppid=$(ctl du "$GNB-du" ue-list | kv WRONG_PPID)"
e1=$(ctl wait ran.e1.setup --timeout 15s | kv EVENT)
# E1's association, seen from our end of it: our CU-UP's, or our CU-CP's with OCUDU's CU-UP (C4).
case "$KSIM_RUN_MODE" in
    C4) e1_ns=${SPLIT_CUCP_NETNS:-ksim-cucp} ;;
    *) e1_ns=${SPLIT_CUUP_NETNS:-ksim-cuup} ;;
esac
row ksim-p2.e1-setup-sctp '^e1setup=ran.e1.setup sctp=[1-9][0-9]* e1_ready=1$' \
    "e1setup=$e1 sctp=$(sctp_estab 38462 "$e1_ns") e1_ready=$(ctl cuup "$GNB-cuup" bearers | kv E1_READY)"

echo "-- KAIR"
farms=$(ctl wait ran.du.kair.subscribe --timeout 15s | kv FARMS)
sock=no
[ -S "$RUN/kair.sock" ] && sock=yes
row ksim-p2.kair-seqpacket '^farms=[1-9] socket=yes$' "farms=$farms socket=$sock"

echo "-- one F1 stream per UE (UEs $SPLIT_UE1 and $SPLIT_UE2)"
ctl ue "$SPLIT_UE1" power on --wait 30s >/dev/null || abort "UE $SPLIT_UE1 did not register"
ctl ue "$SPLIT_UE2" power on --wait 30s >/dev/null || abort "UE $SPLIT_UE2 did not register"
list=$(ctl gnb "$GNB" ue-list)
streams=$(printf '%s\n' "$list" | kv F1_UE_STREAMS)
nstreams=$(printf '%s' "$streams" | tr ',' '\n' | grep -c '[0-9]')
row ksim-p2.per-ue-stream '^streams=[0-9,]+ distinct=([2-9]|[1-9][0-9]+) on_stream0=0$' \
    "streams=$streams distinct=$nstreams on_stream0=$(printf '%s\n' "$list" | kv F1_UE_ON_STREAM0)"

echo "-- F1-U over UDP (UE $SPLIT_UE1)"
ctl ue "$SPLIT_UE1" ps-establish ipv4 --dnn internet $SLICE --wait 15s >/dev/null || abort "UE $SPLIT_UE1 got no session"
ping=$(ctl ue "$SPLIT_UE1" ping "${DN_ADDR:-10.60.0.1}" -c 3 --interval 200 | kv RECEIVED)
# The DU's F1-U address, whatever the placement (127.0.10.2 on the dev PC, its ksim-mid leg in the
# lab): only the DU sends DL DATA DELIVERY STATUS (TS 38.425), NR-U PDU type 1.
du_f1u=$(tshark_fields "$RUN/gtpu.pcapng" "nrup.pdu_type == 1" ip.src | head -n 1)
f1u=$(tshark_fields "$RUN/gtpu.pcapng" "udp.port == 2152 && ip.addr == ${du_f1u:-127.0.10.2}" frame.number | wc -l)
if [ -n "$PEER_CUUP" ]; then
    # OCUDU's CU-UP (C3, C4): the user data our DU passed over F1-U, its SDUs each way.
    du=$(ctl du "$GNB-du" ue-list)
    dl=$(printf '%s\n' "$du" | kv DL_SDUS); ul=$(printf '%s\n' "$du" | kv UL_SDUS)
else
    bearers=$(ctl cuup "$GNB-cuup" bearers)
    dl=$(printf '%s\n' "$bearers" | kv DL_PACKETS); ul=$(printf '%s\n' "$bearers" | kv UL_PACKETS)
fi
row ksim-p2.f1u-udp '^received=[1-9] dl=[1-9][0-9]* ul=[1-9][0-9]* f1u_frames=[1-9][0-9]*$' \
    "received=$ping dl=$dl ul=$ul f1u_frames=$f1u"
release_all "$SPLIT_UE1"

if [ "$CORE" != stub ] || [ "$KSIM_RUN_MODE" != split ]; then
    skip_row ksim-p2.f1-loss-release "the DU's restart is for the stub only, in split mode"
    skip_row ksim-p2.f1-reassociation "the CU-CP's restart is for the stub only, in split mode"
    ctl ue "$SPLIT_UE1" deregister normal --wait 15s >/dev/null
    ctl ue "$SPLIT_UE2" deregister normal --wait 15s >/dev/null
    summary "ksim-p2-split"
    exit $?
fi

echo "-- the DU's process restarted under UE $SPLIT_UE1"
# A role's restart is refused while the one before is still starting its process
# ("the gNB is restarting"), which a cell back up does not wait for. Each restart
# below is retried until taken, and its sequence comes from info: a refused reply has
# none, and the waits would then match the events from before (P2 Q7: the mutant
# f1_no_reassociation survived that way in a loaded CI run).
restart_role() {   # $1 = du|cucp, $2 = its name in a message
    _n="$GNB"; [ "$1" = du ] && _n="$GNB-du"
    _i=0
    until ctl "$1" "$_n" restart >/dev/null 2>&1; do
        _i=$((_i + 1)); [ "$_i" -gt 75 ] && abort "the $2 did not restart"
        sleep 0.2
    done
}
since=$(ctl info | kv EVENT_SEQ)
[ -n "$since" ] || abort "the run gave no event sequence"
restart_role du "DU"
lost=$(ctl wait ran.f1.lost --since "$since" --timeout 15s | kv EVENT)
cause=$(ctl wait ran.ue.release_request --since "$since" --timeout 15s | kv CAUSE)
released=$(ctl wait ran.ue.released --since "$since" --timeout 15s | kv EVENT)
row ksim-p2.f1-loss-release '^lost=ran.f1.lost cause=radio-connection-with-ue-lost released=ran.ue.released$' \
    "lost=$lost cause=$cause released=$released"
ctl wait ran.f1.setup --where cell_active=1 --since "$since" --timeout 30s >/dev/null ||
    abort "the DU's cell did not come back after its restart"

echo "-- the CU-CP's process restarted"
since=$(ctl info | kv EVENT_SEQ)
[ -n "$since" ] || abort "the run gave no event sequence"
restart_role cucp "CU-CP"
again=$(ctl wait ran.f1.setup --where cell_active=1 --since "$since" --timeout 30s | kv EVENT)
ng=$(ctl wait ran.ng.setup --since "$since" --timeout 30s | kv EVENT)
row ksim-p2.f1-reassociation '^f1setup=ran.f1.setup cell_active=1 ngsetup=ran.ng.setup$' \
    "f1setup=$again cell_active=$(ctl du "$GNB-du" ue-list | kv CELL_ACTIVE) ngsetup=$ng"

summary "ksim-p2-split"
