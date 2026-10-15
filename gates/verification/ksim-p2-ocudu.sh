#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The OCUDU interop gate, combination C3 (P2 Q4; ADR 0012): our UE farm and DU
# with OCUDU's CU-CP and CU-UP, which gates/run.sh starts from the topology's
# peers (tools/ocudu-peer.sh). Rows of gates/rows/p2.tsv (KSIM_ROWS) whose
# milestone is Q4 and whose modes hold C3; a run without the peers SKIPs them.
# OCUDU has no ksim control API, so the checks read our DU's and UE's events
# and our captures: f1ap.pcapng and gtpu.pcapng are the DU's in this run.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza [STUB_CTL=<stub socket>] gates/verification/ksim-p2-ocudu.sh
#
# topology: topologies/ocudu-c3-stub.yaml
# mutants: run by tools/ci.d/58-ocudu.sh
# UE OCUDU_UE (default 1). The peer's UE inactivity timer is 15 s (its config
# template), so the release row waits up to 30 s.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

ROWS_C3="ksim-p2.ocudu-f1-setup ksim-p2.ocudu-registration ksim-p2.ocudu-as-smc ksim-p2.ocudu-capability
ksim-p2.ocudu-drb ksim-p2.ocudu-ddds ksim-p2.ocudu-inactivity-release ksim-p2.ocudu-paging ksim-p2.ocudu-dereg"
if [ "$(ctl info | kv PEER_CUCP)" != ocudu ]; then
    for id in $ROWS_C3; do
        skip_row "$id" "not a C3 run (the topology's peers name no OCUDU CU-CP)"
    done
    summary "ksim-p2-ocudu"
    exit $?
fi
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
GNB=$(ctl info | kv GNB)
: "${OCUDU_UE:=1}"
u=$OCUDU_UE
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }

echo "-- F1 Setup with OCUDU's CU-CP"
f1=$(ctl wait ran.f1.setup --where cell_active=1 --timeout 30s | kv EVENT)
activated=$(tshark_fields "$RUN/f1ap.pcapng" "f1ap.Cells_to_be_Activated_List_Item_element" frame.number | wc -l)
row ksim-p2.ocudu-f1-setup '^f1setup=ran.f1.setup cell_active=1 activated=[1-9][0-9]*$' \
    "f1setup=$f1 cell_active=$(ctl du "$GNB-du" ue-list | kv CELL_ACTIVE) activated=$activated"

echo "-- registration through OCUDU (UE $u)"
reg=$(ctl ue "$u" power on --wait 30s)
complete=$(ctl ue "$u" wait nas.reg.complete --timeout 5s | kv EVENT)
row ksim-p2.ocudu-registration '^ACCEPT complete=nas.reg.complete$' "$(printf '%s\n' "$reg" | kv RESULT) complete=$complete"
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE $u did not register through OCUDU"
supi=$(printf '%s\n' "$reg" | kv UE)
mine="frame.comment contains \"$supi\""

# OCUDU's preference lists (topologies/peers/ocudu/cucp.yml.in): nia2,nia1 and nea2,nea1,nea0.
as=$(ctl ue "$u" wait rrc.smc.complete --timeout 5s | kv ALG)
ctl ue "$u" wait rrc.integrity_failure --timeout 1ms >/dev/null 2>&1
ifail=$?   # 3: none recorded
row ksim-p2.ocudu-as-smc '^alg=nia2/nea2 integrity_failures=none$' \
    "alg=$as integrity_failures=$([ "$ifail" -eq 3 ] && echo none || echo found)"

# The stub gives no UE Radio Capability, so OCUDU enquires; the UE answers from its persona.
# The UE's persona: its group's in the run's topology (the UE role's manifest names the file).
group=$(ctl ues | sed -n "s/^UE\.$u\.GROUP=//p")
persona=$(python3 -I - "$RUN/ue/manifest.json" "$group" <<'PY'
import json, os, re, sys
topo = json.load(open(sys.argv[1]))["topology"]["file"]
for m in re.finditer(r"group: *([\w-]+),(?:(?!group:).)*?persona: *([^\s,}]+)", open(topo).read(), re.S):
    if m.group(1) == sys.argv[2]:
        print(os.path.normpath(os.path.join(os.path.dirname(topo), m.group(2))))
PY
)
want=$(sed -n '/- rat: nr/{n;s/^ *uper: *//p;}' "$persona" 2>/dev/null | head -n 1)
got=$(tshark_fields "$RUN/uu.pcapng" "nr-rrc.ueCapabilityInformation_element && $mine" nr-rrc.ue_CapabilityRAT_Container | head -n 1 | tr -d ':')
row ksim-p2.ocudu-capability '^sent=1 identical=1$' \
    "sent=$([ -n "$got" ] && echo 1 || echo 0) identical=$([ -n "$want" ] && [ "$got" = "$want" ] && echo 1 || echo 0)"

echo "-- the DRB and a ping over it"
ps=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s)
psi=$(printf '%s\n' "$ps" | kv PSI)
ip=$(printf '%s\n' "$ps" | kv IP)
ping=$(ctl ue "$u" ping "${DN_ADDR:-10.60.0.1}" --psi "$psi" -c 3 --interval 200 | kv RECEIVED)
mod=$(tshark_fields "$RUN/f1ap.pcapng" "f1ap.UEContextModificationRequest_element && f1ap.DRBs_ToBeSetupMod_Item_element" frame.number | wc -l)
row ksim-p2.ocudu-drb '^modification=[1-9][0-9]* received=[1-9]$' "modification=$mod received=$ping"

ddds=$(tshark_fields "$RUN/gtpu.pcapng" "nrup.pdu_type == 1" frame.number | wc -l)
row ksim-p2.ocudu-ddds '^ddds_tx=[1-9][0-9]* captured=[1-9][0-9]*$' \
    "ddds_tx=$(ctl du "$GNB-du" ue-list | kv DDDS_TX) captured=$ddds"

echo "-- OCUDU's inactivity release (up to 30 s)"
seq=$(ctl info | kv EVENT_SEQ)
idle=$(ctl ue "$u" wait nas.mm.cm_idle --since "$seq" --timeout 30s | kv EVENT)
row ksim-p2.ocudu-inactivity-release '^nas.mm.cm_idle$' "$idle"

echo "-- a downlink ping to the idle UE"
if on_stub && [ "$idle" = nas.mm.cm_idle ]; then
    seq=$(ctl info | kv EVENT_SEQ)
    stub ping-ue --ue "$supi" --psi "$psi" --seq 1 >/dev/null || abort "the stub did not take ping-ue"
    paged=$(ctl wait ran.du.paging --since "$seq" --timeout 10s | kv EVENT)
    ans=$(ctl ue "$u" wait ue.ping.answered --since "$seq" --timeout 15s | kv EVENT)
    row ksim-p2.ocudu-paging '^paged=ran.du.paging answered=ue.ping.answered$' "paged=$paged answered=$ans"
elif on_stub; then
    skip_row ksim-p2.ocudu-paging "the UE did not go idle"
else
    skip_row ksim-p2.ocudu-paging "no DN-side ping on $CORE"
fi

echo "-- deregistration through OCUDU"
# The UE is idle here: a session release would come with a signalling-only Service
# Request, and OCUDU d9d2263f4d drops the PDU SESSION RESOURCE RELEASE COMMAND for a
# UE without a CU-UP context (docs/interop/ocudu.md, lead O-1). The deregistration
# releases the session with it.
seq=$(ctl info | kv EVENT_SEQ)
dereg=$(ctl ue "$u" deregister normal --wait 15s | kv EVENT)
[ -n "$dereg" ] || dereg=$(ctl ue "$u" wait nas.dereg.accept --since "$seq" --timeout 5s | kv EVENT)
sleep 1
rel=$(tshark_fields "$RUN/f1ap.pcapng" "f1ap.UEContextReleaseCommand_element" frame.number | wc -l)
row ksim-p2.ocudu-dereg '^dereg=nas.dereg.accept release_commands=[1-9][0-9]*$' "dereg=$dereg release_commands=$rel"
ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1
ctl ue "$u" power off --abrupt >/dev/null 2>&1   # deregistered but on: off for the next gate

summary "ksim-p2-ocudu"
