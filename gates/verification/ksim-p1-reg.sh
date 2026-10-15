#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P1 registration gate (P1 N8): NG Setup, initial registration with a null
# SUCI, NAS and AS security mode (NIA2/NEA2), the IMEISV, UE-initiated
# de-registration and switch-off. Rows of gates/rows/p1.tsv whose milestone is
# N8, scored from kaluza-sim's own evidence on any core.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p1-reg.sh
#
# The run's UEs must be off at the start; UE 1 and UE 2 are used.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

command -v tshark >/dev/null 2>&1 || abort "tshark is needed for the pcap rows"
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"

echo "-- NG Setup"
ng=$(ctl wait ran.ng.setup --timeout 15s)
ng_amf=$(printf '%s\n' "$ng" | kv AMF)
ng_pcap=$(tshark_fields "$RUN/ngap.pcapng" 'ngap.NGSetupResponse_element' frame.number | wc -l)
row amf-ueransim.001 '^setup amf=.+ responses=[1-9]' "setup amf=$ng_amf responses=$ng_pcap"
row smsf.009 '^setup amf=.+ responses=[1-9]' "setup amf=$ng_amf responses=$ng_pcap"

echo "-- initial registration (UE 1)"
reg=$(ctl ue 1 power on --wait 30s)
complete=$(ctl ue 1 wait nas.reg.complete --timeout 5s | kv EVENT)
guti=$(printf '%s\n' "$reg" | kv GUTI)
row amf-ueransim.006 '^ACCEPT complete=nas.reg.complete guti=.+' \
    "$(printf '%s\n' "$reg" | kv RESULT) complete=$complete guti=$guti"
supi=$(printf '%s\n' "$reg" | kv UE)
msin=$(printf '%s' "$supi" | sed 's/^imsi-.....//')   # MCC and a 2-digit MNC (the sim ranges)

smc=$(ctl ue 1 wait nas.smc.complete --timeout 5s)
row amf-ueransim.012 '^ea=[0-9] ia=[1-3]$' \
    "ea=$(printf '%s\n' "$smc" | kv EA) ia=$(printf '%s\n' "$smc" | kv IA)"

# The REGISTRATION REQUEST's SUCI in the Uu capture: scheme 0 and the MSIN.
# Frames are this UE's by their comment (the run's other gates use other UEs).
mine="frame.comment contains \"$supi\""
suci=$(tshark_fields "$RUN/uu.pcapng" "nas-5gs.mm.message_type == 0x41 && $mine" \
    nas-5gs.mm.suci.scheme_id nas-5gs.mm.suci.msin | head -n 1 | tr '\t' ' ')
row ksim-p1.reg-null-suci "^0 $msin\$" "$suci"

as=$(ctl ue 1 wait rrc.smc.complete --timeout 5s | kv ALG)
ctl ue 1 wait rrc.integrity_failure --timeout 1ms >/dev/null 2>&1
ifail=$?   # 3: none recorded
row ksim-p1.as-smc-nia2 '^alg=nia2/nea2 integrity_failures=none$' \
    "alg=$as integrity_failures=$([ "$ifail" -eq 3 ] && echo none || echo found)"

# IMEISV iff requested: the SECURITY MODE COMMAND's IMEISV request (Wireshark
# dissects the IE with its EPS routine) against the identity type of the
# SECURITY MODE COMPLETE's first identity, its IMEISV IE (5); a REGISTRATION
# REQUEST in the NAS message container brings a second one.
asked=$(tshark_fields "$RUN/uu.pcapng" "nas-5gs.mm.message_type == 0x5d && $mine" nas-eps.emm.imeisv_req | head -n 1 | cut -d, -f1)
sent=$(tshark_fields "$RUN/uu.pcapng" "nas-5gs.mm.message_type == 0x5e && $mine" nas-5gs.mm.type_id | head -n 1 | cut -d, -f1)
case "$asked" in 1) want='^asked=1 sent=5$' ;; *) want='^asked=0 sent=$' ;; esac
row ksim-p1.imeisv "$want" "asked=${asked:-0} sent=$sent"

echo "-- de-registration (UE 1)"
dereg=$(ctl ue 1 deregister normal --wait 15s)
row amf-ueransim.061 '^nas.dereg.accept$' "$(printf '%s\n' "$dereg" | kv EVENT)"

echo "-- switch-off (UE 2)"
ctl ue 2 power on --wait 30s >/dev/null
seq=$(ctl info | kv EVENT_SEQ)
off=$(ctl ue 2 power off --switch-off --wait 10s)
rel=$(ctl wait ran.ue.released --since "$seq" --timeout 10s | kv EVENT)
row ksim-p1.switch-off '^switch_off=1 released=ran.ue.released$' \
    "switch_off=$(printf '%s\n' "$off" | kv SWITCH_OFF) released=$rel"

summary ksim-p1-reg
