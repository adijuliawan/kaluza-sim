#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P1 SMS gate (P1 N13): SMS over NAS between two UEs, as kaluza-core's
# smsf gate scores it: SMS requested and allowed (or not) at registration, an
# MO SMS-SUBMIT relayed to the other UE as an SMS-DELIVER with the same TP-UD,
# what that takes on the air, UCS2, a concatenated message, MT to an idle UE
# through paging, MO from idle, and a UE without SMS sending nothing. Rows of
# gates/rows/p1.tsv whose milestone is N13. MT is UE to UE (D7).
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza [STUB_CTL=<stub socket>] gates/verification/ksim-p1-sms.sh
#   [SMS_UE1=, SMS_UE2=, NOSMS_UE3=]   the UEs (default 10, 11 and 12): two with SMS in
#                                      the subscription, one without (the stub is told so)
#
# Each must be off at the start.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

command -v tshark >/dev/null 2>&1 || abort "tshark is needed for the pcap rows"
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
: "${SMS_UE1:=10}"
: "${SMS_UE2:=11}"
: "${NOSMS_UE3:=12}"
GNB=$(ctl info | kv GNB)
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }
# The sim range's MSISDN: 999 and the MSIN's last eight digits.
msisdn() { printf '999%s\n' "$(printf '%s' "$1" | sed 's/^imsi-//' | cut -c8-15)"; }
supi_of() { ctl ue "$1" status | kv UE; }

release() {
    _seq=$(ctl info | kv EVENT_SEQ)
    ctl gnb "$GNB" ue-release "$1" >/dev/null || abort "gnb ue-release $1 refused"
    ctl ue "$1" wait nas.mm.cm_idle --since "$_seq" --timeout 10s >/dev/null || abort "UE $1 not idle"
    ctl wait ran.ue.released --since "$_seq" --timeout 10s >/dev/null
}

echo "-- registration: two UEs with SMS, one without"
if on_stub; then
    s3=$(printf '%s' "$(ctl ues | kv "UE.$NOSMS_UE3")" | sed 's/^imsi-//')
    stub sms-sub --ue "$s3" --off >/dev/null || abort "the stub did not take sms-sub"
fi
seq0=$(ctl info | kv EVENT_SEQ)
for u in "$SMS_UE1" "$SMS_UE2" "$NOSMS_UE3"; do
    r=$(ctl ue "$u" power on --wait 30s)
    [ "$(printf '%s\n' "$r" | kv RESULT)" = ACCEPT ] || abort "UE $u did not register"
done
ue1=$(supi_of "$SMS_UE1"); ue2=$(supi_of "$SMS_UE2"); ue3=$(supi_of "$NOSMS_UE3")
acc() { ctl ue "$1" wait nas.reg.accept --since "$seq0" --timeout 5s | kv SMS_ALLOWED; }
a1=$(acc "$SMS_UE1"); a2=$(acc "$SMS_UE2"); a3=$(acc "$NOSMS_UE3")
row smsf.010 '^registered$' "$(ctl ue "$SMS_UE1" status | kv RM_STATE | sed 's/RM-REGISTERED/registered/')"
row smsf.011 '^registered$' "$(ctl ue "$SMS_UE2" status | kv RM_STATE | sed 's/RM-REGISTERED/registered/')"
row smsf.012 '^registered$' "$(ctl ue "$NOSMS_UE3" status | kv RM_STATE | sed 's/RM-REGISTERED/registered/')"
# On the wire: the full REGISTRATION REQUEST (in the SECURITY MODE COMPLETE's
# container when the UE had no context) asks for SMS; each accept answers.
req_sms() { tshark_fields "$RUN/uu.pcapng" "nas-5gs.mm.sms_requested == 1 && frame.comment contains \"$1\"" frame.number | wc -l; }
acc_sms() { tshark_fields "$RUN/uu.pcapng" "nas-5gs.mm.message_type == 0x42 && frame.comment contains \"$1\"" nas-5gs.mm.reg_res.sms_all | tail -n 1; }
row smsf.013 '^1=[1-9][0-9]* 2=[1-9][0-9]* 3=[1-9][0-9]*$' "1=$(req_sms "$ue1") 2=$(req_sms "$ue2") 3=$(req_sms "$ue3")"
row smsf.014 '^1=(1|True) 2=(1|True) 3=(0|False)$' "1=$(acc_sms "$ue1") 2=$(acc_sms "$ue2") 3=$(acc_sms "$ue3")"
row smsf.015 '^sms_allowed=1$' "sms_allowed=$a1"
row smsf.019 '^sms_allowed=0 registered$' "sms_allowed=$a3 $(ctl ue "$NOSMS_UE3" status | kv RM_STATE | sed 's/RM-REGISTERED/registered/')"

echo "-- the UE without SMS sends nothing"
seq=$(ctl info | kv EVENT_SEQ)
ctl ue "$NOSMS_UE3" sms-send "$(msisdn "$ue1")" "not allowed" >/dev/null 2>&1
rc=$?
ctl ue "$NOSMS_UE3" wait sms.cp.data --since "$seq" --timeout 1ms >/dev/null 2>&1
cp=$?   # 3: none
row ksim-p1.sms-not-allowed '^exit=6 cp_data=none$' "exit=$rc cp_data=$([ "$cp" -eq 3 ] && echo none || echo sent)"

echo "-- requested again"
if on_stub; then
    stub sms-sub --ue "$(printf '%s' "$ue3" | sed 's/^imsi-//')" >/dev/null
    up=$(ctl ue "$NOSMS_UE3" register --update --wait 15s)
    row smsf.022 '^ACCEPT sms_allowed=1$' "$(printf '%s\n' "$up" | kv RESULT) sms_allowed=$(printf '%s\n' "$up" | kv SMS_ALLOWED)"
else
    skip_row smsf.022 "needs SMS added to the subscription on $CORE (no trigger in P1)"
fi

echo "-- UE 1 to UE 2"
TEXT="ksim sms test $(date +%s)"
f0=$(tshark_fields "$RUN/uu.pcapng" "frame" frame.number | tail -n 1)
seq=$(ctl info | kv EVENT_SEQ)
snd=$(ctl ue "$SMS_UE1" sms-send "$(msisdn "$ue2")" "$TEXT" --wait 20s)
src=$?
row smsf.023 '^exit=0$' "exit=$src"
ack=$(ctl ue "$SMS_UE1" wait sms.rp.ack --since "$seq" --where dir=dl --timeout 10s | kv EVENT)
row smsf.024 '^sms.rp.ack$' "$ack"
dlv=$(ctl ue "$SMS_UE2" wait sms.mt.deliver --since "$seq" --timeout 20s)
sub=$(ctl ue "$SMS_UE1" wait sms.mo.submit --since "$seq" --timeout 1s | kv UD)
sleep 1   # the final CP-ACKs
n=$(ctl ue "$ue2" events --since "$seq" 2>/dev/null | grep -c '"sms.mt.deliver"')
row smsf.025 "^delivered=1 text=$TEXT\$" "delivered=$n text=$(printf '%s\n' "$dlv" | kv TEXT)"
row smsf.026 '^same=1$' "same=$([ -n "$sub" ] && [ "$sub" = "$(printf '%s\n' "$dlv" | kv UD)" ] && echo 1 || echo 0)"
# The air of this one message, both UEs' frames after f0.
mine="frame.number > ${f0:-0} && (frame.comment contains \"$ue1\" || frame.comment contains \"$ue2\")"
cpd=$(tshark_fields "$RUN/uu.pcapng" "gsm_a.dtap.msg_sms_type == 0x01 && $mine" frame.number | wc -l)
cpa=$(tshark_fields "$RUN/uu.pcapng" "gsm_a.dtap.msg_sms_type == 0x04 && $mine" frame.number | wc -l)
row smsf.028 '^cp_data=4 cp_ack=4$' "cp_data=$cpd cp_ack=$cpa"
rpt=$(tshark_fields "$RUN/uu.pcapng" "gsm_a.rp.msg_type && $mine" gsm_a.rp.msg_type | sort | tr '\n' ',' | sed 's/,$//')
row smsf.029 '^0x00,0x01,0x02,0x03$' "$rpt"
# The TPDUs of the RP-DATA (types 0 and 1): an RP-ACK may carry a report TPDU
# too (TS 24.011 7.3.3; kaluza-core's carries an SMS-SUBMIT-REPORT, W2).
tps=$(tshark_fields "$RUN/uu.pcapng" "gsm_a.rp.msg_type <= 1 && gsm_sms.tp-mti && $mine" gsm_sms.tp-mti | sort | tr '\n' ',' | sed 's/,$//')
txt=$(tshark_fields "$RUN/uu.pcapng" "gsm_a.rp.msg_type == 1 && gsm_sms.tp-mti == 0 && $mine" gsm_sms.sms_text | head -n 1)
row smsf.030 "^tpdu=0,1 text=$TEXT\$" "tpdu=$tps text=$txt"
mal=$(tshark_fields "$RUN/uu.pcapng" "_ws.malformed && $mine" frame.number | wc -l)
row smsf.031 '^malformed=0$' "malformed=$mal"

echo "-- UCS2 (Korean)"
seq=$(ctl info | kv EVENT_SEQ)
KOR="안녕하세요 ksim"
ctl ue "$SMS_UE1" sms-send "$(msisdn "$ue2")" "$KOR" --ucs2 --wait 20s >/dev/null
d=$(ctl ue "$SMS_UE2" wait sms.mt.deliver --since "$seq" --timeout 20s)
row smsf.032 "^dcs=8 text=$KOR\$" "dcs=$(printf '%s\n' "$d" | kv DCS) text=$(printf '%s\n' "$d" | kv TEXT)"

echo "-- concatenated"
seq=$(ctl info | kv EVENT_SEQ)
LONG=$(awk 'BEGIN { for (i = 0; i < 9; i++) printf "concatenated part of a long ksim message %d. ", i }')
ctl ue "$SMS_UE1" sms-send "$(msisdn "$ue2")" "$LONG" --wait 20s >/dev/null
ctl ue "$SMS_UE2" wait sms.mt.deliver --since "$seq" --where concat=3/3 --timeout 30s >/dev/null
sleep 1
cat=$(ctl ue "$ue2" events --since "$seq" 2>/dev/null | grep '"sms.mt.deliver"' | grep -c '"concat":"[123]/3"')
row smsf.034 '^delivers=3$' "delivers=$cat"

echo "-- MT to an idle UE"
release "$SMS_UE2"
seq=$(ctl info | kv EVENT_SEQ)
ctl ue "$SMS_UE1" sms-send "$(msisdn "$ue2")" "to the idle UE" --wait 20s >/dev/null
pg=$(ctl wait ran.ngap.paging --since "$seq" --timeout 10s | kv EVENT)
row smsf.035 '^ran.ngap.paging$' "$pg"
sr=$(ctl ue "$SMS_UE2" wait nas.sr.request --since "$seq" --timeout 10s | kv SEQ)
dl=$(ctl ue "$SMS_UE2" wait sms.mt.deliver --since "$seq" --timeout 20s)
sleep 1
n=$(ctl ue "$ue2" events --since "$seq" 2>/dev/null | grep -c '"sms.mt.deliver"')
row smsf.036 '^sr_first=1 delivered=1$' \
    "sr_first=$([ -n "$sr" ] && [ "$sr" -lt "$(printf '%s\n' "$dl" | kv SEQ)" ] && echo 1 || echo 0) delivered=$n"

echo "-- MO from idle"
release "$SMS_UE1"
seq=$(ctl info | kv EVENT_SEQ)
ctl ue "$SMS_UE1" sms-send "$(msisdn "$ue2")" "from the idle UE" --wait 20s >/dev/null
sr=$(ctl ue "$SMS_UE1" wait nas.sr.request --since "$seq" --timeout 10s | kv SEQ)
ack=$(ctl ue "$SMS_UE1" wait sms.rp.ack --since "$seq" --where dir=dl --timeout 10s | kv SEQ)
ctl ue "$SMS_UE2" wait sms.mt.deliver --since "$seq" --timeout 20s >/dev/null
sleep 1
n=$(ctl ue "$ue2" events --since "$seq" 2>/dev/null | grep -c '"sms.mt.deliver"')
row smsf.037 '^sr_first=1 delivered=1$' \
    "sr_first=$([ -n "$sr" ] && [ -n "$ack" ] && [ "$sr" -lt "$ack" ] && echo 1 || echo 0) delivered=$n"

for u in "$SMS_UE1" "$SMS_UE2" "$NOSMS_UE3"; do
    release_all "$u"
    ctl ue "$u" power off --switch-off --wait 10s >/dev/null
done
summary ksim-p1-sms
