#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The UP security policy gate (P2 Q9; TS 38.413 8.2.1.2, TS 33.501 6.6.1). Rows of
# gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q9:
#   ksim-p2.up-integrity-required        required: the DRB carries a MAC-I both ways
#   ksim-p2.up-integrity-preferred       preferred: the CU-CP's local policy, reported in
#                                        the Security Result
#   ksim-p2.up-confidentiality-not-needed  not-needed: unciphered at both ends (cipheringDisabled)
#   ksim-p2.up-required-unmet            required integrity the gNB cannot do: refused with
#                                        the TS 38.413 cause
#   ksim-p2.up-indication-absent         no Security Indication: the CU-CP's default, and an event
# The stub's SMF sends what each row needs (ksim-ctl stub up-policy) and the CU-CP's local
# policy is set for it (ksim-ctl gnb <name> up-policy). On kaluza-core, whose SMF sends no
# Security Indication, only the last row runs. Every session is released and every UE
# switched off at the end; the stub's and the CU-CP's policies are put back.
#
#   RUN=<run dir> CORE=stub|kaluza gates/verification/ksim-p2-up.sh
#
# UE UP_UE (default 5).

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
GNB=$(ctl info | kv GNB)
: "${UP_UE:=5}"
u=$UP_UE
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }
policy() { ctl gnb "$GNB" up-policy "$@" >/dev/null || abort "the CU-CP took no up-policy"; }

off() {
    release_all "$u"
    ctl ue "$u" power off --switch-off --wait 10s >/dev/null 2>&1
    ctl ue "$u" power off --abrupt >/dev/null 2>&1
}
# session: registers the UE and sets a session up; prints the ran.up.security fields and
# the pings received, as "indication=… integrity=… confidentiality=… cuup_i=… cuup_c=… received=…"
session() {
    _seq=$(ctl info | kv EVENT_SEQ)
    ctl ue "$u" power on --wait 30s >/dev/null || { echo "registered=0"; return; }
    _psi=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
    _up=$(ctl wait ran.up.security --since "$_seq" --timeout 5s)
    _bc=$(ctl wait ran.cuup.bearer.setup --since "$_seq" --timeout 5s)
    _rx=0
    [ -n "$_psi" ] && _rx=$(ctl ue "$u" ping "${DN_ADDR:-10.60.0.1}" --psi "$_psi" -c 3 --interval 200 | kv RECEIVED)
    echo "indication=$(printf '%s\n' "$_up" | kv INDICATION) integrity=$(printf '%s\n' "$_up" | kv INTEGRITY)" \
         "confidentiality=$(printf '%s\n' "$_up" | kv CONFIDENTIALITY) cuup_i=$(printf '%s\n' "$_bc" | kv INTEGRITY)" \
         "cuup_c=$(printf '%s\n' "$_bc" | kv CIPHERING) received=${_rx:-0}"
}
field() { printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"; }

if ! on_stub; then
    for id in ksim-p2.up-integrity-required ksim-p2.up-integrity-preferred ksim-p2.up-confidentiality-not-needed \
              ksim-p2.up-required-unmet; do
        skip_row "$id" "the SMF's Security Indication is the core's ($CORE): only the stub's can be set"
    done
else
    off

    echo "-- integrity required (UE $u)"
    stub up-policy --integrity required --confidentiality required >/dev/null || abort "the stub took no up-policy"
    got=$(session)
    row ksim-p2.up-integrity-required '^integrity=1 cuup_i=1 received=[1-9]$' \
        "integrity=$(field "$got" integrity) cuup_i=$(field "$got" cuup_i) received=$(field "$got" received)"
    off

    echo "-- integrity preferred, the CU-CP's policy: not performed (UE $u)"
    policy --preferred-integrity 0
    stub up-policy --integrity preferred --confidentiality required >/dev/null
    got=$(session)
    # The Security Result of the last PDU SESSION RESOURCE SETUP RESPONSE (0 performed, 1 not).
    res=$(tshark_fields "$RUN/ngap.pcapng" "ngap.integrityProtectionResult" ngap.integrityProtectionResult | tail -n 1)
    case "$res" in 0) res=performed ;; 1) res=not-performed ;; *) res=none ;; esac
    row ksim-p2.up-integrity-preferred '^integrity=0 result=not-performed received=[1-9]$' \
        "integrity=$(field "$got" integrity) result=$res received=$(field "$got" received)"
    off
    policy --preferred-integrity 1

    echo "-- confidentiality not needed (UE $u)"
    stub up-policy --integrity not-needed --confidentiality not-needed >/dev/null
    got=$(session)
    disabled=$(tshark_fields "$RUN/uu.pcapng" "nr-rrc.cipheringDisabled" frame.number | wc -l)
    row ksim-p2.up-confidentiality-not-needed '^confidentiality=0 cuup_c=0 ue_disabled=[1-9][0-9]* received=[1-9]$' \
        "confidentiality=$(field "$got" confidentiality) cuup_c=$(field "$got" cuup_c) ue_disabled=$disabled received=$(field "$got" received)"
    off

    echo "-- integrity required, this gNB cannot (UE $u)"
    policy --integrity-possible 0
    stub up-policy --integrity required --confidentiality required >/dev/null
    seq=$(ctl info | kv EVENT_SEQ)
    ctl ue "$u" power on --wait 30s >/dev/null || abort "UE $u did not register"
    ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 5s >/dev/null 2>&1   # no accept comes
    result=$(ctl wait ran.up.security --since "$seq" --timeout 5s | kv RESULT)
    refused=$(tshark_fields "$RUN/ngap.pcapng" "ngap.PDUSessionResourceFailedToSetupItemSURes_element" frame.number | wc -l)
    row ksim-p2.up-required-unmet '^result=up-integrity-protection-not-possible refused=[1-9][0-9]*$' \
        "result=${result:-none} refused=$refused"
    ctl ue "$u" power off --abrupt >/dev/null 2>&1   # its establishment still waits
    policy --integrity-possible 1
fi

echo "-- no Security Indication (UE $u)"
on_stub && stub up-policy --integrity absent --confidentiality required >/dev/null
off
got=$(session)
row ksim-p2.up-indication-absent '^indication=absent integrity=[01] confidentiality=[01] received=[1-9]$' \
    "indication=$(field "$got" indication) integrity=$(field "$got" integrity) confidentiality=$(field "$got" confidentiality) received=$(field "$got" received)"
off
on_stub && stub up-policy --integrity not-needed --confidentiality required >/dev/null

summary "ksim-p2-up"
