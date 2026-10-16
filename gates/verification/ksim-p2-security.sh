#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The AS and NAS security gate (P2 Q8; TS 33.501 6.7, D.2-D.4). Rows of
# gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q8:
#   ksim-p2.as-nea1-nia1   our CU-CP preferring NEA1/NIA1 (a *-nea1 topology) selects
#                          them, and SRB1, SRB2 and the DRB verify (mutant nia1_wrong_fresh)
#   ksim-p2.nas-nea1-nia1  the stub's AMF selecting EA1/IA1 (ksim-ctl stub nas-alg),
#                          the UE protects and verifies NAS with them
#   ksim-p2.ocudu-nea1     C3 with nea1 and nia1 first in OCUDU's lists (OCUDU_NEA_PREF,
#                          OCUDU_NIA_PREF for tools/ocudu-peer.sh): the UE ran on them
# Each row is skipped where its precondition does not hold. Every session is
# released and every UE switched off at the end.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p2-security.sh
#
# topology: topologies/aio-stub-nea1.yaml
# UEs AS_UE (default 3), NAS_UE (default 4).

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
info=$(ctl info)
nea=$(printf '%s\n' "$info" | kv AS_NEA)
nia=$(printf '%s\n' "$info" | kv AS_NIA)
pcp=$(printf '%s\n' "$info" | kv PEER_CUCP)
: "${AS_UE:=3}"
: "${NAS_UE:=4}"
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
on_stub() { [ "$CORE" = stub ] && [ -n "${STUB_CTL:-}" ]; }

off() {   # $1 = UE: sessions released, then switched off (or off, when not registered)
    release_all "$1"
    ctl ue "$1" power off --switch-off --wait 10s >/dev/null 2>&1
    ctl ue "$1" power off --abrupt >/dev/null 2>&1
}

# as_run ROW UE: registers the UE, then a session and a ping over the DRB; prints
# "alg=<rrc.smc.complete ALG> received=<n> failures=<UE + CU-CP SRB integrity failures>"
as_run() {
    _u=$2
    _seq=$(ctl info | kv EVENT_SEQ)
    ctl ue "$_u" power on --wait 30s >/dev/null || { echo "registered=0"; return; }
    _alg=$(ctl ue "$_u" wait rrc.smc.complete --since "$_seq" --timeout 10s | kv ALG)
    _psi=$(ctl ue "$_u" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)   # NAS over SRB2
    _rx=0
    [ -n "$_psi" ] && _rx=$(ctl ue "$_u" ping "${DN_ADDR:-10.60.0.1}" --psi "$_psi" -c 3 --interval 200 | kv RECEIVED)
    _f=0
    ctl ue "$_u" wait rrc.integrity_failure --since "$_seq" --timeout 1ms >/dev/null 2>&1 && _f=$((_f + 1))
    ctl wait ran.rrc.integrity_failure --since "$_seq" --timeout 1ms >/dev/null 2>&1 && _f=$((_f + 1))
    echo "alg=${_alg:-none} received=${_rx:-0} failures=$_f"
    off "$_u"
}

echo "-- AS: NEA1 and NIA1 first at our CU-CP (UE $AS_UE)"
if [ -n "$pcp" ]; then
    skip_row ksim-p2.as-nea1-nia1 "the CU-CP is the peer's ($pcp)"
elif [ "${nea%%,*}" != 1 ] || [ "${nia%%,*}" != 1 ]; then
    skip_row ksim-p2.as-nea1-nia1 "our CU-CP prefers NEA ${nea:-?} and NIA ${nia:-?} (a *-nea1 topology puts 1 first)"
else
    off "$AS_UE"
    got=$(as_run ksim-p2.as-nea1-nia1 "$AS_UE")
    row ksim-p2.as-nea1-nia1 '^alg=nia1/nea1 received=[1-9] failures=0$' "$got"
fi

echo "-- NAS: EA1 and IA1 from the stub's AMF (UE $NAS_UE)"
if [ -n "$pcp" ]; then
    skip_row ksim-p2.nas-nea1-nia1 "not an aio or split run (the CU-CP is the peer's)"
elif ! on_stub; then
    skip_row ksim-p2.nas-nea1-nia1 "the NAS algorithms are the core's ($CORE): only the stub's can be set"
else
    off "$NAS_UE"
    stub nas-alg --ea 1 --ia 1 >/dev/null || abort "the stub did not take nas-alg"
    seq=$(ctl info | kv EVENT_SEQ)
    reg=$(ctl ue "$NAS_UE" power on --wait 30s | kv RESULT)
    smc=$(ctl ue "$NAS_UE" wait nas.smc.complete --since "$seq" --timeout 10s)
    ea=$(printf '%s\n' "$smc" | kv EA)
    ia=$(printf '%s\n' "$smc" | kv IA)
    # NAS both ways under EA1/IA1: a session asked and accepted, then released.
    psi=$(ctl ue "$NAS_UE" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
    rel=none
    [ -n "$psi" ] && rel=$(ctl ue "$NAS_UE" ps-release "$psi" --wait 15s | kv RESULT)
    # The command on the wire: the NAS security algorithms IE of the SECURITY MODE COMMAND.
    sel=$(tshark_fields "$RUN/ngap.pcapng" "nas-5gs.mm.message_type == 0x5d" \
        nas-5gs.mm.nas_sec_algo_enc nas-5gs.mm.nas_sec_algo_ip | tail -n 1 | tr '\t' ',')
    stub nas-alg --ea 2 --ia 2 >/dev/null
    row ksim-p2.nas-nea1-nia1 '^reg=ACCEPT ea=1 ia=1 session=[0-9]+ released=ACCEPT wire=1,1$' \
        "reg=${reg:-none} ea=${ea:-?} ia=${ia:-?} session=${psi:-none} released=${rel:-none} wire=${sel:-none}"
    off "$NAS_UE"
fi

echo "-- C3: nea1 and nia1 first at OCUDU's CU-CP (UE $AS_UE)"
if [ "$pcp" != ocudu ]; then
    skip_row ksim-p2.ocudu-nea1 "not a C3 run"
elif [ "${OCUDU_NEA_PREF:-}" = "" ] || [ "${OCUDU_NEA_PREF%%,*}" != nea1 ]; then
    skip_row ksim-p2.ocudu-nea1 "OCUDU's lists are its template's (OCUDU_NEA_PREF puts nea1 first)"
else
    off "$AS_UE"
    got=$(as_run ksim-p2.ocudu-nea1 "$AS_UE")
    row ksim-p2.ocudu-nea1 '^alg=nia1/nea1 received=[1-9] failures=0$' "$got"
fi

summary "ksim-p2-security"
