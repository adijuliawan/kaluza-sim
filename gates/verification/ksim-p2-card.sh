#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P2 card gate (P2 Q1; sim-uicc.md §5, decision D3): a UE whose card is
# behind PC/SC (pcscd, a vpcd reader or a real card in the OmniKey) or behind
# the card bridge registers and de-registers; the bridge refuses what an
# administrator alone may send; a burn's report says the card was written and
# checked. Rows of gates/rows/p2.tsv (KSIM_ROWS) whose milestone is Q1.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza [CARD_UE=1] [BRIDGE=1] [PROBE_REPORT=<file>]
#   [BURN_REPORT=<file>] [REAL_CARD=1] gates/verification/ksim-p2-card.sh
#
# The run's UE CARD_UE has a pcsc: or bridge: card (topology); BRIDGE=1 says
# it is the bridge's. PROBE_REPORT is tools/vpcd_probe.py's output against the
# bridge, taken before the run (the bridge serves one client at a time), and
# BURN_REPORT ksim-sim burn's. tools/ci.d/57-pcsc.sh runs this gate on vpcd reader 1
# and also runs its mutants (tests/mutants.tsv: pcsc_response_truncated,
# bridge_admin_open), since they need a reader.
# mutants: run by tools/ci.d/57-pcsc.sh

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

: "${CARD_UE:=1}"
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"

if [ -n "${BURN_REPORT:-}" ]; then
    echo "-- the burn"
    burn=$(sed -n 's/^BURN=//p' "$BURN_REPORT")
    check=$(sed -n 's/^AUTH_CHECK=//p' "$BURN_REPORT")
    tries=$(sed -n 's/^ADM1_TRIES_LEFT=//p' "$BURN_REPORT")
    row ksim-p2.burn-verify '^burn=PASS auth=PASS_(RES|AUTS) adm1_tries=[3-9]' "burn=$burn auth=$check adm1_tries=$tries"
fi

if [ -n "${PROBE_REPORT:-}" ]; then
    echo "-- the bridge refuses the administrator's commands"
    adm=$(kv VERIFY_ADM1_SW < "$PROBE_REPORT")
    upd=$(kv UPDATE_AF20_SW < "$PROBE_REPORT")
    pin=$(kv VERIFY_PIN1_STATUS_SW < "$PROBE_REPORT")
    row ksim-p2.bridge-refuses-admin '^verify_adm1=6982 update_af20=6982 pin1_status=(63C[0-9A-F]|9000)$' \
        "verify_adm1=$adm update_af20=$upd pin1_status=$pin"
fi

echo "-- registration with the card behind $([ -n "${BRIDGE:-}" ] && echo the bridge || echo PC/SC) (UE $CARD_UE)"
info=$(ctl ue "$CARD_UE" sim info)
reader=$(printf '%s\n' "$info" | kv READER)
if [ -z "${BRIDGE:-}" ] && [ "${REAL_CARD:-0}" != 1 ] && [ "${reader#pcsc:}" = "$reader" ]; then
    # P2 Q13: a run whose UE has its card in process (a core's whole set): nothing behind PC/SC.
    skip_row ksim-p2.pcsc-register "UE $CARD_UE's card is ${reader:-in process}, not behind PC/SC (the topology's card)"
    summary "ksim-p2-card"
    exit $?
fi
reg=$(ctl ue "$CARD_UE" power on --wait 30s)
complete=$(ctl ue "$CARD_UE" wait nas.reg.complete --timeout 5s | kv EVENT)
got="$reader $(printf '%s\n' "$reg" | kv RESULT) complete=$complete"
if [ -n "${BRIDGE:-}" ] && [ "${REAL_CARD:-0}" = 1 ]; then
    row ksim-p2.real-card-bridge '^bridge:.+ ACCEPT complete=nas.reg.complete$' "$got"
elif [ -n "${BRIDGE:-}" ]; then
    # The soft card behind the bridge (CI): checked here, scored by no row.
    if printf '%s\n' "$got" | grep -Eq '^bridge:.+ ACCEPT complete=nas.reg.complete$'; then
        echo "  CHECK registration through the bridge got=$got"
    else
        fail=$((fail + 1)); echo "  FAIL  registration through the bridge got=$got"
    fi
elif [ "${REAL_CARD:-0}" = 1 ]; then
    row ksim-p2.real-card-register '^pcsc:.+ ACCEPT complete=nas.reg.complete$' "$got"
else
    row ksim-p2.pcsc-register '^pcsc:.+ ACCEPT complete=nas.reg.complete$' "$got"
fi
ctl ue "$CARD_UE" deregister normal --wait 15s >/dev/null || echo "   UE $CARD_UE: no de-registration accept"

summary "ksim-p2-card"
