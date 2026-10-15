# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The gate library (P1 N8; ADR 0009 point 9; verification.md section 6). POSIX sh,
# sourced by gates/verification/*.sh. A gate drives a running ksim through
# ksim-ctl and scores rows from the sim's own evidence: events (ksim-ctl wait),
# ksim-ctl output and the run's pcaps. Rows print in kaluza-core's format
#   '  PASS  <row text> got=<evidence>'
# with the row text taken verbatim from the phase's row set by row id (the
# UE_IMPL parity contract): gates/rows/p1.tsv, or gates/rows/p2.tsv when
# KSIM_ROWS names it (P2 Q0; it carries the P1 rows with the same text).
# Each row is appended to <run>/rows.tsv as
#   <row id> TAB <PASS|FAIL|SKIP|ALLOWED> TAB <core> TAB <got>
# for tools/p1_exit.py and tools/p2_exit.py. On Open5GS a FAIL that gates/allow/open5gs.tsv lists for
# the row is scored ALLOWED (ADR 0010 point 3).
#
# The caller sets RUN (the run directory), CORE (stub, open5gs or kaluza) and
# optionally KSIM_CTL (default: ksim-ctl on PATH) and KSIM_ROOT (the repo).

: "${KSIM_ROOT:=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}"
: "${KSIM_CTL:=ksim-ctl}"
: "${CORE:?CORE is stub, open5gs or kaluza}"
: "${RUN:?RUN is the run directory}"

# The S-NSSAI the gates ask sessions for: the core env's SLICE (the stub's SST 1 by default).
: "${SLICE:=--sst 1}"

pass=0; fail=0; skip=0; allowed=0
ROWS_TSV="$RUN/rows.tsv"
: "${KSIM_ROWS:=$KSIM_ROOT/gates/rows/p1.tsv}"
ROWS_SET="$KSIM_ROWS"
ALLOW="$KSIM_ROOT/gates/allow/$CORE.tsv"

abort() { printf '\nABORT: %s\n' "$1" >&2; exit 3; }

ctl() { "$KSIM_CTL" --run "$RUN" "$@"; }

# P2 Q7, the watchdog: rows are not scored on a run whose loop lagged since the gate
# began (platform.loop_lag; cli.md exit 7, the environment is unsound).
KSIM_GATE_SEQ=$(ctl info 2>/dev/null | sed -n 's/^EVENT_SEQ=//p' | head -n 1)
: "${KSIM_GATE_SEQ:=0}"
lag_guard() {
    if _lag=$(ctl wait platform.loop_lag --since "$KSIM_GATE_SEQ" --timeout 1ms 2>/dev/null) &&
        printf '%s\n' "$_lag" | grep -q '^EVENT=platform.loop_lag$'; then
        printf '\nABORT: the run lagged (%s ms late, threshold %s ms): its rows are not scored\n' \
            "$(printf '%s\n' "$_lag" | sed -n 's/^LAG_MS=//p')" "$(printf '%s\n' "$_lag" | sed -n 's/^THRESHOLD_MS=//p')" >&2
        exit 7
    fi
}

# kv KEY: the first KEY=value of the text on stdin.
kv() { sed -n "s/^$1=//p" | head -n 1; }

# row_text ID: the row's text in the phase's row set.
row_text() {
    awk -F '\t' -v id="$1" '$1 == id { print $4; found = 1; exit } END { if (!found) exit 1 }' "$ROWS_SET"
}

# allow_id ID: the allow entry for the row on this core, if any; on an interop run
# (P2 Q5, ADR 0012 point 7) also the peer's for the run's mode: a gate sets
# PEER_ALLOW (gates/allow/<peer>.tsv, whose third column lists the modes) and
# PEER_MODE (C3, C4 or C5).
allow_id() {
    if [ -f "$ALLOW" ] &&
        awk -F '\t' -v id="$1" '$1 !~ /^#/ && $2 == id { print $1; found = 1; exit } END { if (!found) exit 1 }' "$ALLOW"; then
        return 0
    fi
    [ -n "${PEER_ALLOW:-}" ] && [ -f "$PEER_ALLOW" ] && [ -n "${PEER_MODE:-}" ] || return 1
    awk -F '\t' -v id="$1" -v mode="$PEER_MODE" \
        '$1 !~ /^#/ && $2 == id && index("," $3 ",", "," mode ",") { print $1; found = 1; exit } END { if (!found) exit 1 }' "$PEER_ALLOW"
}

record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$CORE" "$3" >> "$ROWS_TSV"; }

# The run's mode for gates/rows/p2.tsv's modes column (P2 Q5): aio, split, or the
# interop combination the topology's peers make (C3: OCUDU's CU-CP and CU-UP; C4:
# its CU-UP; C5: its CU-CP). Set once, in KSIM_RUN_MODE.
set_run_mode() {
    _info=$(ctl info 2>/dev/null)
    _pcp=$(printf '%s\n' "$_info" | kv PEER_CUCP)
    _pup=$(printf '%s\n' "$_info" | kv PEER_CUUP)
    KSIM_RUN_MODE=aio
    [ "$(printf '%s\n' "$_info" | kv ROLE)" = split ] && KSIM_RUN_MODE=split
    if [ -n "$_pcp" ] && [ -n "$_pup" ]; then
        KSIM_RUN_MODE=C3
    elif [ -n "$_pcp" ]; then
        KSIM_RUN_MODE=C5
    elif [ -n "$_pup" ]; then
        KSIM_RUN_MODE=C4
    fi
}
# row_modes ID: the row's modes ("aio,split,C3"), empty in a row set without a modes
# column (p1.tsv): the column is found by the header row's name.
row_modes() {
    awk -F '\t' -v id="$1" '
        $1 ~ /^#/ { next }
        !col { for (i = 1; i <= NF; i++) if ($i == "modes") col = i; if (!col) exit; next }
        $1 == id { print $col; exit }' "$ROWS_SET"
}

# row ID WANT GOT: PASS when GOT matches the extended regex WANT. A row whose modes
# do not hold the run's is skipped instead (P2 Q5). With ROW_NO_ALLOW=1
# a FAIL is not looked up in the allow-lists (the gate saw it fail for another reason).
row() {
    _id="$1"; _want="$2"; _got="$3"
    lag_guard
    _text=$(row_text "$_id") || abort "row $_id is not in $(basename "$ROWS_SET")"
    _modes=$(row_modes "$_id")
    if [ -n "$_modes" ] && [ "$_modes" != - ]; then
        [ -n "${KSIM_RUN_MODE:-}" ] || set_run_mode
        case ",$_modes," in
            *",$KSIM_RUN_MODE,"*) ;;
            *)
                skip=$((skip + 1)); printf '  SKIP  %-66s %s\n' "$_text" "not a $KSIM_RUN_MODE row (modes $_modes)"
                record "$_id" SKIP "not a $KSIM_RUN_MODE row (modes $_modes)"
                return 0
                ;;
        esac
    fi
    if printf '%s\n' "$_got" | grep -Eq -- "$_want"; then
        pass=$((pass + 1)); printf '  PASS  %-66s got=%s\n' "$_text" "$_got"; record "$_id" PASS "$_got"
    elif [ "${ROW_NO_ALLOW:-0}" != 1 ] && _allow=$(allow_id "$_id"); then
        allowed=$((allowed + 1)); printf '  ALLOW %-66s got=%s (%s)\n' "$_text" "$_got" "$_allow"
        record "$_id" ALLOWED "$_got ($_allow)"
    else
        fail=$((fail + 1)); printf '  FAIL  %-66s got=%s want~%s\n' "$_text" "$_got" "$_want"; record "$_id" FAIL "$_got"
    fi
}

# skip_row ID WHY
skip_row() {
    _text=$(row_text "$1") || abort "row $1 is not in $(basename "$ROWS_SET")"
    skip=$((skip + 1)); printf '  SKIP  %-66s %s\n' "$_text" "$2"; record "$1" SKIP "$2"
}

# release_all UE: releases each of the UE's PDU sessions before it de-registers, so
# no PFCP session is left behind on a real core (agreed with kaluza-core for W1).
release_all() {
    for _psi in $(ctl ue "$1" ps-list | sed -n 's/^PS\.\([0-9][0-9]*\)\.DNN=.*/\1/p'); do
        ctl ue "$1" ps-release "$_psi" --wait 15s >/dev/null || echo "   UE $1: PSI $_psi not released"
    done
}

# summary NAME: prints the totals; the gate's exit status is 0 with no FAIL.
summary() {
    lag_guard
    printf '\n== %s: %d passed, %d failed, %d skipped, %d allowed ==\n' "$1" "$pass" "$fail" "$skip" "$allowed"
    [ "$fail" -eq 0 ]
}

# tshark_fields PCAP FILTER FIELD...: one line per matching frame, fields tab-separated.
# The capture goes in on stdin (AppArmor keeps tshark out of ~/Development).
tshark_fields() {
    _pcap="$1"; _filter="$2"; shift 2
    _args=""
    for _f in "$@"; do _args="$_args -e $_f"; done
    # shellcheck disable=SC2086
    tshark -r - -Y "$_filter" -T fields $_args < "$_pcap" 2>/dev/null
}
