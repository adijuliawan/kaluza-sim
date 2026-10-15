# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The gate library (P1 N8; ADR 0009 point 9; verification.md section 6). POSIX sh,
# sourced by gates/verification/*.sh. A gate drives a running ksim through
# ksim-ctl and scores rows from the sim's own evidence: events (ksim-ctl wait),
# ksim-ctl output and the run's pcaps. Rows print in kaluza-core's format
#   '  PASS  <row text> got=<evidence>'
# with the row text taken verbatim from gates/rows/p1.tsv by row id (the
# UE_IMPL parity contract), and each row is appended to <run>/rows.tsv as
#   <row id> TAB <PASS|FAIL|SKIP|ALLOWED> TAB <core> TAB <got>
# for tools/p1_exit.py. On Open5GS a FAIL that gates/allow/open5gs.tsv lists for
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
P1_ROWS="$KSIM_ROOT/gates/rows/p1.tsv"
ALLOW="$KSIM_ROOT/gates/allow/$CORE.tsv"

abort() { printf '\nABORT: %s\n' "$1" >&2; exit 3; }

ctl() { "$KSIM_CTL" --run "$RUN" "$@"; }

# kv KEY: the first KEY=value of the text on stdin.
kv() { sed -n "s/^$1=//p" | head -n 1; }

# row_text ID: the row's text in gates/rows/p1.tsv.
row_text() {
    awk -F '\t' -v id="$1" '$1 == id { print $4; found = 1; exit } END { if (!found) exit 1 }' "$P1_ROWS"
}

# allow_id ID: the allow entry for the row on this core, if any.
allow_id() {
    [ -f "$ALLOW" ] || return 1
    awk -F '\t' -v id="$1" '$1 !~ /^#/ && $2 == id { print $1; found = 1; exit } END { if (!found) exit 1 }' "$ALLOW"
}

record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$CORE" "$3" >> "$ROWS_TSV"; }

# row ID WANT GOT: PASS when GOT matches the extended regex WANT.
row() {
    _id="$1"; _want="$2"; _got="$3"
    _text=$(row_text "$_id") || abort "row $_id is not in gates/rows/p1.tsv"
    if printf '%s\n' "$_got" | grep -Eq -- "$_want"; then
        pass=$((pass + 1)); printf '  PASS  %-66s got=%s\n' "$_text" "$_got"; record "$_id" PASS "$_got"
    elif _allow=$(allow_id "$_id"); then
        allowed=$((allowed + 1)); printf '  ALLOW %-66s got=%s (%s)\n' "$_text" "$_got" "$_allow"
        record "$_id" ALLOWED "$_got ($_allow)"
    else
        fail=$((fail + 1)); printf '  FAIL  %-66s got=%s want~%s\n' "$_text" "$_got" "$_want"; record "$_id" FAIL "$_got"
    fi
}

# skip_row ID WHY
skip_row() {
    _text=$(row_text "$1") || abort "row $1 is not in gates/rows/p1.tsv"
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
