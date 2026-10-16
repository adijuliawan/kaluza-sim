#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The rows whose evidence is in an interop peer's own capture (P2): OCUDU writes its
# captures only when it exits, so a gate leaves such a row in <peer dir>/rows-after.tsv
# (gates/lib/ksim.sh, peer_row), and gates/run.sh runs this once the peer has stopped and
# before its captures are redacted. Each line: id, want (an ERE), got with @PEER@, the
# capture's file name, the wall-clock window t0 and t1 (s), the display filter, the field,
# a value map ("20=user-inactivity,…", may be empty) and the run's mode. @PEER@ becomes the
# field of the first frame in the window that matches the filter, named through the map;
# "none" when no frame does. The row is then scored as a gate scores one, into
# $RUN/rows.tsv. Exit 1 when a row fails.
#
#   RUN=<run dir> CORE=<core> KSIM_ROWS=<row set> sh gates/lib/peer_rows.sh <peer dir>

set -u
PEER_DIR="${1:?usage: peer_rows.sh <peer dir>}"
LIST="$PEER_DIR/rows-after.tsv"
[ -f "$LIST" ] || exit 0
# The run has stopped: nothing here asks it anything (ksim.sh's ctl and lag guard see an
# empty answer).
KSIM_CTL=true
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/ksim.sh"

TAB=$(printf '\t')
echo "== the rows from the peer's captures"
while IFS="$TAB" read -r id want got cap t0 t1 filter field map mode; do
    [ -n "$id" ] || continue
    v=none
    if [ -f "$PEER_DIR/$cap" ]; then
        _v=$(tshark_fields "$PEER_DIR/$cap" "frame.time_epoch >= $t0 && frame.time_epoch <= $t1 && ($filter)" "$field" |
            head -n 1 | cut -d, -f1)
        [ -n "$_v" ] && v=$_v
    fi
    if [ -n "$map" ] && [ "$v" != none ]; then
        _n=$(printf '%s\n' "$map" | tr ',' '\n' | sed -n "s/^$v=//p" | head -n 1)
        [ -n "$_n" ] && v=$_n
    fi
    KSIM_RUN_MODE=$mode
    row "$id" "$want" "$(printf '%s\n' "$got" | sed "s|@PEER@|$v|g")"
done < "$LIST"
summary "peer rows"
