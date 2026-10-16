#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The quiet split run (P2 Q7, KS-PLAT-D14): a gate script for gates/run.sh that leaves
# a split run with nothing to do for QUIET_S (default 100) seconds, longer than the
# ~80 s that once filled a quiet role's 16 server threads with followers that had
# left, then times a call to each role through the supervisor and counts each
# role's connections on its control socket. Prints QUIET_SPLIT=PASS when every call
# answers within 2 s and no role holds more than 3 connections; exit 1 otherwise.
#
#   gates/run.sh stub tools/quiet_split_check.sh      (a split topology)
set -u
. "$KSIM_ROOT/gates/lib/ksim.sh"
: "${QUIET_S:=100}"
[ "$(ctl info | kv ROLE)" = split ] || { echo "QUIET_SPLIT=SKIP (not a split run)"; exit 0; }
GNB=$(ctl info | kv GNB)
sleep "$QUIET_S"
bad=0
for q in info ues "ue 1 status" "gnb $GNB ue-list" "du $GNB-du ue-list"; do
    s=$(date +%s%N)
    # shellcheck disable=SC2086
    ctl $q >/dev/null 2>&1
    rc=$?
    ms=$(( ($(date +%s%N) - s) / 1000000 ))
    echo "QUIET_CALL [$q] rc=$rc ${ms} ms"
    { [ "$rc" -eq 0 ] && [ "$ms" -le 2000 ]; } || bad=1
done
for role in cucp cuup du ue; do
    n=$(ss -xn 2>/dev/null | grep -c "$RUN/$role/ctl.sock")
    echo "QUIET_CONNECTIONS $role=$n"
    [ "$n" -le 3 ] || bad=1
done
[ "$bad" = 0 ] && { echo "QUIET_SPLIT=PASS after ${QUIET_S} s"; exit 0; }
echo "QUIET_SPLIT=FAIL after ${QUIET_S} s"
exit 1
