#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# DN_PING for kaluza-core (P1 N18): asks tools/lab-dn-relay.sh, running on the
# dev PC, to ping <IPv4> from the DN side, and waits up to 30 s for its answer.
# Exit 0 when the ping got replies, 1 when not, 3 with no relay listening.
ip="${1:?usage: dn-ping-request.sh <IPv4>}"
d="$HOME/ksim-dn"
[ -f "$d/req" ] || exit 3
id="$(date +%s%N)"
echo "$id $ip" >> "$d/req"
i=0
while [ "$i" -lt 300 ]; do
    rc=$(awk -v id="$id" '$1 == id {print $2}' "$d/done" 2>/dev/null)
    if [ -n "$rc" ]; then
        [ "$rc" = 0 ]
        exit $?
    fi
    sleep 0.1
    i=$((i + 1))
done
exit 3
