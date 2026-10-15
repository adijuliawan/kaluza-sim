#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The DN-side ping for the lab gates (P1 N18; kaluza-core-df, 2026-10-15): a
# downlink to an idle UE has to come through the V-UPF's N6, and on the lab
# only the dev PC is on that path (VLAN 61, 172.30.61.1); kaluza-uesim is not.
# Run on the dev PC for a window only:
#
#   tools/lab-dn-relay.sh [--host kaluza-uesim]
#
# It follows ~/ksim-dn/req on the VM, where gates/lib/dn-ping-request.sh writes
# "<id> <IPv4>", and for each pings the address six times (ping -c6 -W3, the
# core gates' trigger) and appends "<id> <rc>" to ~/ksim-dn/done. It pings
# nothing but an address in kaluza-core's internet pool 10.45.0.0/16 whose
# route leaves through lab-trunk.61; anything else is refused. Ctrl-C ends it.
set -u
host=kaluza-uesim
[ "${1:-}" = --host ] && host="${2:?--host needs a name}"
vm() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" "$@"; }
vm 'mkdir -p ~/ksim-dn && : > ~/ksim-dn/req && : > ~/ksim-dn/done' || exit 1
echo "DN_RELAY=up host=$host"
vm 'exec tail -n0 -F ~/ksim-dn/req 2>/dev/null' | while read -r id ip; do
    case "$id" in *[!0-9]*|'') continue ;; esac
    ok=0
    if printf '%s\n' "$ip" | grep -Eq '^10\.45\.([0-9]{1,3})\.([0-9]{1,3})$' &&
        ip route get "$ip" 2>/dev/null | head -n 1 | grep -q ' dev lab-trunk\.61 '; then
        ok=1
    fi
    if [ "$ok" = 1 ]; then
        ping -c6 -W3 "$ip" >/dev/null 2>&1
        rc=$?
    else
        rc=refused
    fi
    vm "echo '$id $rc' >> ~/ksim-dn/done"
    echo "DN_RELAY: $id $ip rc=$rc"
done
