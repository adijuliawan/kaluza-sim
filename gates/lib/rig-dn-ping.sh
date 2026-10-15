#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# DN_PING for the Open5GS rig (P1 N17): the rig itself is the DN (ogstun,
# 10.45.0.1/16), so the downlink ping to an idle UE runs there over ssh, six
# echoes as the core gates send. Only an address of the internet pool.
ip="${1:?usage: rig-dn-ping.sh <IPv4>}"
printf '%s\n' "$ip" | grep -Eq '^10\.45\.[0-9]{1,3}\.[0-9]{1,3}$' || exit 2
exec ssh -o BatchMode=yes -o ConnectTimeout=10 "${RIG_HOST:-amadeus-open5gs}" ping -c6 -W3 "$ip" >/dev/null 2>&1
