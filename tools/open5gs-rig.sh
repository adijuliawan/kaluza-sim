#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The Open5GS fork's 5GC on the rig, for kaluza-sim's control runs (ADR 0010,
# D5). Only inside a window agreed with the kaluza-core session.
#
#   tools/open5gs-rig.sh start|stop|status [--host amadeus-open5gs]
#
# Our copy differs from the live configs in: logger paths (~/kaluza-sim-rig/log),
# the SBI addresses of nrf, ausf, udm and nssf (the fork's loopback defaults,
# as in the .preroam variants: the 5gc FQDNs do not resolve on the rig), the
# AMF's NGAP on vmnet8 only (no wg0 address) and NSAC off (no NSACF in the set).
#
# start: refuses when any open5gs NF already runs on the rig (a kaluza-core
#        set would be using it); then starts nrfd scpd ausfd udmd udrd pcfd bsfd
#        nssfd amfd (kaluza-core-1e's order, 2026-10-15) from ~/kaluza-sim-rig/etc,
#        logging to ~/kaluza-sim-rig/log. No smfd or upfd (no ogstun), none of the
#        peers kaluza-core's gates start, no EPC daemon.
# stop:  stops every NF started from ~/kaluza-sim-rig/etc and checks none is
#        left and no ogstun exists.
# status: NFS=<n>, each one's name and pid, and NGAP_LISTEN=0|1.

set -eu
cmd="${1:?usage: tools/open5gs-rig.sh start|stop|status [--host H]}"
host=amadeus-open5gs
[ "${2:-}" = --host ] && host="${3:?--host needs a name}"
NFS="nrf scp ausf udm udr pcf bsf nssf amf"

rig() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" "$@"; }

case "$cmd" in
start)
    rig "set -eu
running=\$(pgrep -c -f 'open5gs-[a-z0-9]+d' || true)
if [ \"\$running\" != 0 ]; then echo \"RIG=BUSY open5gs_processes=\$running\" >&2; exit 3; fi
[ -d ~/kaluza-sim-rig/etc ] || { echo 'RIG=NO_CONFIG (~/kaluza-sim-rig/etc)' >&2; exit 2; }
cd ~/kaluza-sim-rig
for nf in $NFS; do
    ~/open5gs-n3iwf/install/bin/open5gs-\${nf}d -D -c ~/kaluza-sim-rig/etc/\${nf}.yaml </dev/null >/dev/null 2>&1
    sleep 0.5
done
sleep 2
for nf in $NFS; do
    pid=\$(pgrep -f \"open5gs-\${nf}d .*kaluza-sim-rig/etc/\${nf}.yaml\" | head -n 1 || true)
    echo \"NF.\$nf=\${pid:-DOWN}\"
done"
    ;;
stop)
    rig "pkill -f 'open5gs-[a-z0-9]+d .*kaluza-sim-rig/etc/' || true
sleep 2
pkill -9 -f 'open5gs-[a-z0-9]+d .*kaluza-sim-rig/etc/' 2>/dev/null || true
left=\$(pgrep -c -f 'open5gs-[a-z0-9]+d .*kaluza-sim-rig/etc/' || true)
echo \"NFS_LEFT=\$left\"
if ip link show ogstun >/dev/null 2>&1; then echo OGSTUN=present; else echo OGSTUN=absent; fi"
    ;;
status)
    rig "n=0
for nf in $NFS; do
    pid=\$(pgrep -f \"open5gs-\${nf}d .*kaluza-sim-rig/etc/\${nf}.yaml\" | head -n 1 || true)
    [ -n \"\$pid\" ] && n=\$((n + 1))
    echo \"NF.\$nf=\${pid:-DOWN}\"
done
echo \"NFS=\$n\"
if ss -Slnt 2>/dev/null | grep -q '192.168.134.128:38412'; then echo NGAP_LISTEN=1; else echo NGAP_LISTEN=0; fi"
    ;;
*)
    echo "usage: tools/open5gs-rig.sh start|stop|status [--host H]" >&2
    exit 2
    ;;
esac
