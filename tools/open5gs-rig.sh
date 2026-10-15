#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The Open5GS fork's 5GC on the rig, for kaluza-sim's control runs (ADR 0010,
# D5). Only inside a window agreed with the kaluza-core session.
#
#   tools/open5gs-rig.sh start [--session] [--t3512 N] | stop | status [--host amadeus-open5gs]
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
#        --session (P1 N17) adds smfd and upfd. upfd runs as root (sudo -n; the
#        user allowed it on 2026-10-15 for upfd only) and makes ogstun, which
#        then gets the pool gateways 10.45.0.1/16 and 10.46.0.1/16. --t3512 N
#        sets T3512 in our copy's amf.yaml first (the periodic rows).
# stop:  stops every NF started from ~/kaluza-sim-rig/etc (upfd as root),
#        deletes ogstun and ogstun-edge, and checks no NF and no ogstun is left.
# status: NFS=<n>, each one's name and pid, and NGAP_LISTEN=0|1.

set -eu
cmd="${1:?usage: tools/open5gs-rig.sh start [--session] [--t3512 N]|stop|status [--host H]}"
shift
host=amadeus-open5gs
session=0
t3512=""
while [ $# -gt 0 ]; do
    case "$1" in
        --host) host="${2:?--host needs a name}"; shift ;;
        --session) session=1 ;;
        --t3512) t3512="${2:?--t3512 needs seconds}"; shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
    shift
done
case "$t3512" in ''|*[!0-9]*) [ -z "$t3512" ] || { echo "--t3512 takes seconds" >&2; exit 2; } ;; esac
NFS="nrf scp ausf udm udr pcf bsf nssf amf"
[ "$session" = 1 ] && NFS="$NFS smf"

rig() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" "$@"; }

case "$cmd" in
start)
    rig "set -eu
running=\$(pgrep -c -f 'open5gs-[a-z0-9]+d' || true)
if [ \"\$running\" != 0 ]; then echo \"RIG=BUSY open5gs_processes=\$running\" >&2; exit 3; fi
[ -d ~/kaluza-sim-rig/etc ] || { echo 'RIG=NO_CONFIG (~/kaluza-sim-rig/etc)' >&2; exit 2; }
cd ~/kaluza-sim-rig
if [ -n '$t3512' ]; then
    sed -i '/^    t3512:/{n;s/^      value: [0-9]*/      value: $t3512/}' etc/amf.yaml
    grep -A1 '^    t3512:' etc/amf.yaml | tail -n 1 | sed 's/^ */T3512_CONFIG=/'
fi
if [ '$session' = 1 ]; then
    # upfd as root (sudo -n): it makes ogstun; the gateways go on it below.
    sudo -n ~/open5gs-n3iwf/install/bin/open5gs-upfd -D -c ~/kaluza-sim-rig/etc/upf.yaml </dev/null >/dev/null 2>&1
    sleep 2
    sudo -n ip addr replace 10.45.0.1/16 dev ogstun
    sudo -n ip addr replace 10.46.0.1/16 dev ogstun
    sudo -n ip link set ogstun up
    pid=\$(pgrep -f 'open5gs-upfd .*kaluza-sim-rig/etc/upf.yaml' | head -n 1 || true)
    echo \"NF.upf=\${pid:-DOWN}\"
fi
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
if pgrep -f 'open5gs-upfd .*kaluza-sim-rig/etc/' >/dev/null; then
    sudo -n pkill -f 'open5gs-upfd .*kaluza-sim-rig/etc/' || true
fi
sleep 2
pkill -9 -f 'open5gs-[a-z0-9]+d .*kaluza-sim-rig/etc/' 2>/dev/null || true
if pgrep -f 'open5gs-upfd .*kaluza-sim-rig/etc/' >/dev/null; then
    sudo -n pkill -9 -f 'open5gs-upfd .*kaluza-sim-rig/etc/' || true
fi
for dev in ogstun ogstun-edge; do
    if ip link show \$dev >/dev/null 2>&1; then sudo -n ip link del \$dev || true; fi
done
left=\$(pgrep -c -f 'open5gs-[a-z0-9]+d .*kaluza-sim-rig/etc/' || true)
echo \"NFS_LEFT=\$left\"
if ip link show ogstun >/dev/null 2>&1 || ip link show ogstun-edge >/dev/null 2>&1; then echo OGSTUN=present; else echo OGSTUN=absent; fi"
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
