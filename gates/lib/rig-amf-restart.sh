#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# AMF_RESTART for the Open5GS rig (P1 N17): our amfd (from ~/kaluza-sim-rig/etc)
# stopped with SIGTERM and started again, the restart gate's AMF restart.
exec ssh -o BatchMode=yes -o ConnectTimeout=10 "${RIG_HOST:-amadeus-open5gs}" "set -eu
pkill -TERM -f 'open5gs-[a]mfd .*kaluza-sim-rig/etc/amf.yaml' || true
i=0; while pgrep -f 'open5gs-[a]mfd .*kaluza-sim-rig/etc/amf.yaml' >/dev/null && [ \$i -lt 50 ]; do sleep 0.1; i=\$((i+1)); done
nf=amf
~/open5gs-n3iwf/install/bin/open5gs-\${nf}d -D -c ~/kaluza-sim-rig/etc/\${nf}.yaml </dev/null >/dev/null 2>&1
sleep 1
pgrep -f 'open5gs-[a]mfd .*kaluza-sim-rig/etc/amf.yaml' >/dev/null && echo AMF_RESTARTED=1"
