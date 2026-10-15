#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The P1 data-plane gate (P1 N11): a UE's PDU sessions as the kernel sees them
# in the UE's own namespace (ksim-ue-<n>, a TUN per session from ksim-netd):
# the address, no IPv6 and no noise on the tunnels, a ping to the DN over the
# tunnel with its replies, a 1400-octet probe, and the QFI of the downlink.
# Rows of gates/rows/p1.tsv whose milestone is N11. A run without ksim-netd
# (inject mode) has no TUN: those rows SKIP; the QFI row scores in both.
#
#   RUN=<run dir> CORE=stub|open5gs|kaluza gates/verification/ksim-p1-dataplane.sh
#   [IMS_ADDR=<IPv4>]  pinged on the ims session too, as evidence (kaluza-core: 172.30.63.10)
#   [DN_ADDR=<IPv4>]   the address pinged (default 10.60.0.1, the stub's DN;
#                      172.30.61.1 on kaluza-core)
#
# UE 5 is used (the other gates use 1 to 4 and 6 to 9); it must be off at the start.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/lib/ksim.sh"

command -v tshark >/dev/null 2>&1 || abort "tshark is needed for the QFI row"
[ "$(ctl faults list | kv FAULTS)" = 0 ] || abort "the run has faults set"
: "${DN_ADDR:=10.60.0.1}"
UE=5

echo "-- registration and two sessions (UE $UE)"
reg=$(ctl ue "$UE" power on --wait 30s)
[ "$(printf '%s\n' "$reg" | kv RESULT)" = ACCEPT ] || abort "UE $UE did not register: $(printf '%s\n' "$reg" | kv CAUSE)"
est=$(ctl ue "$UE" ps-establish ipv4 --dnn internet --sst 1 --wait 15s)
[ "$(printf '%s\n' "$est" | kv RESULT)" = ACCEPT ] || abort "no internet session: $(printf '%s\n' "$est" | kv CAUSE)"
ip=$(printf '%s\n' "$est" | kv IP)
psi=$(printf '%s\n' "$est" | kv PSI)
psi_ims=$(ctl ue "$UE" ps-establish ipv4 --dnn ims --sst 1 --wait 15s | kv PSI)

ifs=$(ctl ue "$UE" ifaces)
mode=$(printf '%s\n' "$ifs" | kv MODE)
echo "   data plane: $mode $(printf '%s\n' "$ifs" | kv NETNS)"

echo "-- a ping to the DN ($DN_ADDR)"
png=$(ctl ue "$UE" ping "$DN_ADDR" --psi "$psi" -c 3 --interval 200)
sent=$(printf '%s\n' "$png" | kv SENT)
got=$(printf '%s\n' "$png" | kv RECEIVED)
echo "   $mode ping: sent=$sent received=$got rtt_avg_ms=$(printf '%s\n' "$png" | kv RTT_AVG_MS)"

if [ "$mode" = netns ]; then
    ifs=$(ctl ue "$UE" ifaces)   # after the ping: the counters
    kern=$(printf '%s\n' "$ifs" | kv "KERNEL.pdu$psi.IPV4")
    row amf-ueransim.014 "^pdu$psi=$ip/32 accepted=$ip\$" "pdu$psi=$kern accepted=$ip"
    row smf-ueransim.010 "^pdu$psi=$ip/32 accepted=$ip\$" "pdu$psi=$kern accepted=$ip"
    row amf-ueransim.015 '^ipv6=0 noise=0$' \
        "ipv6=$(printf '%s\n' "$ifs" | kv KERNEL_IPV6) noise=$(printf '%s\n' "$ifs" | kv NOISE)"
    row amf-ueransim.018 '^received=[1-9][0-9]*$' "received=$got"
    row smf-ueransim.020 '^received=[1-9][0-9]* dl_packets=[1-9][0-9]*$' \
        "received=$got dl_packets=$(printf '%s\n' "$ifs" | kv "IF.pdu$psi.DL_PACKETS")"
    probe=$(ctl ue "$UE" ping "$DN_ADDR" --psi "$psi" -c 1 --size 1372 --df)
    echo "   1400-octet probe (DF): received=$(printf '%s\n' "$probe" | kv RECEIVED)"
    if [ -n "${IMS_ADDR:-}" ] && [ -n "$psi_ims" ]; then
        # Evidence only (no row): the ims session's own peer (kaluza-core: the P-CSCF).
        ipng=$(ctl ue "$UE" ping "$IMS_ADDR" --psi "$psi_ims" -c 3 --interval 200)
        echo "   ims ping $IMS_ADDR: sent=$(printf '%s\n' "$ipng" | kv SENT) received=$(printf '%s\n' "$ipng" | kv RECEIVED)"
    fi
else
    for r in amf-ueransim.014 smf-ueransim.010 amf-ueransim.015 amf-ueransim.018 smf-ueransim.020; do
        skip_row "$r" "inject mode: no TUN in this run (needs ksim-netd, topology netd: ues)"
    done
fi

# The QFI the UE took from its default QoS rule against the QFI the network
# marks in the DL PDU Session Container (TS 38.415) to the UE's address.
qfi=$(ctl ue "$UE" ps-list | kv "PS.$psi.QFI")
dl=$(tshark_fields "$RUN/gtpu.pcapng" "gtp.ext_hdr.pdu_ses_con.pdu_type == 0 && ip.dst == $ip" \
    gtp.ext_hdr.pdu_ses_con.qos_flow_id | sort -u | tr '\n' ' ' | sed 's/ $//')
row smf-ueransim.017 "^rule=$qfi dl=$qfi\$" "rule=$qfi dl=$dl"

release_all "$UE"
ctl ue "$UE" power off --switch-off --wait 10s >/dev/null
summary ksim-p1-dataplane
