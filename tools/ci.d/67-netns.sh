#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N11; data-plane.md): the TUN data plane for real. Opt-in only: it
# runs when KSIM_CI_PRIV=1 and sudo works without a prompt, and reports SKIP
# otherwise. It starts ksim-netd as root on a temporary socket (this uid, no
# parent link), then the stub component run with the UEs in namespaces of
# their own (topology netd: {nodes: false, ues: true}; the nodes stay on
# loopback beside the stub) and gate ksim-p1-dataplane.sh: the TUN's address,
# no IPv6 and no noise, a ping to the DN over the tunnel, the 1400-octet
# probe, the QFI. Every row must PASS (none SKIP), and once netd has stopped
# no ksim- namespace may be left.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${KSIM_CI_PRIV:-0}" == 1 ]] || { echo "NETNS_PRIV=SKIP (opt-in: KSIM_CI_PRIV=1)"; exit 77; }
sudo -n true 2>/dev/null || { echo "NETNS_PRIV=SKIP (sudo -n refused)"; exit 77; }
B="$ROOT/build/dev/apps"
for x in "$B/ksim/ksim" "$B/ksim-ctl/ksim-ctl" "$B/ksim-corestub/ksim-corestub" "$B/ksim-sim/ksim-sim" "$B/ksim-netd/ksim-netd"; do
    [[ -x "$x" ]] || { echo "NETNS_PRIV=SKIP (no $x; build the dev preset)"; exit 77; }
done
T="$(mktemp -d)"
BLOCK=001010000300001/5
"$B/ksim-sim/ksim-sim" range init --master "$T/keys/master.key" --kek "$T/keys/kek.key" >/dev/null || exit 1
"$B/ksim-sim/ksim-sim" range derive --block "$BLOCK" --master "$T/keys/master.key" --kek "$T/keys/kek.key" \
    --out "$T/cards" >/dev/null || exit 1
sudo -n "$B/ksim-netd/ksim-netd" --uid "$(id -u)" --socket "$T/netd.sock" > "$T/netd.log" 2>&1 &
netd=$!
for _ in $(seq 50); do [[ -S "$T/netd.sock" ]] && break; sleep 0.1; done
sed "s|template: ../cards/usim-5g.yaml|template: $ROOT/cards/usim-5g.yaml|" "$ROOT/topologies/aio-stub.yaml" > "$T/topology.yaml"
echo "netd: {socket: $T/netd.sock, nodes: false, ues: true}" >> "$T/topology.yaml"
KSIM_TOPOLOGY_FILE="$T/topology.yaml" KSIM_RUNS="$T/runs" KSIM_MASTER="$T/keys/master.key" KSIM_KEK="$T/keys/kek.key" \
    KSIM_SEALED="$T/cards" sh "$ROOT/gates/run.sh" stub "$ROOT/gates/verification/ksim-p1-dataplane.sh" > "$T/gates.out" 2>&1
cat "$T/gates.out"
RUN="$(sed -n 's/^RUN_DIR=//p' "$T/gates.out")"
rc=0
if [[ -z "$RUN" || ! -f "$RUN/rows.tsv" ]]; then
    rc=1
else
    awk -F '\t' '$2 != "PASS" { bad = 1 } END { exit bad }' "$RUN/rows.tsv" || rc=1
    [[ "$(wc -l < "$RUN/rows.tsv")" -ge 6 ]] || rc=1
fi
sudo -n kill "$netd" 2>/dev/null; wait "$netd" 2>/dev/null
left=$(ip netns list 2>/dev/null | grep -c '^ksim-' || true)
echo "NETNS_PRIV_LEFT=$left"
[[ "$left" -eq 0 ]] || rc=1
mkdir -p "$ROOT/build/component"
rm -rf "$ROOT/build/component/netns-last"
[[ -n "$RUN" && -d "$RUN" ]] && cp -r "$RUN" "$ROOT/build/component/netns-last" && rm -f "$ROOT/build/component/netns-last/ctl.sock"
sudo -n rm -rf "$T"
echo "NETNS_PRIV=$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)"
exit "$rc"
