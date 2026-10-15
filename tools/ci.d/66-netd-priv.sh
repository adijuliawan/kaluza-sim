#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N9; ADR 0009 consequences): the privileged ksim-netd smoke. Opt-in
# only: it runs when KSIM_CI_PRIV=1 and sudo works without a prompt, and
# reports SKIP otherwise. It starts ksim-netd as root on a temporary socket,
# serving this uid with no parent link (the dev PC allows none), runs
# netd_smoke (a namespace, a socket made in it, from P2 Q6 a DN namespace whose
# TUN answers an echo, gc), stops netd and checks
# that no ksim- namespace is left.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${KSIM_CI_PRIV:-0}" == 1 ]] || { echo "NETD_PRIV=SKIP (opt-in: KSIM_CI_PRIV=1)"; exit 77; }
sudo -n true 2>/dev/null || { echo "NETD_PRIV=SKIP (sudo -n refused)"; exit 77; }
NETD="$ROOT/build/dev/apps/ksim-netd/ksim-netd"
SMOKE="$ROOT/build/dev/tests/unit/net/netd_smoke"
[[ -x "$NETD" && -x "$SMOKE" ]] || { echo "NETD_PRIV=SKIP (build the dev preset)"; exit 77; }
T="$(mktemp -d)"
sudo -n "$NETD" --uid "$(id -u)" --socket "$T/netd.sock" --dn 10.60.0.0/24 > "$T/netd.log" 2>&1 &
pid=$!
for _ in $(seq 50); do [[ -S "$T/netd.sock" ]] && break; sleep 0.1; done
"$SMOKE" "$T/netd.sock"; rc=$?
sudo -n kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
left=$(ip netns list 2>/dev/null | grep -c '^ksim-' || true)
echo "NETD_PRIV_LEFT=$left"
sudo -n rm -rf "$T"
[[ $rc -eq 0 && $left -eq 0 ]]
