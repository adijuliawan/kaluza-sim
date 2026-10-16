#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The performance harness (P2 Q12; requirements.md §3.5, ADR 0011 design point d). On this
# host, against ksim-corestub on loopback, from the release build: the UEs in namespaces of
# their own and the stub's UPF forwarding to a DN namespace with iperf3 behind it, both made
# by the host's ksim-netd (which needs --dn: lab.md). User-plane capture headers only. The
# runs, one after another:
#   nea2     aio, one UE: TCP DL and UL, ping RTT, CPU and RSS; NIA2 on the DRB (TCP DL)
#   nea1     the same with 128-NEA1 at AS (cucp nea [1])
#   split    the one-UE case in split mode (the roles as processes)
#   many     split mode, 100 UEs 10 at a time, then TCP DL on all of them at once
# Each run's numbers ($RUN/perf.tsv) go to build/perf/last/perf.tsv, and
# tools/perf/perf_report.py prints them against §3.5 (build/perf/last/report.txt).
#
#   tools/perf/perf.sh [nea2] [nea1] [split] [many]    (none: all)
#   PERF_SECS=10 PERF_NETD=/run/ksim/netd.sock
#   PERF_BIN=<dir>  every binary from one directory: a release's bin/ on kaluza-uesim (P2 Q15,
#                   LW3); without it the dev PC's release build, and ksim-sim from the dev build
#   PERF_OUT=<dir>  where the runs go (build/perf; short: split mode's sockets live there)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -n "${PERF_BIN:-}" ]]; then
    KSIM_EXE="$PERF_BIN/ksim"; CTL="$PERF_BIN/ksim-ctl"; STUB_EXE="$PERF_BIN/ksim-corestub"; SIM="$PERF_BIN/ksim-sim"
else
    R="$ROOT/build/release/apps"
    KSIM_EXE="$R/ksim/ksim"; CTL="$R/ksim-ctl/ksim-ctl"; STUB_EXE="$R/ksim-corestub/ksim-corestub"
    SIM="$ROOT/build/dev/apps/ksim-sim/ksim-sim"
fi
for x in "$KSIM_EXE" "$CTL" "$STUB_EXE" "$SIM"; do
    [[ -x "$x" ]] || { echo "PERF=SKIP (no $x; build the release and dev presets, or PERF_BIN)"; exit 77; }
done
# The oracle venv on the dev PC; the system's python3 elsewhere (the report needs only its stdlib).
PY="$ROOT/.venv/bin/python"; [[ -x "$PY" ]] || PY=python3
NETD="${PERF_NETD:-/run/ksim/netd.sock}"
"$CTL" netd list --netd "$NETD" >/dev/null 2>&1 || { echo "PERF=SKIP (no ksim-netd at $NETD)"; exit 77; }
command -v iperf3 >/dev/null || { echo "PERF=SKIP (no iperf3)"; exit 77; }
cases=("$@")
[[ ${#cases[@]} -eq 0 ]] && cases=(nea2 nea1 split many)

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${PERF_OUT:-$ROOT/build/perf}"
W="$OUT/$STAMP"
mkdir -p "$W/bin"
ln -sf "$KSIM_EXE" "$W/bin/ksim"
ln -sf "$CTL" "$W/bin/ksim-ctl"
ln -sf "$STUB_EXE" "$W/bin/ksim-corestub"
for b in ksim-du ksim-cucp ksim-cuup ksim-ue; do
    for d in "$(dirname "$KSIM_EXE")" "${R:-/nonexistent}/$b"; do
        [[ -x "$d/$b" ]] && ln -sf "$d/$b" "$W/bin/$b"
    done
done
"$SIM" range init --master "$W/keys/master.key" --kek "$W/keys/kek.key" >/dev/null || exit 1
"$SIM" range derive --block 001010000300000/101 --master "$W/keys/master.key" --kek "$W/keys/kek.key" \
    --out "$W/cards" >/dev/null || exit 1
: > "$W/perf.tsv"

# topo SRC [CUCP]: a copy with absolute paths, the host's netd for the UEs, headers-only capture.
topo() {
    sed "s|\.\./|$ROOT/|g" "$ROOT/topologies/$1" > "$W/topology.yaml"
    # t-Reordering 100 ms, as a deployed gNB has it: a PDCP hole costs time, not the run.
    sed -i "s|cucp: {ng_bind: 127.0.0.2}|cucp: {ng_bind: 127.0.0.2, t_reordering_ms: 100${2:+, $2}}|" "$W/topology.yaml"
    grep -q "t_reordering_ms: 100" "$W/topology.yaml" || { echo "PERF: no cucp line to set in $1"; exit 2; }
    # The link delay at 0: §3.5 bounds the added processing, without the configured delay.
    printf 'netd: {socket: %s, nodes: false, ues: true}\ncapture: {user_plane: headers}\nlink: {delay_ms: 0}\n' "$NETD" \
        >> "$W/topology.yaml"
}
# run LABEL CASE [env...]: one ksim run with the perf gate.
run() {
    local label=$1 kase=$2
    shift 2
    echo "== $label ($kase)"
    env "$@" PERF_CASE="$kase" PERF_LABEL="$label" PERF_SECS="${PERF_SECS:-10}" STUB_DN_NETD="$NETD" \
        KSIM_BIN="$W/bin" KSIM_TOPOLOGY_FILE="$W/topology.yaml" KSIM_RUNS="$W/runs-$label" KSIM_MASTER="$W/keys/master.key" \
        KSIM_KEK="$W/keys/kek.key" KSIM_SEALED="$W/cards" KSIM_PHASE=p2 \
        sh "$ROOT/gates/run.sh" stub "$ROOT/tools/perf/gate.sh" > "$W/$label.out" 2>&1
    grep -E '^  [a-z0-9-]+ [a-z_]+ = |ABORT|CLEANUP' "$W/$label.out"
    local rd
    rd="$(sed -n 's/^RUN_DIR=//p' "$W/$label.out")"
    [[ -n "$rd" && -f "$rd/perf.tsv" ]] && cat "$rd/perf.tsv" >> "$W/perf.tsv"
}
for c in "${cases[@]}"; do
    case "$c" in
        nea2) topo aio-stub.yaml; run nea2 one-ue ;;
        nea1) topo aio-stub.yaml "nea: [1], nia: [2, 1]"; run nea1 one-ue ;;
        split) topo split-stub.yaml; run split one-ue ;;
        many) topo split-stub-100.yaml; run many many STUB_BLOCK=001010000300000/100 PERF_UES=100 ;;
        *) echo "unknown case $c"; exit 2 ;;
    esac
done
left=$(ip netns list 2>/dev/null | grep -c '^ksim-' || true)
echo "PERF_NETNS_LEFT=$left"
rm -rf "$OUT/last"
mkdir -p "$OUT/last"
cp "$W/perf.tsv" "$OUT/last/perf.tsv"
# The commit: the checkout's, or a release's name (~/ksim/releases/<commit>/).
COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || basename "$(readlink -f "$ROOT")")"
"$PY" -I "$ROOT/tools/perf/perf_report.py" "$OUT/last/perf.tsv" --commit "$COMMIT" --host "$(hostname)" \
    | tee "$OUT/last/report.txt"
