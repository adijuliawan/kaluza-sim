#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Runs gates against one core (P1 N8; ADR 0009 point 9):
#
#   gates/run.sh <core> [gate …]       core: a gates/cores/<core>.env
#
# It starts ksim-corestub when the core is the stub, then `ksim run` with the
# core's topology, runs each gate (default: every gates/verification/ksim-p1-*.sh)
# with RUN and CORE set, stops ksim and the stub, and prints RUN_DIR. The run
# directory keeps the manifest, events, pcaps and rows.tsv.
#
# Environment:
#   KSIM_BIN      the directory holding ksim, ksim-ctl, ksim-corestub (default build/dev/apps/*)
#   KSIM_RUNS     where runs go (default runs/)
#   KSIM_MASTER, KSIM_KEK, KSIM_SEALED
#                 the range master, the KEK and the sealed cards (default: the
#                 topology's secrets and ~/.kaluza-sim/secrets/range-master.key);
#                 CI passes throwaway ones
#   KSIM_LAB=1    pass --lab (kaluza-uesim only; the guard enforces it)
#   KSIM_TOPOLOGY_FILE
#                 a topology instead of the core's (the privileged netns hook writes one)

set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
core="${1:?usage: gates/run.sh <core> [gate ...]}"; shift
env_file="$ROOT/gates/cores/$core.env"
[ -f "$env_file" ] || { echo "no core $core ($env_file)" >&2; exit 2; }
. "$env_file"

bin() {
    if [ -n "${KSIM_BIN:-}" ]; then echo "$KSIM_BIN/$1"; else echo "$ROOT/build/dev/apps/$1/$1"; fi
}
KSIM=$(bin ksim); KSIM_CTL=$(bin ksim-ctl); STUB_BIN=$(bin ksim-corestub)
export KSIM_CTL KSIM_ROOT="$ROOT" CORE
: "${KSIM_RUNS:=$ROOT/runs}"
: "${KSIM_MASTER:=$HOME/.kaluza-sim/secrets/range-master.key}"

RUN="$KSIM_RUNS/$core-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$KSIM_RUNS"
stub_pid=""; ksim_pid=""
cleanup() {
    [ -n "$ksim_pid" ] && { "$KSIM_CTL" --run "$RUN" stop >/dev/null 2>&1; wait "$ksim_pid" 2>/dev/null; }
    [ -n "$stub_pid" ] && { kill "$stub_pid" 2>/dev/null; wait "$stub_pid" 2>/dev/null; }
}
trap cleanup EXIT INT TERM

if [ "${STUB:-0}" = 1 ]; then
    # The gates reach the stub's network-side triggers here (STUB_CTL).
    STUB_CTL="$KSIM_RUNS/$core-stub.sock"; export STUB_CTL
    "$STUB_BIN" --listen "$STUB_LISTEN" --master "$KSIM_MASTER" --block "$STUB_BLOCK" \
        --ctl "$STUB_CTL" ${STUB_N3:+--n3 "$STUB_N3"} > "$KSIM_RUNS/$core-stub.out" 2>&1 &
    stub_pid=$!
    i=0
    until grep -q '^CTL=' "$KSIM_RUNS/$core-stub.out" 2>/dev/null; do
        i=$((i + 1)); [ "$i" -gt 50 ] && { cat "$KSIM_RUNS/$core-stub.out" >&2; exit 1; }
        sleep 0.1
    done
fi

# The gates read NAS in clear (the IMEISV row), so they ask for it (KS-CTL-004).
extra="--plain-nas"
[ -n "${KSIM_SEALED:-}" ] && extra="$extra --sealed $KSIM_SEALED"
[ -n "${KSIM_KEK:-}" ] && extra="$extra --kek $KSIM_KEK"
[ "${KSIM_LAB:-0}" = 1 ] && extra="$extra --lab"
# shellcheck disable=SC2086
"$KSIM" run -c "${KSIM_TOPOLOGY_FILE:-$ROOT/$KSIM_TOPOLOGY}" --run-dir "$RUN" $extra > "$KSIM_RUNS/$core-ksim.out" 2>&1 &
ksim_pid=$!
i=0
until grep -q '^CTL=' "$KSIM_RUNS/$core-ksim.out" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 100 ] || ! kill -0 "$ksim_pid" 2>/dev/null; then
        cat "$KSIM_RUNS/$core-ksim.out" >&2; ksim_pid=""; exit 1
    fi
    sleep 0.1
done
export RUN

[ $# -gt 0 ] || set -- "$ROOT"/gates/verification/ksim-p1-*.sh
rc=0
for g in "$@"; do
    echo "== $(basename "$g") on $core"
    sh "$g" || rc=1
done

if [ -n "$stub_pid" ]; then
    "$KSIM_CTL" --socket "$KSIM_RUNS/$core-stub.sock" stub > "$RUN/stub.txt" 2>&1 || true
fi
cleanup; ksim_pid=""; stub_pid=""
echo "RUN_DIR=$RUN"
exit "$rc"
