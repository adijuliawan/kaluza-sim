#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# tools/ci.sh [quick|full]
#
# The local CI gate (plan M1; no GitHub workflows). Run it before every push.
#   quick: presets dev + asan (configure, build, ctest), all guards with their
#          must-fail self-tests, reuse lint, and the quick extension hooks.
#   full:  adds tsan, release, release-lab and fuzz, and the full hooks
#          (oracle runs, fuzz smoke) as later milestones add them.
#
# Extension hooks: executable tools/ci.d/NN-name.sh scripts, called with the
# mode and the job count. Each exits 0 on pass, 77 to report SKIP.
#
# House rules (lab.md §1): never while the OCUDU/B220 cell runs; nice/ionice;
# job counts sized from MemAvailable, not from the core count.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-quick}"
case "$MODE" in quick|full) ;; *) echo "usage: tools/ci.sh [quick|full]" >&2; exit 2 ;; esac

# The B220 cell on the dev PC must not compete with a build (kaluza-core's "no big
# work during the cell" rule). OCUDU's cell runs as gnb, or as odu in split mode.
for proc in gnb odu; do
    if pgrep -x "$proc" >/dev/null 2>&1; then
        echo "CI=REFUSED reason=cell-running process=$proc" >&2
        exit 3
    fi
done

if [[ -z "${KSIM_CI_NICE:-}" ]]; then
    export KSIM_CI_NICE=1
    exec nice -n 10 ionice -c 2 -n 7 "$0" "$@"
fi

avail_kib=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
avail_mib=$(( avail_kib / 1024 ))
ncpu=$(nproc)
clamp() { local v=$1 lo=$2 hi=$3; (( v < lo )) && v=$lo; (( v > hi )) && v=$hi; echo "$v"; }
JOBS=$(clamp $(( avail_mib / 1536 )) 1 "$ncpu")
LINK_JOBS=$(clamp $(( avail_mib / 4096 )) 1 4)
GEN_JOBS=$JOBS

PRESETS=(dev asan)
[[ "$MODE" == full ]] && PRESETS+=(tsan release release-lab fuzz)

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOGDIR="$ROOT/build/ci/$STAMP"
mkdir -p "$LOGDIR"
declare -a SUMMARY=()
FAILED=0

step() {  # step NAME COMMAND...  (logs to $LOGDIR/NAME.log)
    local name="$1"; shift
    local log="$LOGDIR/$name.log" t0 rc
    t0=$(date +%s)
    ( cd "$ROOT" && "$@" ) >"$log" 2>&1
    rc=$?
    local dt=$(( $(date +%s) - t0 ))
    local res=PASS
    if (( rc == 77 )); then res=SKIP
    elif (( rc != 0 )); then res=FAIL; FAILED=$((FAILED + 1))
        echo "---- $name failed (rc=$rc), last lines of $log:" >&2
        tail -n 25 "$log" >&2
    fi
    SUMMARY+=("$(printf '%-34s %-4s %5ss' "$name" "$res" "$dt")")
}

echo "CI_MODE=$MODE JOBS=$JOBS LINK_JOBS=$LINK_JOBS MEM_AVAILABLE_MIB=$avail_mib LOGDIR=$LOGDIR"

needs=(guards asn1 "${PRESETS[@]}")
step doctor "$ROOT/tools/doctor.sh" "${needs[@]}"

for g in "$ROOT"/tools/guards/check_*.py; do
    name="$(basename "$g" .py)"
    step "guard:${name#check_}:selftest" python3 "$g" --self-test
    step "guard:${name#check_}" python3 "$g"
done
step reuse-lint reuse --root "$ROOT" lint --quiet

for p in "${PRESETS[@]}"; do
    step "configure:$p" cmake --preset "$p" -DKSIM_LINK_JOBS="$LINK_JOBS" -DKSIM_GEN_JOBS="$GEN_JOBS"
    step "build:$p" cmake --build --preset "$p" -j "$JOBS"
    if [[ "$p" != fuzz ]]; then
        step "test:$p" ctest --preset "$p" -j "$JOBS"
    fi
done

# The link graph only exists after configure, so the layer guard runs again here.
step "guard:layers:graph" python3 "$ROOT/tools/guards/check_layers.py"

if [[ -d "$ROOT/tools/ci.d" ]]; then
    for hook in "$ROOT"/tools/ci.d/*.sh; do
        [[ -x "$hook" ]] || continue
        step "hook:$(basename "$hook" .sh)" "$hook" "$MODE" "$JOBS"
    done
fi

echo
printf '%s\n' "${SUMMARY[@]}"
if (( FAILED > 0 )); then
    echo "CI=FAIL FAILED_STEPS=$FAILED LOGDIR=$LOGDIR"
    exit 1
fi
echo "CI=PASS MODE=$MODE LOGDIR=$LOGDIR"
