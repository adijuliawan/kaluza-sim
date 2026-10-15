#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P2 Q4; ADR 0012): interop combination C3 on this host. Our UE farm and
# DU with OCUDU's CU-CP and CU-UP (tools/ocudu-peer.sh's build of the pin), against
# ksim-corestub, all on 127.0.0.x:
#   1. gates/verification/ksim-p2-ocudu.sh on topologies/ocudu-c3-stub.yaml (gates/run.sh
#      starts the peers from the topology and stops them);
#   2. tools/pcap_check.py on our captures (the peer's reported apart) and the canary
#      over the run, the peer's files included;
#   3. with the mutants preset built: no_ddds fails ksim-p2.ocudu-ddds;
#   4. no OCUDU process of ours is left.
# Full mode only. SKIP without the peer build, the binaries, tshark or the oracle venv,
# and while a gnb or odu process (a B220 cell) runs on the host: the dev PC's rule.
# The summary goes to build/ocudu/last/summary.txt for tools/p2_exit.py.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "OCUDU=SKIP (full mode only)"; exit 77; }
D="$ROOT/build/dev/apps"
M="$ROOT/build/mutants/apps"
PY="$ROOT/.venv/bin/python"
for x in "$D/ksim/ksim" "$D/ksim-ctl/ksim-ctl" "$D/ksim-corestub/ksim-corestub" "$D/ksim-sim/ksim-sim"; do
    [[ -x "$x" ]] || { echo "OCUDU=SKIP (no $x; build the dev preset)"; exit 77; }
done
PIN=$(sed -n 's/^PIN=//p' "$ROOT/tools/ocudu-peer.sh")
[[ -f "$HOME/kaluza-sim-peers/ocudu-$PIN/PIN" ]] || { echo "OCUDU=SKIP (no peer build; tools/ocudu-peer.sh build)"; exit 77; }
command -v tshark >/dev/null || { echo "OCUDU=SKIP (no tshark)"; exit 77; }
[[ -x "$PY" ]] || { echo "OCUDU=SKIP (no oracle venv)"; exit 77; }
if pgrep -x gnb >/dev/null || pgrep -x odu >/dev/null; then
    echo "OCUDU=SKIP (a gnb or odu process runs: a B220 cell)"; exit 77
fi
GATE="$ROOT/gates/verification/ksim-p2-ocudu.sh"
TOPO="$ROOT/topologies/ocudu-c3-stub.yaml"
BLOCK=001010000300001/12
OUT="$ROOT/build/ocudu/last"
rm -rf "$OUT"; mkdir -p "$OUT"
T="$(mktemp -d)"
trap '"$ROOT/tools/ocudu-peer.sh" stop >/dev/null 2>&1; rm -rf "$T"' EXIT
"$D/ksim-sim/ksim-sim" range init --master "$T/keys/master.key" --kek "$T/keys/kek.key" >/dev/null || exit 1
"$D/ksim-sim/ksim-sim" range derive --block "$BLOCK" --master "$T/keys/master.key" --kek "$T/keys/kek.key" \
    --out "$T/cards" >/dev/null || exit 1

gate() {   # $1 = label, then env assignments for the run
    local label="$1"; shift
    env "$@" KSIM_PHASE=p2 KSIM_TOPOLOGY_FILE="$TOPO" KSIM_RUNS="$T/runs-$label" KSIM_MASTER="$T/keys/master.key" \
        KSIM_KEK="$T/keys/kek.key" KSIM_SEALED="$T/cards" sh "$ROOT/gates/run.sh" stub "$GATE" > "$OUT/$label.out" 2>&1
    local rc=$?
    local run; run=$(sed -n 's/^RUN_DIR=//p' "$OUT/$label.out")
    [[ -n "$run" && -f "$run/rows.tsv" ]] && cp "$run/rows.tsv" "$OUT/$label.rows.tsv"
    echo "$run" > "$OUT/$label.run"
    return $rc
}
row_of() { awk -F'\t' -v r="$2" '$1 == r {print $2}' "$OUT/$1.rows.tsv" 2>/dev/null | head -n 1; }

rc=0
echo "-- 1. C3: our DU and UEs, OCUDU's CU-CP and CU-UP, the stub"
gate c3 || rc=1
cat "$OUT/c3.out"
RUN=$(cat "$OUT/c3.run")
[[ -n "$RUN" && -d "$RUN/peer" ]] || { echo "OCUDU=FAIL (no run directory with the peer's files)"; exit 1; }

echo "-- 2. captures and the canary"
"$PY" -I "$ROOT/tools/pcap_check.py" "$RUN" | tee "$OUT/pcap.out" || rc=1
"$PY" -I "$ROOT/tools/secret_canary.py" --run-dir "$RUN" --master "$T/keys/master.key" --block "$BLOCK" \
    | tee "$OUT/canary.out" || rc=1
cp -r "$RUN/peer" "$OUT/peer" 2>/dev/null
cp "$RUN/f1ap.pcapng" "$RUN/gtpu.pcapng" "$OUT/" 2>/dev/null
chmod -R go-rwx "$OUT"

echo "-- 3. the mutants"
killed=0; total=0
if [[ -x "$M/ksim/ksim" ]]; then
    mkdir -p "$T/mbin"
    ln -s "$M/ksim/ksim" "$T/mbin/ksim"; ln -s "$D/ksim-ctl/ksim-ctl" "$T/mbin/ksim-ctl"
    ln -s "$D/ksim-corestub/ksim-corestub" "$T/mbin/ksim-corestub"
    total=$((total + 1))
    gate m-ddds KSIM_BIN="$T/mbin" KSIM_MUTANT=no_ddds
    r=$(row_of m-ddds ksim-p2.ocudu-ddds)
    [[ "$r" == FAIL ]] && killed=$((killed + 1))
    echo "MUTANT=no_ddds $([[ "$r" == FAIL ]] && echo KILLED || echo SURVIVED) row=ksim-p2.ocudu-ddds result=${r:-none}" \
        | tee -a "$OUT/summary.txt"
else
    echo "MUTANTS=SKIP (no mutants preset)" | tee -a "$OUT/summary.txt"
fi

echo "-- 4. nothing left"
"$ROOT/tools/ocudu-peer.sh" stop | tee "$OUT/stop.out"
grep -qx 'OCUDU_LEFT=0' "$OUT/stop.out" || rc=1

fails=$(awk -F'\t' '$2 == "FAIL"' "$OUT/c3.rows.tsv" 2>/dev/null | wc -l)
passes=$(awk -F'\t' '$2 == "PASS"' "$OUT/c3.rows.tsv" 2>/dev/null | wc -l)
[[ "$fails" -eq 0 && "$passes" -ge 9 ]] || rc=1
[[ "$killed" -eq "$total" ]] || rc=1
{
    echo "OCUDU_PIN=$PIN"
    sed 's/^/OCUDU_/' "$HOME/kaluza-sim-peers/ocudu-$PIN/PIN" | sed -n 's/^OCUDU_\(ocucp\|ocuup\)=[^ ]* sha256=/OCUDU_\U\1\E_SHA256=/p'
    echo "OCUDU_C3_PASS=$passes"
    echo "OCUDU_C3_FAIL=$fails"
    grep -E '^(PCAP_MALFORMED|PYCRATE_FAILED|PEER_PCAP_MALFORMED)=' "$OUT/pcap.out"
    grep -E '^CANARY_RUN=' "$OUT/canary.out"
    echo "OCUDU_MUTANTS_KILLED=$killed/$total"
} | tee -a "$OUT/summary.txt"
echo "OCUDU=$([[ $rc -eq 0 ]] && echo PASS || echo FAIL) OUT=build/ocudu/last"
exit "$rc"
