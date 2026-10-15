#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P2 Q1; sim-uicc.md §5, KS-UICC-009): the PC/SC path with no real
# card. pcscd's vpcd reader 1 shows our soft card (ksim-sim serve, the
# sysmoISIM-SJA5 personality, the TS 35.208 test keys), and then:
#   1. ksim-sim adm1 seal and burn write it as imsi-001010000300100 with K and
#      OPc from a throwaway range master, through PC/SC, and check it;
#   2. a UE whose card is pcsc: "Virtual PCD 00 01" registers against the stub
#      (gates/verification/ksim-p2-card.sh: ksim-p2.burn-verify,
#      ksim-p2.pcsc-register);
#   3. the card bridge (ksim-sim serve --pcsc) in front of the same reader:
#      tools/vpcd_probe.py finds the administrator's commands refused, and a UE
#      whose card is bridge: 127.0.0.1:35970 registers
#      (ksim-p2.bridge-refuses-admin);
#   4. with the mutants preset built: pcsc_response_truncated (ksim) and
#      bridge_admin_open (ksim-sim) each fail their row.
# Full mode only; SKIP without pcscd, vpcd or the binaries. The summary goes to
# build/pcsc/last/summary.txt for tools/p2_exit.py.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "PCSC=SKIP (full mode only)"; exit 77; }
D="$ROOT/build/dev/apps"
M="$ROOT/build/mutants/apps"
for x in "$D/ksim/ksim" "$D/ksim-ctl/ksim-ctl" "$D/ksim-corestub/ksim-corestub" "$D/ksim-sim/ksim-sim"; do
    [[ -x "$x" ]] || { echo "PCSC=SKIP (no $x; build the dev preset)"; exit 77; }
done
command -v pcscd >/dev/null || [[ -x /usr/sbin/pcscd ]] || { echo "PCSC=SKIP (no pcscd)"; exit 77; }
[[ -f /etc/reader.conf.d/vpcd || -d /usr/lib/pcsc/drivers/serial ]] || { echo "PCSC=SKIP (no vpcd driver)"; exit 77; }
SIM="$D/ksim-sim/ksim-sim"
READER="Virtual PCD 00 01"
VPCD=127.0.0.1:35964
BRIDGE=127.0.0.1:35970
IMSI=001010000300100
OUT="$ROOT/build/pcsc/last"
rm -rf "$OUT"; mkdir -p "$OUT"
T="$(mktemp -d)"
pids=()
cleanup() {
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
"$SIM" range init --master "$T/keys/master.key" --kek "$T/keys/kek.key" >/dev/null || exit 1

start_card() {
    "$SIM" serve --template "$ROOT/cards/usim-5g.yaml" --imsi "$IMSI" --test-keys --personality sysmoISIM-SJA5 \
        --vpcd "$VPCD" > "$T/card.out" 2>&1 &
    pids+=($!)
    # pcscd's driver polls the ATR; once it has, the reader holds a card (a dry run opens it).
    # Right after hook 55's soft card left the same reader, vpcd takes longer than 10 s
    # to take a new one (P2 Q7), so up to 30 s.
    for _ in $(seq 1 300); do
        "$SIM" burn --pcsc "$READER" --imsi "$IMSI" --master "$T/keys/master.key" --adm1 /dev/null --kek "$T/keys/kek.key" \
            --dry-run >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    cat "$T/card.out" >&2
    return 1
}

topology() {   # $1 = card yaml, $2 = file
    cat > "$2" <<Y
plmn: "00101"
seed: 42
amf: [{addr: 127.0.0.1, port: 39412}]
gnbs:
  - id: {value: 0x1A0, bits: 22}
    name: ksim-gnb1
    cucp: {ng_bind: 127.0.0.2}
    dus: [{id: 1, cells: [{pci: 101, tac: 1, arfcn: 632628}]}]
ues:
  - {group: card, count: 1, range: "$IMSI", card: $1, nssai: [1], imeisv_tac: "86000000"}
secrets: {sealed: $T/cards, kek: $T/keys/kek.key}
peer: {name: ksim-corestub}
Y
}
gate() {   # $1 = label, then env assignments for the gate
    local label="$1"; shift
    env "$@" KSIM_PHASE=p2 KSIM_RUNS="$T/runs-$label" KSIM_MASTER="$T/keys/master.key" KSIM_KEK="$T/keys/kek.key" \
        STUB_BLOCK="$IMSI/1" sh "$ROOT/gates/run.sh" stub "$ROOT/gates/verification/ksim-p2-card.sh" > "$OUT/$label.out" 2>&1
    local rc=$?
    local run; run=$(sed -n 's/^RUN_DIR=//p' "$OUT/$label.out")
    [[ -n "$run" && -f "$run/rows.tsv" ]] && cp "$run/rows.tsv" "$OUT/$label.rows.tsv"
    return $rc
}
row_of() { awk -F'\t' -v r="$2" '$1 == r {print $2}' "$OUT/$1.rows.tsv" 2>/dev/null | head -n 1; }

rc=0
"$ROOT/tools/vpcd_ready.sh" "$READER" || { echo "PCSC=FAIL (pcscd has no $READER)"; exit 1; }
start_card || { echo "PCSC=FAIL (the soft card never showed on $READER)"; exit 1; }

echo "-- 1. the burn"
echo 11111111 | "$SIM" adm1 seal --out "$T/adm1.sealed" --kek "$T/keys/kek.key" --stdin > "$OUT/seal.out" || rc=1
"$SIM" burn --pcsc "$READER" --imsi "$IMSI" --master "$T/keys/master.key" --adm1 "$T/adm1.sealed" \
    --kek "$T/keys/kek.key" > "$OUT/burn.out" 2>&1 || rc=1
cat "$OUT/burn.out"

echo "-- 2. a UE on PC/SC"
topology "{pcsc: {reader: \"$READER\"}}" "$T/topo-pcsc.yaml"
gate pcsc KSIM_TOPOLOGY_FILE="$T/topo-pcsc.yaml" BURN_REPORT="$OUT/burn.out" || rc=1
cat "$OUT/pcsc.out"

echo "-- 3. the bridge"
"$SIM" serve --pcsc "$READER" --listen "$BRIDGE" --allow 127.0.0.1 > "$OUT/bridge-serve.out" 2>&1 &
bridge_pid=$!; pids+=("$bridge_pid")
for _ in $(seq 1 50); do grep -q '^BRIDGE=' "$OUT/bridge-serve.out" && break; sleep 0.1; done
python3 -I "$ROOT/tools/vpcd_probe.py" --connect "$BRIDGE" > "$OUT/probe.out" 2>&1 || rc=1
topology "{bridge: \"$BRIDGE\"}" "$T/topo-bridge.yaml"
gate bridge KSIM_TOPOLOGY_FILE="$T/topo-bridge.yaml" BRIDGE=1 PROBE_REPORT="$OUT/probe.out" || rc=1
cat "$OUT/bridge.out" "$OUT/bridge-serve.out"
kill "$bridge_pid" 2>/dev/null; wait "$bridge_pid" 2>/dev/null

echo "-- 4. the mutants"
killed=0; total=0
if [[ -x "$M/ksim/ksim" && -x "$M/ksim-sim/ksim-sim" ]]; then
    mkdir -p "$T/mbin"
    ln -s "$M/ksim/ksim" "$T/mbin/ksim"; ln -s "$D/ksim-ctl/ksim-ctl" "$T/mbin/ksim-ctl"
    ln -s "$D/ksim-corestub/ksim-corestub" "$T/mbin/ksim-corestub"
    total=$((total + 1))
    gate m-pcsc KSIM_TOPOLOGY_FILE="$T/topo-pcsc.yaml" KSIM_BIN="$T/mbin" KSIM_MUTANT=pcsc_response_truncated
    r=$(row_of m-pcsc ksim-p2.pcsc-register)
    [[ "$r" == FAIL ]] && killed=$((killed + 1))
    echo "MUTANT=pcsc_response_truncated $([[ "$r" == FAIL ]] && echo KILLED || echo SURVIVED) row=ksim-p2.pcsc-register result=${r:-none}" | tee -a "$OUT/summary.txt"
    total=$((total + 1))
    KSIM_MUTANT=bridge_admin_open "$M/ksim-sim/ksim-sim" serve --pcsc "$READER" --listen "$BRIDGE" --allow 127.0.0.1 \
        > "$OUT/m-bridge.out" 2>&1 &
    mb=$!; pids+=("$mb")
    for _ in $(seq 1 50); do grep -q '^BRIDGE=' "$OUT/m-bridge.out" && break; sleep 0.1; done
    python3 -I "$ROOT/tools/vpcd_probe.py" --connect "$BRIDGE" > "$OUT/m-probe.out" 2>&1
    kill "$mb" 2>/dev/null; wait "$mb" 2>/dev/null
    gate m-bridge KSIM_TOPOLOGY_FILE="$T/topo-pcsc.yaml" PROBE_REPORT="$OUT/m-probe.out"
    r=$(row_of m-bridge ksim-p2.bridge-refuses-admin)
    [[ "$r" == FAIL ]] && killed=$((killed + 1))
    echo "MUTANT=bridge_admin_open $([[ "$r" == FAIL ]] && echo KILLED || echo SURVIVED) row=ksim-p2.bridge-refuses-admin result=${r:-none}" | tee -a "$OUT/summary.txt"
else
    echo "MUTANTS=SKIP (no mutants preset)" | tee -a "$OUT/summary.txt"
fi

for label in pcsc bridge; do
    [[ -f "$OUT/$label.rows.tsv" ]] && cat "$OUT/$label.rows.tsv" >> "$OUT/rows.tsv"
done
fails=$(awk -F'\t' '$2 == "FAIL"' "$OUT/rows.tsv" 2>/dev/null | wc -l)
passes=$(awk -F'\t' '$2 == "PASS"' "$OUT/rows.tsv" 2>/dev/null | wc -l)
[[ "$fails" -eq 0 && "$passes" -ge 3 ]] || rc=1
[[ "$killed" -eq "$total" ]] || rc=1
{ echo "CARD_ROWS_PASS=$passes"; echo "CARD_ROWS_FAIL=$fails"; echo "PCSC_MUTANTS_KILLED=$killed/$total"; } | tee -a "$OUT/summary.txt"
echo "PCSC=$([[ $rc -eq 0 ]] && echo PASS || echo FAIL) OUT=build/pcsc/last"
exit "$rc"
