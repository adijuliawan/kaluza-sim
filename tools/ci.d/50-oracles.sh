#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M8): the oracle harness must-fail self-test, the derived
# tshark allowlist is current, and the external-origin corpus is current with
# its sender rules; the M10 probes and the M11 and M12 must-fail cases; every
# RRC builder's output (P1 N6) clean in pycrate and tshark; in
# full mode the round trip of every v1 type (asn1c against pycrate and
# tshark; NAS, SMS, GTP-U, PSC, NR-U and APDUs likewise), which must have no FAIL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-quick}"
PY=("$ROOT/.venv/bin/python" -I)
[[ -x "$ROOT/.venv/bin/python" ]] || { echo "ORACLES=SKIP (no .venv; see tools/requirements-oracle.txt)"; exit 77; }
# run_kept NAME PATTERN ARGS...: an oracle.py command whose whole output is kept
# in build/oracle/NAME.log; the lines matching PATTERN are shown, and on failure
# the log's tail too, so a crash is not filtered away.
run_kept() {
    local name="$1" pattern="$2"
    shift 2
    mkdir -p "$ROOT/build/oracle"
    local log="$ROOT/build/oracle/$name.log"
    "${PY[@]}" "$ROOT/tests/oracles/oracle.py" "$@" > "$log" 2>&1
    local s=$?
    grep -E "$pattern" "$log"
    if (( s != 0 )); then
        echo "ORACLE_STEP=FAIL $name exit=$s log=build/oracle/$name.log"
        grep -v CryptoMobile "$log" | tail -n 15 | sed 's/^/  /'
        return 1
    fi
}
"${PY[@]}" "$ROOT/tests/oracles/oracle.py" selftest 2>&1 | grep -v CryptoMobile; s=${PIPESTATUS[0]}
(( s == 0 )) || exit 1
"${PY[@]}" "$ROOT/tests/oracles/oracle.py" allowlists --check 2>&1 | grep -v CryptoMobile; s=${PIPESTATUS[0]}
(( s == 0 )) || exit 1
if [[ -d /home/amadeus/Development/ran/ocudu && -d /home/amadeus/Development/kaluza-core/testkit ]]; then
    "${PY[@]}" "$ROOT/tools/corpus_ingest.py" --check 2>&1 | grep -v CryptoMobile | tail -n 3; s=${PIPESTATUS[0]}
    (( s == 0 )) || exit 1
else
    echo "CORPUS=SKIP (the OCUDU checkout or the kaluza-core testkit is not on this machine)"
fi
# Our C++ codecs (plan M10) through ksim-codec from the dev build.
export KSIM_CODEC="${KSIM_CODEC:-$ROOT/build/dev/apps/ksim-codec/ksim-codec}"
if [[ ! -x "$KSIM_CODEC" ]]; then
    echo "ROUNDTRIP=SKIP (no ksim-codec at $KSIM_CODEC; build the dev preset)"
else
    "${PY[@]}" "$ROOT/tests/oracles/oracle.py" probes 2>&1 | grep -E "^PROBE|^  " ; s=${PIPESTATUS[0]}
    (( s == 0 )) || exit 1
    # The NAS and SMS check's own must-fail mutations (plan M11), and M12's.
    "${PY[@]}" "$ROOT/tests/oracles/oracle.py" l3roundtrip --selftest 2>&1 | grep -E "^L3SELFTEST" ; s=${PIPESTATUS[0]}
    (( s == 0 )) || exit 1
    "${PY[@]}" "$ROOT/tests/oracles/oracle.py" m12roundtrip --selftest 2>&1 | grep -E "^M12" ; s=${PIPESTATUS[0]}
    (( s == 0 )) || exit 1
    # Every typed RRC builder's output against pycrate, tshark and asn1c (P1 N6).
    run_kept builders "^BUILDER" builders || exit 1
    if [[ "$MODE" == full ]]; then
        # Every v1 type: corpus vectors (local ones too, where this machine has
        # them) and generated min/max values, asn1c against pycrate and tshark.
        run_kept roundtrip "^ROUNDTRIP|^FAILURE" roundtrip --show 20 || exit 1
        # Every v1 5GMM, 5GSM and SMS type against pycrate and tshark (plan M11).
        run_kept l3roundtrip "^L3ROUNDTRIP|^FAILURE" l3roundtrip --show 20 || exit 1
        # Every v1 GTP-U, PSC, NR-U and APDU type, and FCP templates, against pycrate,
        # pySim (where this machine has it) and tshark (plan M12).
        run_kept m12roundtrip "^M12ROUNDTRIP|^FAILURE" m12roundtrip --show 20 || exit 1
    fi
fi
echo "ORACLES=PASS"
