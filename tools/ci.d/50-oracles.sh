#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M8): the oracle harness must-fail self-test, the derived
# tshark allowlist is current, and the external-origin corpus is current with
# its sender rules; the M10 probes; in full mode the round trip of every v1
# type (asn1c against pycrate and tshark), which must have no FAIL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-quick}"
PY=("$ROOT/.venv/bin/python" -I)
[[ -x "$ROOT/.venv/bin/python" ]] || { echo "ORACLES=SKIP (no .venv; see tools/requirements-oracle.txt)"; exit 77; }
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
    if [[ "$MODE" == full ]]; then
        # Every v1 type: corpus vectors (local ones too, where this machine has
        # them) and generated min/max values, asn1c against pycrate and tshark.
        "${PY[@]}" "$ROOT/tests/oracles/oracle.py" roundtrip --show 20 2>&1 | grep -E "^ROUNDTRIP|^FAILURE"
        s=${PIPESTATUS[0]}
        (( s == 0 )) || exit 1
    fi
fi
echo "ORACLES=PASS"
