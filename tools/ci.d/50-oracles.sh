#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M8): the oracle harness must-fail self-test, the derived
# tshark allowlist is current, and the external-origin corpus is current with
# its sender rules. In full mode the generated-value sweep over every v1 AP type
# is reported (informational until M10 turns it into the exit check).
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
if [[ "$MODE" == full ]]; then
    "${PY[@]}" "$ROOT/tests/oracles/oracle.py" sweep 2>&1 | grep -E "^SWEEP"
fi
echo "ORACLES=PASS"
