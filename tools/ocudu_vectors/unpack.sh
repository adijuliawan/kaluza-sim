#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# OCUDU's ASN.1 decoder over our RRC PDUs (P3 R0 spike 2; R1's offline oracle): builds
# ocudu-unpack against the pinned OCUDU tree (tools/ocudu-peer.sh's build, the version C6-C8
# run) outside both trees, then reads "<type>\t<hex>" lines on stdin. Refuses while the lab
# cell (gnb/odu) runs, like tools/ci.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PIN=$(sed -n 's/^PIN=//p' "$ROOT/tools/ocudu-peer.sh")
BASE="$HOME/kaluza-sim-peers/ocudu-$PIN"
[[ -f "$BASE/PIN" ]] || { echo "OCUDU_UNPACK=FAIL (no pinned OCUDU build; tools/ocudu-peer.sh build)" >&2; exit 2; }
if pgrep -x gnb >/dev/null || pgrep -x odu >/dev/null; then
    echo "OCUDU_UNPACK=REFUSED (the lab cell is running)" >&2; exit 1
fi
B="$HOME/.cache/kaluza-sim/ocudu-unpack-$PIN"
cmake -S "$ROOT/tools/ocudu_vectors" -B "$B" -G Ninja -DOCUDU_SRC="$BASE/src" -DOCUDU_BUILD="$BASE/build" >/dev/null
nice -n 10 cmake --build "$B" -j "$(nproc)" --target ocudu-unpack >/dev/null
exec "$B/ocudu-unpack"
