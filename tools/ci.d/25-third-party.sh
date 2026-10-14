#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M9, P1 N1): the verbatim OCUDU SNOW 3G copy is unmodified and
# alone, and the vendored cpp-httplib header matches its manifest.
# Every file under third_party/ocudu-security/{include,src} matches
# MANIFEST.sha256, and nothing else sits there (shim/ is ours, README.md and
# CMakeLists.txt are ours).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/third_party/ocudu-security"
( cd "$D" && sha256sum --quiet -c MANIFEST.sha256 ) ||
    { echo "OCUDU_SECURITY=FAIL (vendored files differ from MANIFEST.sha256)"; exit 1; }
extra=$(comm -13 <(awk '{print $2}' "$D/MANIFEST.sha256" | LC_ALL=C sort) \
                 <(cd "$D" && find include src -type f | LC_ALL=C sort))
[[ -z "$extra" ]] || { echo "OCUDU_SECURITY=FAIL (files not in MANIFEST.sha256: $extra)"; exit 1; }
echo "OCUDU_SECURITY=PASS files=$(wc -l < "$D/MANIFEST.sha256")"
H="$ROOT/third_party/cpp-httplib"
( cd "$H" && sha256sum --quiet -c MANIFEST.sha256 ) ||
    { echo "CPP_HTTPLIB=FAIL (httplib.h differs from MANIFEST.sha256)"; exit 1; }
echo "CPP_HTTPLIB=PASS"
