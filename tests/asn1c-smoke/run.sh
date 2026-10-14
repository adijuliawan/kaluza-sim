#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# asn1c smoke (plan M4). With the pinned compiler and the vendored runtime:
#  1. generate Smoke.asn twice, with -fprefix=SA_ and SB_;
#  2. compile the vendored runtime once, plus both generated sets, under the one
#     config header (src/codec/asn1/ksim_asn1_config.h);
#  3. nm hygiene: every generated global carries its prefix; nothing is defined
#     twice across SA, SB and the runtime;
#  4. APER round trip with an INTEGER over 2^32, and a JER dump.
# Exit 77 (SKIP) when the pinned compiler is not installed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASN1C="${KSIM_ASN1C:-$HOME/.local/opt/asn1c-18e56503/bin/asn1c}"
[[ -x "$ASN1C" ]] || { echo "ASN1C_SMOKE=SKIP (no $ASN1C; run tools/build-asn1c.sh)"; exit 77; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
FLAGS=(-fcompound-names -findirect-choice -fno-include-deps -pdu=all -no-gen-OER -no-gen-BER
       -no-gen-XER -no-gen-random-fill -no-gen-example)
CF=(-std=gnu17 -O1 -g0 -fno-strict-aliasing -include "$ROOT/src/codec/asn1/ksim_asn1_config.h"
    -I "$ROOT/third_party/asn1c/runtime")
for P in SA SB; do
    mkdir -p "$W/gen$P" "$W/obj$P"
    "$ASN1C" "${FLAGS[@]}" -fprefix=${P}_ -D "$W/gen$P" "$ROOT/tests/asn1c-smoke/Smoke.asn" >"$W/gen$P.log" 2>&1 ||
        { echo "ASN1C_SMOKE=FAIL generate $P"; cat "$W/gen$P.log"; exit 1; }
    for f in "$W/gen$P"/${P}_*.c; do
        gcc "${CF[@]}" -I "$W/gen$P" -c "$f" -o "$W/obj$P/$(basename "${f%.c}").o" || { echo "ASN1C_SMOKE=FAIL cc $f"; exit 1; }
    done
done
# The runtime is the skeleton subset asn1c lists for these flags (not every
# vendored file: the BER-only ones do not build with BER disabled). Each listed
# file must be byte-identical to the vendored copy, which is what gets compiled.
mkdir -p "$W/objR"
mapfile -t RT < <(grep -oE '[^/[:space:]]+\.c' "$W/genSA/Makefile.am.libasncodec" | grep -v '^SA_' | LC_ALL=C sort -u)
for f in "${RT[@]}"; do
    cmp -s "$W/genSA/$f" "$ROOT/third_party/asn1c/runtime/$f" ||
        { echo "ASN1C_SMOKE=FAIL runtime file $f differs from the vendored copy"; exit 1; }
    gcc "${CF[@]}" -c "$ROOT/third_party/asn1c/runtime/$f" -o "$W/objR/${f%.c}.o" ||
        { echo "ASN1C_SMOKE=FAIL cc runtime $f"; exit 1; }
done
for P in SA SB R; do
    nm --defined-only -g "$W/obj$P"/*.o | awk 'NF==3{print $3}' | LC_ALL=C sort -u >"$W/syms$P"
done
bad=0
for P in SA SB; do
    n=$(grep -c -v -E "(^|_)${P}_" "$W/syms$P")
    (( n == 0 )) || { echo "ASN1C_SMOKE=FAIL unprefixed globals in $P: $n"; bad=1; }
done
for pair in "SA SB" "SA R" "SB R"; do
    set -- $pair
    n=$(LC_ALL=C comm -12 "$W/syms$1" "$W/syms$2" | wc -l)
    (( n == 0 )) || { echo "ASN1C_SMOKE=FAIL $n globals defined in both $1 and $2"; bad=1; }
done
(( bad == 0 )) || exit 1
gcc "${CF[@]}" -I "$W/genSA" "$ROOT/tests/asn1c-smoke/roundtrip.c" "$W/objSA"/*.o "$W/objR"/*.o -o "$W/roundtrip" ||
    { echo "ASN1C_SMOKE=FAIL link"; exit 1; }
"$W/roundtrip" >"$W/rt.out" || { cat "$W/rt.out"; echo "ASN1C_SMOKE=FAIL roundtrip"; exit 1; }
grep '^SMOKE_' "$W/rt.out"
echo "ASN1C_SMOKE=PASS globals_SA=$(wc -l <"$W/symsSA") runtime_files=${#RT[@]} runtime_globals=$(wc -l <"$W/symsR")"
