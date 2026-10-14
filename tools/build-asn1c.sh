#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# tools/build-asn1c.sh: build the pinned ASN.1 compiler (architecture.md §4.1).
#
#   mouse07410/asn1c at 18e565032e52af8002c2353be20bdbba9233e700 (2024-08-21)
#   source  ~/.cache/kaluza-sim/asn1c-src   (git clone, detached at the pin)
#   prefix  ~/.local/opt/asn1c-18e56503     (KSIM_ASN1C in cmake/asn1c.cmake)
#
# Why this commit: the fork's later HEAD aborts on the parameterized
# ProtocolIE-Container family, and stock 0.9.29 cannot parse Rel-16+ [[ ]]
# brackets inside CHOICE (facts from UERANSIM's notes; no code taken).
#
# gcc 15 compiles C as gnu23 and makes implicit declarations, int-conversion and
# incompatible pointer types hard errors. The fallback ladder:
#   1. autoreconf, then CFLAGS=-std=gnu17 (C17 semantics: bool is not a keyword)
#   2. step 1 plus -fpermissive (gcc >= 14 downgrades those errors for C)
#   3. our own compiler patches from third_party/asn1c/patches/compiler/
# Each rung that was needed becomes a register row (docs/compliance/rows.tsv).

set -euo pipefail
PIN=18e565032e52af8002c2353be20bdbba9233e700
REPO=https://github.com/mouse07410/asn1c
SRC="${KSIM_ASN1C_SRC:-$HOME/.cache/kaluza-sim/asn1c-src}"
PREFIX="${KSIM_ASN1C_PREFIX:-$HOME/.local/opt/asn1c-18e56503}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOBS="${JOBS:-$(nproc)}"

if [[ ! -d "$SRC/.git" ]]; then
    git clone -q "$REPO" "$SRC"
fi
git -C "$SRC" -c advice.detachedHead=false checkout -q "$PIN"
if [[ "$(git -C "$SRC" rev-parse HEAD)" != "$PIN" ]]; then
    echo "ASN1C_BUILD=FAIL reason=wrong-commit" >&2; exit 1
fi
git -C "$SRC" reset -q --hard "$PIN"
git -C "$SRC" clean -qfdx

patches="$ROOT/third_party/asn1c/patches/compiler"
if [[ -d "$patches" ]] && compgen -G "$patches/*.patch" >/dev/null; then
    for p in "$patches"/*.patch; do
        git -C "$SRC" apply --check "$p" && git -C "$SRC" apply "$p"
        echo "ASN1C_PATCH=$(basename "$p")"
    done
fi

cd "$SRC"
autoreconf -fi >/dev/null 2>&1

try_build() {  # try_build RUNG CFLAGS
    local rung="$1" cflags="$2"
    echo "ASN1C_TRY rung=$rung CFLAGS='$cflags'"
    if [[ -f Makefile ]]; then make -s distclean >/dev/null 2>&1 || true; fi
    ./configure -q --prefix="$PREFIX" CFLAGS="$cflags" >"$SRC/.ksim-configure.log" 2>&1 &&
        make -s -j "$JOBS" >"$SRC/.ksim-make.log" 2>&1
}

if try_build 1 "-std=gnu17 -O2 -g -fno-strict-aliasing"; then
    RUNG=1
elif try_build 2 "-std=gnu17 -O2 -g -fno-strict-aliasing -fpermissive"; then
    RUNG=2
else
    echo "ASN1C_BUILD=FAIL (rungs 1-2; see $SRC/.ksim-make.log; next: add compiler patches)" >&2
    tail -n 30 "$SRC/.ksim-make.log" >&2
    exit 1
fi

rm -rf "$PREFIX"
make -s install >"$SRC/.ksim-install.log" 2>&1
echo "ASN1C_BUILD=PASS rung=$RUNG prefix=$PREFIX"
echo "ASN1C_VERSION=$("$PREFIX/bin/asn1c" -v 2>&1 | head -n 1)"
echo "ASN1C_SHA256=$(sha256sum "$PREFIX/bin/asn1c" | cut -c1-64)"
