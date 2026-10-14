#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# tools/doctor.sh [need...]
#
# Prints TOOL=version for every tool kaluza-sim uses, then fails if a tool
# needed by the named presets or categories is missing. Needs:
#   dev asan tsan release release-lab cov fuzz   (CMake presets)
#   guards asn1 oracle                           (categories)
# With no arguments it only reports.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASN1C="${KSIM_ASN1C:-$HOME/.local/opt/asn1c-18e56503/bin/asn1c}"
PYSIM_DIR="${KSIM_PYSIM_DIR:-/home/amadeus/Development/ran/usim}"
PYSIM_PY="$PYSIM_DIR/.venv-pysim/bin/python"

declare -A VER

probe() {  # probe NAME COMMAND...
    local name="$1"; shift
    local v
    if v="$("$@" 2>/dev/null | head -n 1)" && [[ -n "$v" ]]; then
        VER[$name]="$v"
    else
        VER[$name]="MISSING"
    fi
    printf '%s=%s\n' "$name" "${VER[$name]}"
}

probe GCC gcc -dumpfullversion
probe GXX g++ -dumpfullversion
probe CLANG clang -dumpversion
probe CLANGXX clang++ -dumpversion
probe LLD ld.lld --version
probe MOLD mold --version
probe CMAKE cmake --version
probe NINJA ninja --version
probe CCACHE ccache --version
probe CLANG_TIDY clang-tidy --version
probe GCOVR gcovr --version
probe REUSE reuse --version
probe PYTHON python3 --version
probe VENV_PYTHON "$ROOT/.venv/bin/python" --version
probe PYCRATE "$ROOT/.venv/bin/python" -c 'import importlib.metadata as m; print(m.version("pycrate"))'
probe TSHARK tshark -v
probe ASN1C "$ASN1C" -v
probe PYSIM env PYTHONPATH="$PYSIM_DIR/pysim-src" "$PYSIM_PY" -c 'import pySim; print("ok")'
if [[ -f /usr/lib/llvm-21/lib/clang/21/lib/linux/libclang_rt.fuzzer-x86_64.a ]]; then
    VER[LIBFUZZER]="llvm-21"; else VER[LIBFUZZER]="MISSING"; fi
printf 'LIBFUZZER=%s\n' "${VER[LIBFUZZER]}"

required() {
    case "$1" in
        dev|asan|tsan|release|release-lab) echo GCC GXX CMAKE NINJA CCACHE MOLD ;;
        cov) echo GCC GXX CMAKE NINJA CCACHE MOLD GCOVR ;;
        fuzz) echo CLANG CLANGXX LLD CMAKE NINJA CCACHE LIBFUZZER ;;
        guards) echo PYTHON REUSE ;;
        asn1) echo ASN1C ;;
        oracle) echo VENV_PYTHON PYCRATE TSHARK ;;
        *) echo "UNKNOWN_NEED_$1" ;;
    esac
}

missing=0
for need in "$@"; do
    for tool in $(required "$need"); do
        if [[ "${VER[$tool]:-MISSING}" == "MISSING" ]]; then
            echo "DOCTOR_MISSING=$tool (needed by $need)" >&2
            missing=$((missing + 1))
        fi
    done
done
echo "DOCTOR_MISSING_COUNT=$missing"
exit $(( missing > 0 ? 1 : 0 ))
