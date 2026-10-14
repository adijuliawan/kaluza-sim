# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ksim::warnings: the warning set for hand-written code. Generated ASN.1 C and
# vendored third-party code do not link this target.

add_library(ksim_warnings INTERFACE)
add_library(ksim::warnings ALIAS ksim_warnings)

target_compile_options(ksim_warnings INTERFACE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wcast-qual -Wformat=2 -Wundef
    -Wnull-dereference -Wdouble-promotion -Wimplicit-fallthrough
    $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor -Wold-style-cast -Woverloaded-virtual>
    $<$<BOOL:${KSIM_WERROR}>:-Werror>)
