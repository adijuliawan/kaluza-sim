# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# KSIM_SANITIZE: none | asan (AddressSanitizer + UBSan) | tsan (ThreadSanitizer).
# Applied to the whole build, generated code included, so a PER decoder bug in
# asn1c output shows up under asan too (architecture.md §11).

set(KSIM_SANITIZE "none" CACHE STRING "none | asan | tsan")
set_property(CACHE KSIM_SANITIZE PROPERTY STRINGS none asan tsan)
option(KSIM_COVERAGE "Build with gcov coverage instrumentation" OFF)

if(KSIM_SANITIZE STREQUAL "asan")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer
                        -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=address,undefined)
elseif(KSIM_SANITIZE STREQUAL "tsan")
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
elseif(NOT KSIM_SANITIZE STREQUAL "none")
    message(FATAL_ERROR "KSIM_SANITIZE must be none, asan or tsan (got '${KSIM_SANITIZE}')")
endif()

if(KSIM_COVERAGE)
    add_compile_options(--coverage -O0)
    add_link_options(--coverage)
endif()
