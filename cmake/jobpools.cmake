# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Ninja job pools sized from the memory actually available, not from the core
# count. The dev PC has 24 threads but often only ~30 GiB free (lab.md §1), and
# generated ASN.1 code and sanitizer builds are memory-hungry.
#   link     : every link step (CMAKE_JOB_POOL_LINK)
#   asn1_gen : compiles of generated ASN.1 C (used from M6)
# tools/ci.sh passes KSIM_LINK_JOBS / KSIM_GEN_JOBS explicitly; the defaults
# below apply to manual configures.

cmake_host_system_information(RESULT _ksim_avail_mib QUERY AVAILABLE_PHYSICAL_MEMORY)
cmake_host_system_information(RESULT _ksim_ncpu QUERY NUMBER_OF_LOGICAL_CORES)

math(EXPR _ksim_link_default "${_ksim_avail_mib} / 4096")
if(_ksim_link_default LESS 1)
    set(_ksim_link_default 1)
elseif(_ksim_link_default GREATER 4)
    set(_ksim_link_default 4)
endif()

math(EXPR _ksim_gen_default "${_ksim_avail_mib} / 1536")
if(_ksim_gen_default LESS 1)
    set(_ksim_gen_default 1)
elseif(_ksim_gen_default GREATER _ksim_ncpu)
    set(_ksim_gen_default ${_ksim_ncpu})
endif()

set(KSIM_LINK_JOBS "${_ksim_link_default}" CACHE STRING "Concurrent link jobs")
set(KSIM_GEN_JOBS "${_ksim_gen_default}" CACHE STRING "Concurrent compiles of generated ASN.1 C")

set_property(GLOBAL APPEND PROPERTY JOB_POOLS link=${KSIM_LINK_JOBS} asn1_gen=${KSIM_GEN_JOBS})
set(CMAKE_JOB_POOL_LINK link)
