# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The asn1c runtime (vendored, built once) and one static library per protocol
# (cmake/asn1c.cmake). The config header is forced into every translation unit
# that sees asn1c structures, including our C++ wrappers (PUBLIC).

set(KSIM_ASN1_CONFIG_H "${CMAKE_CURRENT_SOURCE_DIR}/ksim_asn1_config.h")

add_library(ksim_asn1_rt STATIC ${KSIM_ASN1_RUNTIME_SRCS})
add_library(ksim::asn1_rt ALIAS ksim_asn1_rt)
target_include_directories(ksim_asn1_rt SYSTEM PUBLIC "${PROJECT_SOURCE_DIR}/third_party/asn1c/runtime")
target_compile_options(ksim_asn1_rt
    PRIVATE ${KSIM_ASN1_C_OPTIONS}
    PUBLIC "SHELL:-include ${KSIM_ASN1_CONFIG_H}")
set_target_properties(ksim_asn1_rt PROPERTIES JOB_POOL_COMPILE asn1_gen C_STANDARD 17)
ksim_layer(ksim_asn1_rt codec)

foreach(_p IN LISTS KSIM_ASN1_PROTOCOLS)
    ksim_asn1_library(${_p})
endforeach()
