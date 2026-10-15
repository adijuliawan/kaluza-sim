# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The asn1c runtime (vendored, built once) and one static library per protocol
# (cmake/asn1c.cmake). The config header is forced into every translation unit
# that sees asn1c structures, including our C++ wrappers (PUBLIC).

set(KSIM_ASN1_CONFIG_H "${CMAKE_CURRENT_SOURCE_DIR}/ksim_asn1_config.h")

add_library(ksim_asn1_rt STATIC ${KSIM_ASN1_RUNTIME_SRCS})
add_library(ksim::asn1_rt ALIAS ksim_asn1_rt)
target_include_directories(ksim_asn1_rt SYSTEM PUBLIC "${KSIM_ASN1_RUNTIME_DIR}")
target_compile_options(ksim_asn1_rt
    PRIVATE ${KSIM_ASN1_C_OPTIONS}
    PUBLIC "SHELL:-include ${KSIM_ASN1_CONFIG_H}")
set_target_properties(ksim_asn1_rt PROPERTIES JOB_POOL_COMPILE asn1_gen C_STANDARD 17)
ksim_layer(ksim_asn1_rt codec)

foreach(_p IN LISTS KSIM_ASN1_PROTOCOLS)
    ksim_asn1_library(${_p})
endforeach()

# The C++ face (asn1.hpp): protocol-agnostic, over the runtime only.
add_library(ksim_codec_asn1 STATIC asn1.cpp)
add_library(ksim::codec_asn1 ALIAS ksim_codec_asn1)
target_include_directories(ksim_codec_asn1 PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_asn1 PUBLIC ksim::platform ksim_asn1_rt PRIVATE ksim::warnings)
ksim_layer(ksim_codec_asn1 codec)

# Every type of every protocol by name (registry.hpp), for ksim-codec and the
# oracle harness: one generated translation unit per protocol.
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
set(_reg_srcs registry.cpp)
foreach(_p IN LISTS KSIM_ASN1_PROTOCOLS)
    string(TOUPPER ${_p} _P)
    set(_out "${CMAKE_CURRENT_BINARY_DIR}/registry_${_p}.cpp")
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -I "${PROJECT_SOURCE_DIR}/tools/asn1_registry.py" ${_p}
                "${KSIM_ASN1_${_P}_DIR}" "${_out}"
        RESULT_VARIABLE _rc OUTPUT_VARIABLE _log ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "ASN.1 registry for ${_p} failed:\n${_log}${_err}")
    endif()
    list(APPEND _reg_srcs "${_out}")
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/tools/asn1_registry.py")
add_library(ksim_asn1_registry STATIC ${_reg_srcs})
add_library(ksim::asn1_registry ALIAS ksim_asn1_registry)
target_include_directories(ksim_asn1_registry PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_asn1_registry
    PUBLIC ksim::codec_asn1 ksim::asn1_rrc ksim::asn1_ngap ksim::asn1_f1ap ksim::asn1_e1ap ksim::asn1_xnap
    PRIVATE ksim::warnings)
ksim_layer(ksim_asn1_registry codec)

# Typed RRC builders and readers (P1 N6; architecture.md §4.1 msg/): values
# built as JER, encoded by the generated code.
add_library(ksim_codec_jer STATIC msg/jer.cpp)
target_include_directories(ksim_codec_jer PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_jer PUBLIC ksim::platform ksim::codec_asn1 nlohmann_json::nlohmann_json PRIVATE ksim::warnings)
ksim_layer(ksim_codec_jer codec)

add_library(ksim_codec_rrc STATIC msg/rrc.cpp)
add_library(ksim::codec_rrc ALIAS ksim_codec_rrc)
target_include_directories(ksim_codec_rrc PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_rrc PUBLIC ksim::platform PRIVATE ksim_codec_jer ksim::asn1_rrc ksim::warnings)
ksim_layer(ksim_codec_rrc codec)

# Typed NGAP builders and readers (P1 N7), the same route.
add_library(ksim_codec_ngap STATIC msg/ngap.cpp)
add_library(ksim::codec_ngap ALIAS ksim_codec_ngap)
target_include_directories(ksim_codec_ngap PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_ngap PUBLIC ksim::platform PRIVATE ksim_codec_jer ksim::asn1_ngap ksim::warnings)
ksim_layer(ksim_codec_ngap codec)

# Typed E1AP builders and readers (P1 N10), the same route.
add_library(ksim_codec_e1ap STATIC msg/e1ap.cpp)
add_library(ksim::codec_e1ap ALIAS ksim_codec_e1ap)
target_include_directories(ksim_codec_e1ap PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_e1ap PUBLIC ksim::platform PRIVATE ksim_codec_jer ksim::asn1_e1ap ksim::warnings)
ksim_layer(ksim_codec_e1ap codec)

# Typed F1AP builders and readers (P1 N7), the same route.
add_library(ksim_codec_f1ap STATIC msg/f1ap.cpp)
add_library(ksim::codec_f1ap ALIAS ksim_codec_f1ap)
target_include_directories(ksim_codec_f1ap PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_f1ap PUBLIC ksim::platform PRIVATE ksim_codec_jer ksim::asn1_f1ap ksim::warnings)
ksim_layer(ksim_codec_f1ap codec)
