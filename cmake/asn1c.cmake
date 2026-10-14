# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The ASN.1 pipeline (architecture.md §4.1, plan M6).
#
# At configure time spec/tools/asn1_gen.py generates every protocol once per
# stamp into a shared cache (~/.cache/kaluza-sim/asn1-gen) and writes
# <build>/asn1/files.cmake, which lists the generated sources (from asn1c's own
# Makefile.am.libasncodec; no globbing) and the runtime files they need.
# src/codec/asn1/CMakeLists.txt then builds:
#   ksim_asn1_rt                     the vendored runtime, once
#   ksim_asn1_{rrc,ngap,f1ap,e1ap,xnap}   one static library per protocol
# Every translation unit, generated or ours, force-includes
# src/codec/asn1/ksim_asn1_config.h (row KS-PLAT-B4).

option(KSIM_ASN1 "Generate and build the ASN.1 codec libraries" ON)
set(KSIM_ASN1C "$ENV{HOME}/.local/opt/asn1c-18e56503/bin/asn1c"
    CACHE FILEPATH "The pinned asn1c (mouse07410 fork at 18e56503, tools/build-asn1c.sh)")
set(KSIM_ASN1_CACHE "$ENV{HOME}/.cache/kaluza-sim/asn1-gen"
    CACHE PATH "Shared cache of generated ASN.1 C, keyed by stamp")
set(KSIM_ASN1_PROTOCOLS rrc ngap f1ap e1ap xnap)

# Compile options for generated C and the runtime: optimised but cheap (the RRC
# library alone is ~2700 translation units), C17, and no strict aliasing (asn1c
# and its output were not written for it; row KS-PLAT-T6).
set(KSIM_ASN1_C_OPTIONS -O1 -g0 -ffunction-sections -fdata-sections -fno-strict-aliasing -w)

function(ksim_asn1_generate)
    if(NOT KSIM_ASN1)
        return()
    endif()
    if(NOT EXISTS "${KSIM_ASN1C}")
        message(FATAL_ERROR "No asn1c at ${KSIM_ASN1C}: run tools/build-asn1c.sh, "
                            "or configure with -DKSIM_ASN1=OFF")
    endif()
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    set(_out "${PROJECT_BINARY_DIR}/asn1/files.cmake")
    execute_process(
        COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/spec/tools/asn1_gen.py"
                --asn1c "${KSIM_ASN1C}" --cache "${KSIM_ASN1_CACHE}" --cmake-out "${_out}"
                ${KSIM_ASN1_PROTOCOLS}
        RESULT_VARIABLE _rc
        OUTPUT_VARIABLE _log
        ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "ASN.1 generation failed:\n${_log}${_err}")
    endif()
    string(STRIP "${_log}" _log)
    message(STATUS "${_log}")
    include("${_out}")
    # Reconfigure when an input of the stamp changes.
    file(GLOB _asn CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/spec/asn1/*/*.asn")
    set_property(DIRECTORY "${PROJECT_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                 ${_asn} "${KSIM_ASN1C}" "${PROJECT_SOURCE_DIR}/spec/tools/asn1_gen.py"
                 "${PROJECT_SOURCE_DIR}/src/codec/asn1/ksim_asn1_config.h")
    foreach(_p IN LISTS KSIM_ASN1_PROTOCOLS)
        string(TOUPPER ${_p} _P)
        set(KSIM_ASN1_${_P}_DIR "${KSIM_ASN1_${_P}_DIR}" PARENT_SCOPE)
        set(KSIM_ASN1_${_P}_SRCS "${KSIM_ASN1_${_P}_SRCS}" PARENT_SCOPE)
        set(KSIM_ASN1_${_P}_STAMP "${KSIM_ASN1_${_P}_STAMP}" PARENT_SCOPE)
    endforeach()
    ksim_asn1_runtime_tree(_rt)
    list(TRANSFORM KSIM_ASN1_RUNTIME_SRCS REPLACE "^${PROJECT_SOURCE_DIR}/third_party/asn1c/runtime" "${_rt}")
    set(KSIM_ASN1_RUNTIME_SRCS "${KSIM_ASN1_RUNTIME_SRCS}" PARENT_SCOPE)
    set(KSIM_ASN1_RUNTIME_DIR "${_rt}" PARENT_SCOPE)
endfunction()

# ksim_asn1_runtime_tree(<out var>): the runtime we compile. A copy of the
# vendored third_party/asn1c/runtime (kept as shipped, MANIFEST.sha256) in the
# build tree with third_party/asn1c/patches/series applied in order; redone
# only when the series or a patch changes.
function(ksim_asn1_runtime_tree out)
    set(_src "${PROJECT_SOURCE_DIR}/third_party/asn1c/runtime")
    set(_dir "${PROJECT_SOURCE_DIR}/third_party/asn1c/patches")
    set(_dst "${PROJECT_BINARY_DIR}/asn1c-runtime")
    file(STRINGS "${_dir}/series" _lines REGEX "^[^#].*\\.patch$")
    set(_key "")
    foreach(_p IN LISTS _lines)
        file(SHA256 "${_dir}/${_p}" _h)
        string(APPEND _key "${_p}:${_h};")
        set_property(DIRECTORY "${PROJECT_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_dir}/${_p}")
    endforeach()
    set_property(DIRECTORY "${PROJECT_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_dir}/series")
    string(SHA256 _key "${_key}")
    if(EXISTS "${_dst}/.ksim-patches" )
        file(READ "${_dst}/.ksim-patches" _old)
    else()
        set(_old "")
    endif()
    if(NOT _old STREQUAL _key)
        file(REMOVE_RECURSE "${_dst}")
        file(COPY "${_src}/" DESTINATION "${_dst}")
        foreach(_p IN LISTS _lines)
            execute_process(COMMAND patch -p1 -s --forward -d "${_dst}" -i "${_dir}/${_p}"
                            RESULT_VARIABLE _rc OUTPUT_VARIABLE _o ERROR_VARIABLE _e)
            if(NOT _rc EQUAL 0)
                message(FATAL_ERROR "asn1c runtime patch ${_p} does not apply:\n${_o}${_e}")
            endif()
        endforeach()
        file(WRITE "${_dst}/.ksim-patches" "${_key}")
        list(LENGTH _lines _n)
        message(STATUS "asn1c runtime: ${_n} patch(es) applied in ${_dst}")
    endif()
    set(${out} "${_dst}" PARENT_SCOPE)
endfunction()

# ksim_asn1_library(<proto>): the static library for one protocol.
function(ksim_asn1_library proto)
    string(TOUPPER ${proto} _P)
    set(_t ksim_asn1_${proto})
    add_library(${_t} STATIC ${KSIM_ASN1_${_P}_SRCS})
    add_library(ksim::asn1_${proto} ALIAS ${_t})
    target_include_directories(${_t} SYSTEM PUBLIC "${KSIM_ASN1_${_P}_DIR}")
    target_link_libraries(${_t} PUBLIC ksim_asn1_rt)
    target_compile_options(${_t} PRIVATE ${KSIM_ASN1_C_OPTIONS})
    set_target_properties(${_t} PROPERTIES JOB_POOL_COMPILE asn1_gen C_STANDARD 17)
    ksim_layer(${_t} codec)
endfunction()
