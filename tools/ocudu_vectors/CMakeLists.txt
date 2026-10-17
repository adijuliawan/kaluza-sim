# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# A standalone build (not part of kaluza-sim's): main.cpp plus OCUDU's own test
# message builders, compiled with OCUDU's flags and linked against an existing
# OCUDU build's static libraries. Nothing is written into the OCUDU tree.

cmake_minimum_required(VERSION 3.28)
project(ksim-ocudu-vectors CXX)

set(OCUDU_SRC "/home/amadeus/Development/ran/ocudu" CACHE PATH "OCUDU source tree")
set(OCUDU_BUILD "${OCUDU_SRC}/build" CACHE PATH "An OCUDU build directory with its static libraries")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS ON)
add_compile_options(-fno-exceptions -fno-rtti -march=native -O1 -w)
add_compile_definitions(NDEBUG BUILD_TYPE_RELEASE)
include_directories(
    "${OCUDU_SRC}/include" "${OCUDU_SRC}" "${OCUDU_SRC}/external" "${OCUDU_SRC}/external/fmt/include"
    "${OCUDU_BUILD}" "${OCUDU_BUILD}/lib/support/versioning")

set(_t "${OCUDU_SRC}/tests")
set(_vector_sources
    main.cpp
    "${_t}/test_doubles/f1ap/f1ap_test_messages.cpp"
    "${_t}/test_doubles/pdcp/pdcp_pdu_generator.cpp"
    "${_t}/test_doubles/rrc/rrc_packed_test_messages.cpp"
    "${_t}/test_doubles/rrc/rrc_test_messages.cpp"
    "${_t}/test_doubles/utils/test_rng.cpp"
    "${_t}/unittests/e1ap/common/e1ap_cu_cp_test_messages.cpp"
    "${_t}/unittests/e1ap/common/e1ap_cu_up_test_messages.cpp"
    "${_t}/unittests/ngap/ngap_test_messages.cpp"
    "${_t}/unittests/xnap/xnap_test_messages.cpp")
file(GLOB_RECURSE _libs "${OCUDU_BUILD}/lib/*.a")
# The producer needs OCUDU's test builders at the paths of the tree it was written for; a tree
# without them (the pinned peer tree, P3 R0) builds ocudu-unpack only.
set(_have_tests TRUE)
foreach(_f IN LISTS _vector_sources)
    if(NOT _f STREQUAL "main.cpp" AND NOT EXISTS "${_f}")
        set(_have_tests FALSE)
    endif()
endforeach()
if(_have_tests)
    add_executable(ocudu-vectors ${_vector_sources})
    target_link_libraries(ocudu-vectors
        -Wl,--start-group ${_libs} "${OCUDU_BUILD}/external/fmt/libfmt.a" -Wl,--end-group
        mbedcrypto sctp pthread dl)
endif()

# P3 R0: OCUDU's ASN.1 decoder reading our RRC (tools/ocudu_vectors/unpack.sh).
add_executable(ocudu-unpack unpack.cpp)
target_link_libraries(ocudu-unpack
    -Wl,--start-group ${_libs} "${OCUDU_BUILD}/external/fmt/libfmt.a" -Wl,--end-group
    mbedcrypto sctp pthread dl)
