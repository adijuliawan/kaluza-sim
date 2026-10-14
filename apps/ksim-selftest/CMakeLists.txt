# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ksim-selftest: prints the build identity and runs the built-in self-checks
# (embedded KATs, the committed corpus, a micro-benchmark). M16 runs it on
# kaluza-uesim (tools/deploy-uesim.sh).

find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
set(_data "${CMAKE_CURRENT_BINARY_DIR}/selftest_data.cpp")
execute_process(
    COMMAND ${Python3_EXECUTABLE} -I "${PROJECT_SOURCE_DIR}/tools/selftest_data.py" "${_data}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _log ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "ksim-selftest data failed:\n${_log}${_err}")
endif()
file(GLOB _selftest_inputs CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/spec/kat/*.tsv"
     "${PROJECT_SOURCE_DIR}/tests/vectors/*/index.tsv")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${_selftest_inputs}
             "${PROJECT_SOURCE_DIR}/tools/selftest_data.py")

add_executable(ksim-selftest main.cpp "${_data}")
target_include_directories(ksim-selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ksim-selftest PRIVATE ksim::buildinfo ksim::crypto ksim::codec_nas ksim::codec_up
                      ksim::asn1_registry ksim::warnings)
add_test(NAME ksim-selftest COMMAND ksim-selftest --bench-ms 20)
