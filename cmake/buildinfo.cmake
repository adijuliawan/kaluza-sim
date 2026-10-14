# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ksim::buildinfo: build identity for run manifests and `--version` output
# (requirements.md §3.3). Configure time is enough because tools/ci.sh
# reconfigures on every run.

find_package(Git QUIET)
set(KSIM_GIT_DESCRIBE "unknown")
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --always --dirty --abbrev=12
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE KSIM_GIT_DESCRIBE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
endif()

string(TIMESTAMP KSIM_CONFIGURE_UTC "%Y-%m-%dT%H:%M:%SZ" UTC)
set(KSIM_BUILD_PRESET "$ENV{KSIM_PRESET}")

configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/build_info.hpp.in
    ${PROJECT_BINARY_DIR}/generated/ksim/build_info.hpp
    @ONLY)

add_library(ksim_buildinfo INTERFACE)
add_library(ksim::buildinfo ALIAS ksim_buildinfo)
target_include_directories(ksim_buildinfo INTERFACE ${PROJECT_BINARY_DIR}/generated)
