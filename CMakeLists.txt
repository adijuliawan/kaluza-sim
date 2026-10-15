# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# kaluza-sim: a Rel-19 UE + O-RAN RAN simulator (docs/architecture.md).
# Configure through a preset: cmake --preset dev (see CMakePresets.json).

cmake_minimum_required(VERSION 3.28)

project(kaluza-sim
    VERSION 0.0.0
    DESCRIPTION "Rel-19 UE and O-RAN RAN simulator"
    LANGUAGES C CXX)

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed; use a preset (build/<preset>/).")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Generated ASN.1 C and the vendored C runtime are compiled as C17 (gcc 15 defaults to C23).
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)  # no C++20 modules; skips the dyndep scan

option(KSIM_WERROR "Treat warnings in hand-written code as errors" ON)
set(KSIM_ARCH_FLAGS "" CACHE STRING "Target-CPU flags, e.g. the release-lab preset's x86-64-v3 set")
option(KSIM_MUTATIONS "Compile the sim mutants' switches in (platform/mutation.hpp; preset mutants)" OFF)
if(KSIM_MUTATIONS)
    add_compile_definitions(KSIM_MUTATIONS=1)
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(jobpools)
include(warnings)
include(sanitizers)
include(fuzz)
include(layers)
include(buildinfo)
include(asn1c)

if(KSIM_ARCH_FLAGS)
    separate_arguments(_ksim_arch NATIVE_COMMAND "${KSIM_ARCH_FLAGS}")
    add_compile_options(${_ksim_arch})
endif()

find_package(OpenSSL 3.0 REQUIRED)
find_package(GTest 1.14 REQUIRED)
find_package(fmt 10 REQUIRED)
find_package(Threads REQUIRED)
find_package(yaml-cpp 0.7 REQUIRED)
# The lab VM has neither libfmt nor libyaml-cpp at run time, and packages there
# are the user's (lab.md 5): the release-lab preset builds fmt header-only and
# links yaml-cpp's static archive, so its binaries need neither (LDD=PASS).
option(KSIM_STATIC_DEPS "fmt header-only and yaml-cpp static" OFF)
if(KSIM_STATIC_DEPS)
    set(KSIM_FMT fmt::fmt-header-only)
    find_library(KSIM_YAML_CPP_STATIC NAMES libyaml-cpp.a REQUIRED)
    add_library(ksim_yaml_cpp_static STATIC IMPORTED)
    set_target_properties(ksim_yaml_cpp_static PROPERTIES
        IMPORTED_LOCATION "${KSIM_YAML_CPP_STATIC}"
        INTERFACE_INCLUDE_DIRECTORIES "$<TARGET_PROPERTY:yaml-cpp::yaml-cpp,INTERFACE_INCLUDE_DIRECTORIES>")
    set(KSIM_YAML ksim_yaml_cpp_static)
else()
    set(KSIM_FMT fmt::fmt)
    set(KSIM_YAML yaml-cpp::yaml-cpp)
endif()
find_package(nlohmann_json 3.11 REQUIRED)
find_package(CLI11 2.4 REQUIRED)
ksim_asn1_generate()

enable_testing()
include(GoogleTest)

add_subdirectory(third_party/ocudu-security)
add_subdirectory(src)
add_subdirectory(apps)
add_subdirectory(tests)

# Written last, once every target exists: the layer checker reads it.
ksim_write_layer_graph()
