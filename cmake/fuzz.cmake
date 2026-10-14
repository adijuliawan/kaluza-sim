# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ksim_add_fuzzer(<name> SOURCES <src>... LIBS <lib>... [CORPUS <dir>])
#
# Every fuzz target is one LLVMFuzzerTestOneInput() in its own source file.
#  - With KSIM_FUZZ=ON (the clang `fuzz` preset) it links libFuzzer.
#  - Otherwise it links a small replay driver, so the target still compiles under
#    gcc and its corpus runs as a ctest (architecture.md §10).

option(KSIM_FUZZ "Build fuzz targets with libFuzzer (clang only)" OFF)

if(KSIM_FUZZ AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "KSIM_FUZZ=ON needs clang (use the fuzz preset)")
endif()

function(ksim_add_fuzzer name)
    cmake_parse_arguments(F "" "CORPUS" "SOURCES;LIBS" ${ARGN})
    add_executable(${name} ${F_SOURCES})
    target_link_libraries(${name} PRIVATE ${F_LIBS} ksim::warnings)
    if(KSIM_FUZZ)
        target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
        target_link_options(${name} PRIVATE -fsanitize=fuzzer)
    else()
        target_link_libraries(${name} PRIVATE ksim_fuzz_replay)
        if(F_CORPUS)
            add_test(NAME fuzz-replay.${name} COMMAND ${name} ${F_CORPUS})
        endif()
    endif()
endfunction()
