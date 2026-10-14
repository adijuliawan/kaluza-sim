# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Without libFuzzer (gcc presets), fuzz targets link this replay driver and run
# their corpus as a ctest (cmake/fuzz.cmake).

if(NOT KSIM_FUZZ)
    add_library(ksim_fuzz_replay STATIC replay_main.cpp)
    target_link_libraries(ksim_fuzz_replay PRIVATE ksim::warnings)
endif()
