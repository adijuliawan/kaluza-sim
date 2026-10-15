# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_uicc_card
    card_test.cpp
    usim_test.cpp
    image_test.cpp
    terminal_test.cpp
    range_test.cpp
    vpcd_test.cpp
    trace_test.cpp)
target_link_libraries(unit_uicc_card PRIVATE ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(unit_uicc_card PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(unit_uicc_card DISCOVERY_MODE PRE_TEST)
