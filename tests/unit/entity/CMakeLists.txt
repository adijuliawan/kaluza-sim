# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_entity pdcp_test.cpp mac_sdap_test.cpp gtpu_test.cpp)
target_link_libraries(unit_entity PRIVATE ksim::entity ksim::warnings GTest::gtest_main)
target_compile_definitions(unit_entity PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(unit_entity DISCOVERY_MODE PRE_TEST)
