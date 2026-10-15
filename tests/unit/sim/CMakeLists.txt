# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_sim bundle_test.cpp burn_test.cpp)
target_link_libraries(unit_sim PRIVATE ksim_sim_bundle ksim_sim_card ksim::warnings GTest::gtest_main)
target_compile_definitions(unit_sim PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(unit_sim DISCOVERY_MODE PRE_TEST)
