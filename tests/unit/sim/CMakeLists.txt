# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_sim bundle_test.cpp)
target_link_libraries(unit_sim PRIVATE ksim_sim_bundle ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_sim DISCOVERY_MODE PRE_TEST)
