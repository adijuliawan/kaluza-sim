# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_up up_test.cpp)
target_link_libraries(unit_up PRIVATE ksim::codec_up ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_up DISCOVERY_MODE PRE_TEST)
