# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_proc nas_sec_test.cpp)
target_link_libraries(unit_proc PRIVATE ksim::proc ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_proc DISCOVERY_MODE PRE_TEST)
