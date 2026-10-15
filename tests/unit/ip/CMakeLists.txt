# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_ip ipv4_test.cpp)
target_link_libraries(unit_ip PRIVATE ksim::codec_ip ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_ip DISCOVERY_MODE PRE_TEST)
