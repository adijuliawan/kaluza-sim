# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_api api_test.cpp)
target_link_libraries(unit_api PRIVATE ksim::api ksim::platform ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_api DISCOVERY_MODE PRE_TEST)
