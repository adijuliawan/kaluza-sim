# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_platform
    result_test.cpp
    buf_test.cpp
    secret_test.cpp)
target_link_libraries(unit_platform PRIVATE ksim::platform ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_platform DISCOVERY_MODE PRE_TEST)
