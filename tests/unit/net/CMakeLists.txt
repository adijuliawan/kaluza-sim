# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_net
    assoc_test.cpp
    datagram_test.cpp)
target_link_libraries(unit_net PRIVATE ksim::net ksim::platform ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_net DISCOVERY_MODE PRE_TEST)
