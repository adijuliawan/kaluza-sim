# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_net
    assoc_test.cpp
    datagram_test.cpp
    netlink_test.cpp
    netd_test.cpp)
target_link_libraries(unit_net PRIVATE ksim::net ksim::platform ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_net DISCOVERY_MODE PRE_TEST)

# The privileged smoke's client (tools/ci.d/66-netd-priv.sh); not a ctest test.
add_executable(netd_smoke netd_smoke.cpp)
target_link_libraries(netd_smoke PRIVATE ksim::net ksim::warnings)
