# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_buildinfo buildinfo_test.cpp)
target_link_libraries(unit_buildinfo PRIVATE ksim::buildinfo ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_buildinfo DISCOVERY_MODE PRE_TEST)

add_subdirectory(platform)
add_subdirectory(crypto)
add_subdirectory(nas)
if(KSIM_ASN1)
    add_subdirectory(asn1)
endif()
