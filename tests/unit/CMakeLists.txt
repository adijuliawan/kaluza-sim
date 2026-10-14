# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_buildinfo buildinfo_test.cpp)
target_link_libraries(unit_buildinfo PRIVATE ksim::buildinfo ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_buildinfo DISCOVERY_MODE PRE_TEST)

add_subdirectory(platform)
add_subdirectory(net)
add_subdirectory(crypto)
add_subdirectory(nas)
add_subdirectory(up)
add_subdirectory(air)
add_subdirectory(entity)
add_subdirectory(uicc)
add_subdirectory(uicc_card)
add_subdirectory(proc)
add_subdirectory(api)
if(KSIM_ASN1)
    add_subdirectory(asn1)
    add_subdirectory(node)
endif()
