# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_uicc uicc_test.cpp)
target_link_libraries(unit_uicc PRIVATE ksim::codec_uicc ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_uicc DISCOVERY_MODE PRE_TEST)
