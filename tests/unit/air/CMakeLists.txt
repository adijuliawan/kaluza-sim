# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_air kair_test.cpp)
target_link_libraries(unit_air PRIVATE ksim::codec_air ksim::codec_pdcp ksim::codec_sdap ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_air DISCOVERY_MODE PRE_TEST)
