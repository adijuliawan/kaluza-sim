# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_nas nas_test.cpp sms_test.cpp ie_test.cpp)
target_link_libraries(unit_nas PRIVATE ksim::codec_nas ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_nas DISCOVERY_MODE PRE_TEST)
