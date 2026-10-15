# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_node node_test.cpp persona_test.cpp)
target_compile_definitions(unit_node PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
target_link_libraries(unit_node PRIVATE ksim::node ksim::platform ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_node DISCOVERY_MODE PRE_TEST)
