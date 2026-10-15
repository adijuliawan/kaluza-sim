# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Procedure tests (P1 N5, ADR 0009 point f): entities against the core stub
# on a SimLoop, in virtual time, named by clause.

add_executable(procedure_nas nas_mm_test.cpp eap_test.cpp)
target_link_libraries(procedure_nas PRIVATE ksim_corestub ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_nas PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_nas DISCOVERY_MODE PRE_TEST)

add_executable(procedure_rrc rrc_ue_test.cpp)
target_link_libraries(procedure_rrc PRIVATE ksim::proc ksim::warnings GTest::gtest_main)
gtest_discover_tests(procedure_rrc DISCOVERY_MODE PRE_TEST)

add_executable(procedure_ran ran_test.cpp)
target_link_libraries(procedure_ran PRIVATE ksim_corestub ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_ran PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_ran DISCOVERY_MODE PRE_TEST)

add_executable(procedure_session session_test.cpp)
target_link_libraries(procedure_session PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
gtest_discover_tests(procedure_session DISCOVERY_MODE PRE_TEST)
target_compile_definitions(procedure_session PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

add_executable(procedure_idle idle_test.cpp)
target_link_libraries(procedure_idle PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_idle PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_idle DISCOVERY_MODE PRE_TEST)
