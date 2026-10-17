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

add_executable(procedure_faults faults_test.cpp)
target_link_libraries(procedure_faults PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_faults PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_faults DISCOVERY_MODE PRE_TEST)

add_executable(procedure_net2 net2_test.cpp)
target_link_libraries(procedure_net2 PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::radio ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_net2 PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_net2 DISCOVERY_MODE PRE_TEST)

add_executable(procedure_idle idle_test.cpp)
target_link_libraries(procedure_idle PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_idle PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_idle DISCOVERY_MODE PRE_TEST)

add_executable(procedure_sms sms_test.cpp)
target_link_libraries(procedure_sms PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_sms PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_sms DISCOVERY_MODE PRE_TEST)

add_executable(procedure_card card_test.cpp)
target_link_libraries(procedure_card PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_card PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_card DISCOVERY_MODE PRE_TEST)

add_executable(procedure_persona persona_test.cpp)
target_link_libraries(procedure_persona PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_persona PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_persona DISCOVERY_MODE PRE_TEST)

add_executable(procedure_identification identification_test.cpp)
target_link_libraries(procedure_identification PRIVATE ksim_corestub ksim::node ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_identification PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_identification DISCOVERY_MODE PRE_TEST)
