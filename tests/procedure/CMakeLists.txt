# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Procedure tests (P1 N5, ADR 0009 point f): entities against the core stub
# on a SimLoop, in virtual time, named by clause.

add_executable(procedure_nas nas_mm_test.cpp)
target_link_libraries(procedure_nas PRIVATE ksim_corestub ksim::proc ksim::uicc ksim::warnings GTest::gtest_main)
target_compile_definitions(procedure_nas PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(procedure_nas DISCOVERY_MODE PRE_TEST)
