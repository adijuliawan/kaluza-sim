# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ASN.1 pipeline checks (plan M6):
#  - unit_asn1_link: all five protocol libraries in one binary, one minimal PDU
#    each round-tripped;
#  - asn1_all_headers: every generated header of every protocol in one C++20
#    translation unit;
#  - asn1-nm-hygiene: every global carries its protocol prefix, none defined twice.

add_executable(unit_asn1_link
    link_all_test.cpp ngap_min.cpp f1ap_min.cpp e1ap_min.cpp xnap_min.cpp rrc_min.cpp)
target_link_libraries(unit_asn1_link PRIVATE
    ksim::asn1_rrc ksim::asn1_ngap ksim::asn1_f1ap ksim::asn1_e1ap ksim::asn1_xnap
    ksim::platform GTest::gtest_main)
gtest_discover_tests(unit_asn1_link DISCOVERY_MODE PRE_TEST)

set(_all "${CMAKE_CURRENT_BINARY_DIR}/all_headers.cpp")
set(_text "// Generated: every generated ASN.1 header of every protocol.\n")
foreach(_p IN LISTS KSIM_ASN1_PROTOCOLS)
    string(TOUPPER ${_p} _P)
    file(GLOB _hdrs LIST_DIRECTORIES false "${KSIM_ASN1_${_P}_DIR}/*.h")
    list(SORT _hdrs)
    foreach(_h IN LISTS _hdrs)
        get_filename_component(_n "${_h}" NAME)
        string(APPEND _text "#include \"${_n}\"\n")
    endforeach()
endforeach()
string(APPEND _text "int ksim_asn1_all_headers_compiled() { return 1; }\n")
file(CONFIGURE OUTPUT "${_all}" CONTENT "${_text}")
add_library(asn1_all_headers OBJECT "${_all}")
target_link_libraries(asn1_all_headers PRIVATE
    ksim::asn1_rrc ksim::asn1_ngap ksim::asn1_f1ap ksim::asn1_e1ap ksim::asn1_xnap)

add_test(NAME asn1-nm-hygiene
    COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tools/asn1_nm_check.py"
            --lib "=$<TARGET_FILE:ksim_asn1_rt>"
            --lib "RRC=$<TARGET_FILE:ksim_asn1_rrc>"
            --lib "NGAP=$<TARGET_FILE:ksim_asn1_ngap>"
            --lib "F1AP=$<TARGET_FILE:ksim_asn1_f1ap>"
            --lib "E1AP=$<TARGET_FILE:ksim_asn1_e1ap>"
            --lib "XNAP=$<TARGET_FILE:ksim_asn1_xnap>")
add_test(NAME asn1-nm-hygiene-selftest
    COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tools/asn1_nm_check.py" --self-test)

# The C++ wrapper and the type registry (plan M10).
add_executable(unit_asn1_wrapper wrapper_test.cpp)
target_link_libraries(unit_asn1_wrapper PRIVATE ksim::asn1_registry ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_asn1_wrapper DISCOVERY_MODE PRE_TEST)

add_executable(unit_rrc_msg rrc_msg_test.cpp)
target_link_libraries(unit_rrc_msg PRIVATE ksim::codec_rrc ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_rrc_msg DISCOVERY_MODE PRE_TEST)

add_executable(unit_ngap_msg ngap_msg_test.cpp)
target_link_libraries(unit_ngap_msg PRIVATE ksim::codec_ngap ksim::codec_rrc ksim::warnings GTest::gtest_main)
target_compile_definitions(unit_ngap_msg PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(unit_ngap_msg DISCOVERY_MODE PRE_TEST)

add_executable(unit_e1ap_msg e1ap_msg_test.cpp)
target_link_libraries(unit_e1ap_msg PRIVATE ksim::codec_e1ap ksim::warnings GTest::gtest_main)
target_compile_definitions(unit_e1ap_msg PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(unit_e1ap_msg DISCOVERY_MODE PRE_TEST)

add_executable(unit_f1ap_msg f1ap_msg_test.cpp)
target_link_libraries(unit_f1ap_msg PRIVATE ksim::codec_f1ap ksim::codec_rrc ksim::warnings GTest::gtest_main)
target_compile_definitions(unit_f1ap_msg PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(unit_f1ap_msg DISCOVERY_MODE PRE_TEST)

add_executable(msg_builders_dump msg_builders_dump.cpp)
target_link_libraries(msg_builders_dump PRIVATE ksim::codec_rrc ksim::codec_ngap ksim::codec_f1ap ksim::codec_e1ap ksim::warnings)
