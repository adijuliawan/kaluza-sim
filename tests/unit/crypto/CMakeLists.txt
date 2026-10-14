# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Crypto checks (plan M9):
#  - unit_crypto: every set of every spec/kat file, the key traps and OCUDU's
#    gNB-side key vectors;
#  - crypto-keychain-oracle: the Python oracle (tests/oracles/keychain.py),
#    written from the specification text, against keychain_dump on 10k
#    random synthetic subscribers.

add_executable(unit_crypto kat_test.cpp keys5g_test.cpp)
target_link_libraries(unit_crypto PRIVATE ksim::crypto ksim::warnings GTest::gtest_main)
target_compile_definitions(unit_crypto PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(unit_crypto DISCOVERY_MODE PRE_TEST)

add_executable(keychain_dump keychain_dump.cpp)
target_link_libraries(keychain_dump PRIVATE ksim::crypto ksim::warnings)
add_test(NAME crypto-keychain-oracle
    COMMAND python3 -I ${PROJECT_SOURCE_DIR}/tests/oracles/keychain.py --cxx $<TARGET_FILE:keychain_dump> --n 10000)
# Must-fail: the oracle commits each key trap in turn and must then disagree.
foreach(_m kamf-bcd kgnb-3-octet-count snn-no-pad)
    add_test(NAME crypto-keychain-oracle-mustfail-${_m}
        COMMAND python3 -I ${PROJECT_SOURCE_DIR}/tests/oracles/keychain.py --cxx $<TARGET_FILE:keychain_dump>
                --n 200 --mutate ${_m})
    set_tests_properties(crypto-keychain-oracle-mustfail-${_m} PROPERTIES WILL_FAIL TRUE)
endforeach()
