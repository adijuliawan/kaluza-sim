# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(unit_platform
    result_test.cpp
    blocking_test.cpp
    assoc_slot_test.cpp
    assoc_pool_test.cpp
    buf_test.cpp
    secret_test.cpp
    timer_wheel_test.cpp
    runtime_test.cpp
    pcapng_test.cpp
    executor_test.cpp
    sim_loop_test.cpp
    rng_test.cpp
    yaml_test.cpp
    event_test.cpp
    coro_test.cpp)
target_link_libraries(unit_platform PRIVATE ksim::platform ksim::warnings GTest::gtest_main)
gtest_discover_tests(unit_platform DISCOVERY_MODE PRE_TEST)
