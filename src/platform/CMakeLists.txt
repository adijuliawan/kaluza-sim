# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# platform: depends on nothing else in the tree (rule R1). OpenSSL is used only
# for zeroizing, constant-time compare and the redaction fingerprint; fmt for
# the log façade (plan M13).

add_library(ksim_platform STATIC
    result.cpp
    buf.cpp
    secret.cpp
    clock.cpp
    timer_wheel.cpp
    reactor.cpp
    shard.cpp
    log.cpp
    pcapng.cpp)
add_library(ksim::platform ALIAS ksim_platform)
target_include_directories(ksim_platform PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_platform PUBLIC OpenSSL::Crypto fmt::fmt Threads::Threads PRIVATE ksim::warnings)
ksim_layer(ksim_platform platform)
