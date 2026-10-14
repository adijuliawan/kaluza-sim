# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# net: kernel sockets behind platform's transport ports (P1 N2, ADR 0009).
# Depends on platform only (R7: socket and epoll calls live here and in node).

add_library(ksim_net STATIC
    sockaddr.cpp
    sctp.cpp
    udp.cpp
    tcp.cpp)
add_library(ksim::net ALIAS ksim_net)
target_include_directories(ksim_net PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_net PUBLIC ksim::platform PRIVATE ksim::warnings)
ksim_layer(ksim_net net)
