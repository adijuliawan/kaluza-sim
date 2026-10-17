# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# node: binds the procedures to threads, sockets and files (P1 N8): the UE
# device, and the all-in-one node with its topology, run directory, captures,
# dev-PC guard and control routes. Depends on every layer below it.

add_library(ksim_node STATIC
    ue/device.cpp
    ue/dataplane.cpp
    ue/persona.cpp
    aio/topology.cpp
    aio/run_dir.cpp
    aio/capture.cpp
    aio/faults.cpp
    aio/guard.cpp
    aio/aio.cpp
    aio/control.cpp
    aio/metrics.cpp)
add_library(ksim::node ALIAS ksim_node)
target_include_directories(ksim_node PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_node
    PUBLIC ksim::proc ksim::net ksim::api ksim::uicc ksim::platform ksim::codec_air ksim::codec_ip ksim::codec_ngap ksim::codec_up ksim::codec_names ksim::crypto
    PRIVATE ksim::buildinfo ksim::warnings)
ksim_layer(ksim_node node)
if(KSIM_PCSC)
    target_link_libraries(ksim_node PUBLIC ksim::uicc_pcsc)   # P2 Q1: card: {pcsc: …}
endif()
