# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# entity: passive protocol entities (P1 N6, rule R4): PDCP, SDAP and the ideal
# RLC/MAC seams. Time from an injected TimerService, I/O through injected
# sinks; no threads, no sockets. Depends on platform, codec and crypto only.

add_library(ksim_entity STATIC
    mac/ue_ideal.cpp
    pdcp/pdcp.cpp
    sdap/sdap.cpp)
add_library(ksim::entity ALIAS ksim_entity)
target_include_directories(ksim_entity PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_entity
    PUBLIC ksim::platform ksim::codec_air ksim::codec_pdcp ksim::codec_sdap ksim::crypto
    PRIVATE ksim::warnings)
ksim_layer(ksim_entity entity)
