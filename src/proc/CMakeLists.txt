# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# proc: the UE's and the RAN's procedures (P1, ADR 0009): single-threaded per
# actor, never blocking, sending through ports (rule R6). Depends on platform,
# codec, crypto, entity, uicc and radio only.

add_library(ksim_proc STATIC
    ue/nas_sec/nas_sec.cpp)
add_library(ksim::proc ALIAS ksim_proc)
target_include_directories(ksim_proc PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_proc PUBLIC ksim::platform ksim::codec_nas ksim::crypto PRIVATE ksim::warnings)
ksim_layer(ksim_proc proc)
