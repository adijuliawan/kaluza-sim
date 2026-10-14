# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# PDCP PDU formats (P1 N6; TS 38.323 §6.2).

add_library(ksim_codec_pdcp STATIC pdcp.cpp)
add_library(ksim::codec_pdcp ALIAS ksim_codec_pdcp)
target_include_directories(ksim_codec_pdcp PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_pdcp PUBLIC ksim::platform PRIVATE ksim::warnings)
ksim_layer(ksim_codec_pdcp codec)
