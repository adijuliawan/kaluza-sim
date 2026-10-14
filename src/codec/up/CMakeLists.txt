# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# User plane codecs (plan M12): GTP-U (TS 29.281) and the frames it carries in
# extension headers, the PDU Session Container (TS 38.415) and the NR RAN
# Container (TS 38.425).

add_library(ksim_codec_up STATIC gtpu.cpp frames.cpp)
add_library(ksim::codec_up ALIAS ksim_codec_up)
target_include_directories(ksim_codec_up PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_up PUBLIC ksim::platform PRIVATE ksim::warnings)
ksim_layer(ksim_codec_up codec)
