# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# KAIR v1, the simulated Uu link (P1 N6; architecture.md §2.3).

add_library(ksim_codec_air STATIC kair.cpp)
add_library(ksim::codec_air ALIAS ksim_codec_air)
target_include_directories(ksim_codec_air PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_air PUBLIC ksim::platform PRIVATE ksim::warnings)
ksim_layer(ksim_codec_air codec)
