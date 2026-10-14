# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# SDAP headers (P1 N6; TS 37.324 §6.2): header-only.

add_library(ksim_codec_sdap INTERFACE)
add_library(ksim::codec_sdap ALIAS ksim_codec_sdap)
target_include_directories(ksim_codec_sdap INTERFACE ${PROJECT_SOURCE_DIR}/src)
