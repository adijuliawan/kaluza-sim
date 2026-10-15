# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# IPv4 and ICMP echo (P1 N10): the inject-mode ping and the core stub's DN reflector.

add_library(ksim_codec_ip STATIC ipv4.cpp)
add_library(ksim::codec_ip ALIAS ksim_codec_ip)
target_include_directories(ksim_codec_ip PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_ip PUBLIC ksim::platform PRIVATE ksim::warnings)
ksim_layer(ksim_codec_ip codec)
