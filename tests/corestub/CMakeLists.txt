# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The core stub (P1 N5, ADR 0009 point f): the AMF's NAS side and the home
# functions, for procedure tests in virtual time. Tests only.

add_library(ksim_corestub STATIC home.cpp amf.cpp ngap_amf.cpp)
target_include_directories(ksim_corestub PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ksim_corestub PUBLIC ksim::proc ksim::crypto ksim::codec_nas ksim::codec_ngap ksim::platform PRIVATE ksim::warnings)
