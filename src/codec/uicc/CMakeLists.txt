# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# UICC codecs (plan M12): APDUs (ETSI TS 102 221 clause 10, TS 31.102 clause 7)
# and BER-TLV with the FCP template (TS 102 221 11.1.1).

add_library(ksim_codec_uicc STATIC apdu.cpp fcp.cpp)
add_library(ksim::codec_uicc ALIAS ksim_codec_uicc)
target_include_directories(ksim_codec_uicc PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_codec_uicc PUBLIC ksim::platform PRIVATE ksim::warnings)
ksim_layer(ksim_codec_uicc codec)
