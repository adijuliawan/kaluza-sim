# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Without libFuzzer (gcc presets), fuzz targets link this replay driver and run
# their corpus as a ctest (cmake/fuzz.cmake).

if(NOT KSIM_FUZZ)
    add_library(ksim_fuzz_replay STATIC replay_main.cpp)
    target_link_libraries(ksim_fuzz_replay PRIVATE ksim::warnings)
endif()

# The fuzz targets (plan M14): each ASN.1 protocol's decoder, the hand-written
# codecs, and the smoke's must-fail target. tools/ci.d/60-fuzz.sh runs them.
if(KSIM_ASN1)
    foreach(proto ngap f1ap e1ap xnap rrc)
        ksim_add_fuzzer(fuzz_asn1_${proto} SOURCES fuzz_asn1.cpp LIBS ksim::asn1_registry)
        target_compile_definitions(fuzz_asn1_${proto} PRIVATE KSIM_FUZZ_PROTO="${proto}")
    endforeach()
endif()
ksim_add_fuzzer(fuzz_codecs SOURCES fuzz_l3.cpp LIBS ksim::codec_nas ksim::codec_up ksim::codec_uicc)
ksim_add_fuzzer(fuzz_mustfail SOURCES fuzz_mustfail.cpp)
# P1 N3: the soft card under arbitrary APDU streams.
ksim_add_fuzzer(fuzz_card SOURCES fuzz_card.cpp LIBS ksim::uicc)
target_compile_definitions(fuzz_card PRIVATE KSIM_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
# P1 N4: the typed NAS IEs and the NAS security context.
ksim_add_fuzzer(fuzz_nas_ies SOURCES fuzz_nas_ies.cpp LIBS ksim::proc)
