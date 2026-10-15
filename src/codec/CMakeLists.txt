# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# codec: pure functions over bytes (rule R3). ASN.1 libraries come from asn1c;
# NAS, SMS, GTP-U, NR-U, PSC and APDU codecs are hand-written (M11, M12).

if(KSIM_ASN1)
    add_subdirectory(asn1)
endif()
add_subdirectory(nas)
add_subdirectory(up)
add_subdirectory(ip)
add_subdirectory(air)
add_subdirectory(pdcp)
add_subdirectory(sdap)
add_subdirectory(uicc)
