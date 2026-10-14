# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_subdirectory(ksim-selftest)
if(KSIM_ASN1)
    add_subdirectory(ksim-codec)
endif()
