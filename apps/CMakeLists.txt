# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_subdirectory(ksim-selftest)
if(KSIM_ASN1)
    add_subdirectory(ksim-codec)
    add_subdirectory(ksim)
    add_subdirectory(ksim-ctl)
    add_subdirectory(ksim-corestub)
endif()
add_subdirectory(ksim-sim)
add_subdirectory(ksim-netd)
add_subdirectory(ksim-bench)
