# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ksim-codec: decode, encode and JER for every generated ASN.1 type; the
# oracle harness drives its batch mode (plan M10).

add_executable(ksim-codec main.cpp)
target_link_libraries(ksim-codec PRIVATE ksim::asn1_registry ksim::warnings)
