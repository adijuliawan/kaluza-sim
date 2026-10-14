# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The ASN.1 pipeline (architecture.md §4.1). Milestone M4 pins the compiler; M6
# adds stamp-keyed generation and one static library per protocol. Until then
# this only records where the pinned compiler is expected.

set(KSIM_ASN1C "$ENV{HOME}/.local/opt/asn1c-18e56503/bin/asn1c"
    CACHE FILEPATH "The pinned asn1c (mouse07410 fork at 18e56503)")
