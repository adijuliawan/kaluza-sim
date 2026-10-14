# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Test layers (architecture.md §10): unit/ (codecs, entities, KATs, card OS),
# fuzz/ (libFuzzer targets, replayed as ctests under gcc), oracles/ (Python,
# independent of our C++).

add_subdirectory(fuzz)
add_subdirectory(canary)
add_subdirectory(unit)
