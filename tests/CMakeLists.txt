# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Test layers (architecture.md §10): unit/ (codecs, entities, KATs, card OS),
# fuzz/ (libFuzzer targets, replayed as ctests under gcc), oracles/ (Python,
# independent of our C++), corestub/ and procedure/ (entities against the
# scripted core in virtual time, P1 N5).

add_subdirectory(fuzz)
add_subdirectory(canary)
add_subdirectory(unit)
add_subdirectory(corestub)
add_subdirectory(procedure)
