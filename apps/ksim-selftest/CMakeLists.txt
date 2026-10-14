# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ksim-selftest: prints the build identity and runs the built-in self-checks
# (KATs and codec probes as they land). M16 runs it on kaluza-uesim.

add_executable(ksim-selftest main.cpp)
target_link_libraries(ksim-selftest PRIVATE ksim::buildinfo ksim::warnings)
