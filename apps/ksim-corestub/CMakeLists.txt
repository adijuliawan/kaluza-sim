# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The core stub as a process (ADR 0009 point 8): test tooling, built from
# tests/corestub; never part of a deployment.

add_executable(ksim-corestub main.cpp)
target_link_libraries(ksim-corestub PRIVATE ksim_corestub ksim::net ksim::api ksim::uicc CLI11::CLI11 ksim::warnings)
