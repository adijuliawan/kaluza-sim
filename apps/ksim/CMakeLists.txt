# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(ksim main.cpp)
target_link_libraries(ksim PRIVATE ksim::node ksim::buildinfo CLI11::CLI11 ksim::warnings)
