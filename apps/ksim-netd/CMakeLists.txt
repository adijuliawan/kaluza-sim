# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(ksim-netd main.cpp)
target_link_libraries(ksim-netd PRIVATE ksim::net CLI11::CLI11 ksim::warnings)
