# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(ksim-ctl main.cpp)
target_link_libraries(ksim-ctl PRIVATE ksim::api ksim::buildinfo CLI11::CLI11 ksim::warnings)
