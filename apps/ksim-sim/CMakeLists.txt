# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

add_executable(ksim-sim main.cpp)
target_link_libraries(ksim-sim PRIVATE ksim::uicc ksim::crypto CLI11::CLI11 nlohmann_json::nlohmann_json ksim::warnings)
