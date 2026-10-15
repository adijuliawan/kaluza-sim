# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

# The SubscriberBundle builder, a library so tests/unit/sim can check it.
add_library(ksim_sim_bundle STATIC bundle.cpp)
target_include_directories(ksim_sim_bundle PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ksim_sim_bundle PUBLIC nlohmann_json::nlohmann_json PRIVATE ksim::warnings)

add_executable(ksim-sim main.cpp kaluza.cpp card.cpp)
target_include_directories(ksim-sim SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/cpp-httplib)
target_link_libraries(ksim-sim PRIVATE ksim_sim_bundle ksim::uicc ksim::net ksim::crypto CLI11::CLI11 nlohmann_json::nlohmann_json
                                       OpenSSL::SSL OpenSSL::Crypto ksim::warnings)
