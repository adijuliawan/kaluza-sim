# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

# The SubscriberBundle builder, a library so tests/unit/sim can check it.
add_library(ksim_sim_bundle STATIC bundle.cpp)
target_include_directories(ksim_sim_bundle PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ksim_sim_bundle PUBLIC nlohmann_json::nlohmann_json PRIVATE ksim::warnings)

# The card verbs (serve, the bridge, validate, export, import) and the burn (P2 Q1),
# a library so tests/unit/sim can burn a soft card.
add_library(ksim_sim_card STATIC card.cpp burn.cpp)
target_include_directories(ksim_sim_card PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ksim_sim_card PUBLIC ksim::uicc ksim::net ksim::crypto PRIVATE nlohmann_json::nlohmann_json ksim::warnings)
if(KSIM_PCSC)
    target_link_libraries(ksim_sim_card PUBLIC ksim::uicc_pcsc)   # burn and the card bridge
endif()

add_executable(ksim-sim main.cpp kaluza.cpp)
target_include_directories(ksim-sim SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/cpp-httplib)
target_compile_definitions(ksim-sim PRIVATE CPPHTTPLIB_LISTEN_BACKLOG=128)   # as ksim::api's (KS-PLAT-D8)
target_link_libraries(ksim-sim PRIVATE ksim_sim_bundle ksim_sim_card ksim::uicc ksim::net ksim::crypto CLI11::CLI11
                                       nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto ksim::warnings)
