# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# api: the control API (P1 N8, ADR 0009 point 7): the reply model, wait and
# its evidence, and the HTTP server (cpp-httplib, vendored). Depends on
# platform and codec only; the routes themselves are bound in node/.

add_library(ksim_api STATIC
    reply.cpp
    wait.cpp
    http.cpp)
add_library(ksim::api ALIAS ksim_api)
target_include_directories(ksim_api PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(ksim_api SYSTEM PUBLIC ${PROJECT_SOURCE_DIR}/third_party/cpp-httplib)
target_link_libraries(ksim_api PUBLIC ksim::platform nlohmann_json::nlohmann_json PRIVATE ksim::warnings)
ksim_layer(ksim_api api)
