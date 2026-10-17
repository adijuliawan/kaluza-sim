# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The radio layer (P3; ADR 0013 point 3, architecture.md §3 R8): pure, platform only.
# R2 brings the seam and its static view; R15 the scene, TR 38.901 and the replicas.
add_library(ksim_radio STATIC view.cpp)
add_library(ksim::radio ALIAS ksim_radio)
target_include_directories(ksim_radio PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_radio PUBLIC ksim::platform PRIVATE ksim::warnings)
target_compile_options(ksim_radio PRIVATE -ffp-contract=off)   # ADR 0013 point 11
ksim_layer(ksim_radio radio)
