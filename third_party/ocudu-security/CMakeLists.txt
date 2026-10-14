# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# OCUDU's SNOW 3G kernel, built unmodified (README.md). Third-party code: its own
# warnings are not ours to fix, so they are silenced here and only here.

add_library(ksim_ocudu_security STATIC src/s3g.cpp)
target_include_directories(ksim_ocudu_security
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/shim
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(ksim_ocudu_security PRIVATE -w)
