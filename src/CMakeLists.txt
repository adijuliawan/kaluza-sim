# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# One directory per layer (architecture.md §3). Each layer target is tagged
# with ksim_layer() so the layer checker can see its links.

foreach(_layer IN LISTS KSIM_LAYERS)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${_layer}/CMakeLists.txt)
        add_subdirectory(${_layer})
    endif()
endforeach()
