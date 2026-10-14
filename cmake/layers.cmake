# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Code layering (architecture.md §3, rules R1–R8).
#
# ksim_layer(<target> <layer>) tags a target with its layer. When configuring
# ends, ksim_write_layer_graph() writes <build>/layers.json: every tagged target,
# its layer and its direct link libraries. tools/guards/check_layers.py checks
# that graph and the #include lines under src/ against the same rule table.

set(KSIM_LAYERS platform net crypto codec entity uicc radio proc node api)

function(ksim_layer target layer)
    if(NOT layer IN_LIST KSIM_LAYERS)
        message(FATAL_ERROR "ksim_layer(${target}): unknown layer '${layer}'")
    endif()
    set_property(TARGET ${target} PROPERTY KSIM_LAYER ${layer})
    set_property(GLOBAL APPEND PROPERTY KSIM_LAYER_TARGETS ${target})
endfunction()

function(ksim_write_layer_graph)
    get_property(_targets GLOBAL PROPERTY KSIM_LAYER_TARGETS)
    set(_json "[\n")
    set(_sep "")
    foreach(t IN LISTS _targets)
        get_target_property(_layer ${t} KSIM_LAYER)
        string(APPEND _json "${_sep}  {\"target\": \"${t}\", \"layer\": \"${_layer}\", "
               "\"links\": \"$<JOIN:$<TARGET_PROPERTY:${t},LINK_LIBRARIES>,;>\"}")
        set(_sep ",\n")
    endforeach()
    string(APPEND _json "\n]\n")
    file(GENERATE OUTPUT "${PROJECT_BINARY_DIR}/layers.json" CONTENT "${_json}")
endfunction()
