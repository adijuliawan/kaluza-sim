# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private

# ksim, and the split run's roles (P2 Q3; ADR 0011): ksim-cucp, ksim-cuup, ksim-du and ksim-ue are the
# same program with their role fixed, so `ksim-du run -c t.yaml` is `ksim run -c t.yaml --role du`.
foreach(_app IN ITEMS ksim ksim-cucp ksim-cuup ksim-du ksim-ue)
    add_executable(${_app} main.cpp supervisor.cpp)
    target_include_directories(${_app} SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/cpp-httplib)
    target_link_libraries(${_app} PRIVATE ksim::node ksim::buildinfo CLI11::CLI11 ksim::warnings)
    if(NOT _app STREQUAL "ksim")
        string(REPLACE "ksim-" "" _role ${_app})
        target_compile_definitions(${_app} PRIVATE KSIM_FIXED_ROLE="${_role}")
    endif()
endforeach()
