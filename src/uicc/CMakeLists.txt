# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# uicc: the soft card (os, usim, image, secrets), its transports and the
# terminal (P1 N3; sim-uicc.md). Depends on platform, codec and crypto only
# (rule R5: the card OS knows nothing of UEs, the terminal nothing of NAS).

add_library(ksim_uicc STATIC
    os/card.cpp
    os/keyfile.cpp
    usim/usim.cpp
    secrets/secrets.cpp
    image/image.cpp
    transport/inproc.cpp
    terminal/terminal.cpp)
add_library(ksim::uicc ALIAS ksim_uicc)
target_include_directories(ksim_uicc PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_uicc PUBLIC ksim::platform ksim::codec_uicc ksim::crypto PRIVATE ksim::warnings)
ksim_layer(ksim_uicc uicc)
