# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The secret canary (plan M14); tools/secret_canary.py runs it and scans what
# it writes.

add_executable(ksim_canary canary.cpp)
target_link_libraries(ksim_canary PRIVATE ksim::crypto ksim::codec_nas ksim::codec_uicc ksim::platform ksim::warnings)
