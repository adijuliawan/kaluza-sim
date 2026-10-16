# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# ksim-bench (P2 Q8): the user plane's per-packet costs; tools/ci.d/75-bench.sh
# runs it against tests/bench/bounds.tsv.

add_executable(ksim-bench main.cpp)
target_link_libraries(ksim-bench PRIVATE ksim::entity ksim::crypto ksim::platform ksim::warnings)
