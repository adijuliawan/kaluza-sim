// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A check the core stub made, with the clause it comes from (P1 N5).

#pragma once

#include <string>

namespace ksim::corestub {

struct Verdict {
    std::string clause;
    std::string what;
    bool ok = false;
    std::string detail;
};

} // namespace ksim::corestub
