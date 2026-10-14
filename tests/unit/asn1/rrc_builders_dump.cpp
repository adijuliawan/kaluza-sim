// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Prints every RRC builder sample as "channel<TAB>name<TAB>hex" (P1 N6), for
// tests/oracles/oracle.py builders.

#include <cstdio>

#include "rrc_samples.hpp"

int main() {
    int bad = 0;
    for (const auto& s : ksim::rrc::samples::all()) {
        if (!s.bytes) {
            std::fprintf(stderr, "%s: %s\n", s.name.c_str(), s.bytes.error().what);
            ++bad;
            continue;
        }
        std::printf("%s\t%s\t%s\n", s.channel.c_str(), s.name.c_str(), ksim::to_hex(*s.bytes).c_str());
    }
    return bad == 0 ? 0 : 1;
}
