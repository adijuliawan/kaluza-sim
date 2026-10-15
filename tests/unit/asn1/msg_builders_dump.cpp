// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Prints every builder sample as "proto<TAB>name<TAB>hex" (P1 N6, N7, N10), for
// tests/oracles/oracle.py builders.

#include <cstdio>

#include "e1ap_samples.hpp"
#include "f1ap_samples.hpp"
#include "ngap_samples.hpp"
#include "rrc_samples.hpp"

int main() {
    int bad = 0;
    for (const auto& s : ksim::rrc::samples::all()) {
        if (!s.bytes) {
            std::fprintf(stderr, "rrc %s: %s\n", s.name.c_str(), s.bytes.error().what);
            ++bad;
            continue;
        }
        std::printf("rrc\t%s\t%s\n", s.name.c_str(), ksim::to_hex(*s.bytes).c_str());
    }
    for (const auto& s : ksim::ngap::samples::all()) {
        auto b = ksim::ngap::encode(s.pdu);
        if (!b) {
            std::fprintf(stderr, "ngap %s: %s\n", s.name.c_str(), b.error().what);
            ++bad;
            continue;
        }
        std::printf("ngap\t%s\t%s\n", s.name.c_str(), ksim::to_hex(*b).c_str());
    }
    for (const auto& s : ksim::f1ap::samples::all()) {
        auto b = ksim::f1ap::encode(s.pdu);
        if (!b) {
            std::fprintf(stderr, "f1ap %s: %s\n", s.name.c_str(), b.error().what);
            ++bad;
            continue;
        }
        std::printf("f1ap\t%s\t%s\n", s.name.c_str(), ksim::to_hex(*b).c_str());
    }
    for (const auto& s : ksim::e1ap::samples::all()) {
        auto b = ksim::e1ap::encode(s.pdu);
        if (!b) {
            std::fprintf(stderr, "e1ap %s: %s\n", s.name.c_str(), b.error().what);
            ++bad;
            continue;
        }
        std::printf("e1ap\t%s\t%s\n", s.name.c_str(), ksim::to_hex(*b).c_str());
    }
    return bad == 0 ? 0 : 1;
}
