// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The data ksim-selftest carries (tools/selftest_data.py, generated at
// configure time): KAT files as text and committed corpus vectors.

#pragma once

#include <span>
#include <string_view>

namespace ksim::selftest {

struct Vector {
    const char* proto;   // ngap, f1ap, e1ap, xnap, rrc, nas, gtpu, psc, nru
    const char* type;    // the ASN.1 top type, or the message name
    const char* id;      // the corpus row
    const char* hex;
};

std::string_view kat(std::string_view name);
std::span<const Vector> vectors();

} // namespace ksim::selftest
