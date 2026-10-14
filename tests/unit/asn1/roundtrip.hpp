// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One minimal PDU per protocol, encoded, decoded and re-encoded (plan M6). Each
// protocol lives in its own translation unit; the test binary links all five
// libraries together, which is the point: no symbol may clash.

#pragma once

#include <cstddef>
#include <string>

namespace ksim::test {

struct RoundTrip {
    bool encoded = false;
    bool decoded = false;
    bool identical = false;   // re-encoding the decoded value gives the same bytes
    std::size_t bits = 0;
    std::string hex;
};

RoundTrip ngap_ng_setup_request();
RoundTrip f1ap_f1_setup_request();
RoundTrip e1ap_cu_up_e1_setup_request();
RoundTrip xnap_xn_setup_request();
RoundTrip rrc_rrc_setup_request();

} // namespace ksim::test
