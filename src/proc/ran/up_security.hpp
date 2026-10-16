// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The CU-CP's UP security decision for a PDU session (P2 Q9; TS 33.501 6.6.1, TS 38.413
// 8.2.1.2, 9.3.1.27, 9.3.1.59): from the SMF's Security Indication, or the CU-CP's local
// policy when there is none.
//
//   required    performed; integrity that this gNB cannot do refuses the session with
//               radioNetwork up-integrity-protection-not-possible (ciphering always can)
//   preferred   performed as the local policy says, and reported in the Security Result
//   not-needed  not performed
//   no IE       the local policy's default (38.413 leaves it open; KS-NGAP-B8)
//
// The maximum integrity-protected data rates are kept with the session; enforcing a
// 64 kbit/s limit is not built (KS-NGAP-G5).
#pragma once

#include <optional>

#include "codec/asn1/msg/ngap.hpp"

namespace ksim::proc::ran {

struct UpPolicy {
    bool preferred_integrity = true;        // "preferred": performed when this gNB can
    bool preferred_confidentiality = true;
    bool absent_integrity = false;          // no Security Indication
    bool absent_confidentiality = true;
    bool integrity_possible = true;         // false: this gNB does no UP integrity
    friend bool operator==(const UpPolicy&, const UpPolicy&) = default;
};

struct UpDecision {
    bool integrity = false;
    bool confidentiality = false;
    bool indicated = false;                 // the SMF sent a Security Indication
    bool report = false;                    // a Security Result goes back (one was "preferred")
    std::optional<ngap::Cause> refuse;      // a "required" this gNB cannot meet
};

UpDecision decide_up_security(const std::optional<ngap::SecurityIndication>& in, const UpPolicy& p);

} // namespace ksim::proc::ran
