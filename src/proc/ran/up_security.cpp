// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ran/up_security.hpp"

#include "platform/mutation.hpp"

namespace ksim::proc::ran {

UpDecision decide_up_security(const std::optional<ngap::SecurityIndication>& in, const UpPolicy& p) {
    UpDecision d;
    if (!in) {
        d.integrity = p.absent_integrity && p.integrity_possible;
        d.confidentiality = p.absent_confidentiality;
        return d;
    }
    d.indicated = true;
    if (in->integrity == "required") {
        if (!p.integrity_possible && !KSIM_MUTANT("up_required_accepted")) {
            d.refuse = ngap::Cause{"radioNetwork", "up-integrity-protection-not-possible"};
            return d;
        }
        d.integrity = p.integrity_possible;
    } else if (in->integrity == "preferred") {
        d.integrity = p.preferred_integrity && p.integrity_possible;
        d.report = true;
    }
    if (in->confidentiality == "required") {
        d.confidentiality = true;
    } else if (in->confidentiality == "preferred") {
        d.confidentiality = p.preferred_confidentiality;
        d.report = true;
    }
    return d;
}

} // namespace ksim::proc::ran
