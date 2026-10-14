// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "XNAP_InitiatingMessage.h"
#include "XNAP_XnAP-PDU.h"
#include "roundtrip_impl.hpp"

namespace ksim::test {

RoundTrip xnap_xn_setup_request() {
    auto* pdu = make<XNAP_XnAP_PDU_t>();
    pdu->present = XNAP_XnAP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = make<XNAP_InitiatingMessage_t>();
    auto* im = pdu->choice.initiatingMessage;
    im->procedureCode = XNAP_ProcedureCode_id_xnSetup;
    im->criticality = XNAP_Criticality_reject;
    im->value.present = XNAP_InitiatingMessage__value_PR_XnSetupRequest;
    return roundtrip(&asn_DEF_XNAP_XnAP_PDU, pdu, Per::aligned);
}

} // namespace ksim::test
