// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "NGAP_InitiatingMessage.h"
#include "NGAP_NGAP-PDU.h"
#include "roundtrip_impl.hpp"

namespace ksim::test {

RoundTrip ngap_ng_setup_request() {
    auto* pdu = make<NGAP_NGAP_PDU_t>();
    pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = make<NGAP_InitiatingMessage_t>();
    auto* im = pdu->choice.initiatingMessage;
    im->procedureCode = NGAP_ProcedureCode_id_NGSetup;
    im->criticality = NGAP_Criticality_reject;
    im->value.present = NGAP_InitiatingMessage__value_PR_NGSetupRequest;
    return roundtrip(&asn_DEF_NGAP_NGAP_PDU, pdu, Per::aligned);
}

} // namespace ksim::test
