// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "F1AP_F1AP-PDU.h"
#include "F1AP_InitiatingMessage.h"
#include "roundtrip_impl.hpp"

namespace ksim::test {

RoundTrip f1ap_f1_setup_request() {
    auto* pdu = make<F1AP_F1AP_PDU_t>();
    pdu->present = F1AP_F1AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = make<F1AP_InitiatingMessage_t>();
    auto* im = pdu->choice.initiatingMessage;
    im->procedureCode = F1AP_ProcedureCode_id_F1Setup;
    im->criticality = F1AP_Criticality_reject;
    im->value.present = F1AP_InitiatingMessage__value_PR_F1SetupRequest;
    return roundtrip(&asn_DEF_F1AP_F1AP_PDU, pdu, Per::aligned);
}

} // namespace ksim::test
