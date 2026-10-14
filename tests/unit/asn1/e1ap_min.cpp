// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "E1AP_E1AP-PDU.h"
#include "E1AP_InitiatingMessage.h"
#include "roundtrip_impl.hpp"

namespace ksim::test {

RoundTrip e1ap_cu_up_e1_setup_request() {
    auto* pdu = make<E1AP_E1AP_PDU_t>();
    pdu->present = E1AP_E1AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = make<E1AP_InitiatingMessage_t>();
    auto* im = pdu->choice.initiatingMessage;
    im->procedureCode = E1AP_ProcedureCode_id_gNB_CU_UP_E1Setup;
    im->criticality = E1AP_Criticality_reject;
    im->value.present = E1AP_InitiatingMessage__value_PR_GNB_CU_UP_E1SetupRequest;
    return roundtrip(&asn_DEF_E1AP_E1AP_PDU, pdu, Per::aligned);
}

} // namespace ksim::test
