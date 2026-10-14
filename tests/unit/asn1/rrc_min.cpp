// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "RRC_RRCSetupRequest.h"
#include "RRC_UL-CCCH-Message.h"
#include "roundtrip_impl.hpp"

#include <type_traits>

namespace ksim::test {

// RRCSetupRequest (TS 38.331 §6.2.2): randomValue (39 bits), mo-Signalling.
RoundTrip rrc_rrc_setup_request() {
    auto* msg = make<RRC_UL_CCCH_Message_t>();
    msg->message.present = RRC_UL_CCCH_MessageType_PR_c1;
    // The anonymous member struct's C++ name is nested; deduce it, never spell it.
    msg->message.choice.c1 = make<std::remove_pointer_t<decltype(msg->message.choice.c1)>>();
    auto* c1 = msg->message.choice.c1;
    c1->present = RRC_UL_CCCH_MessageType__c1_PR_rrcSetupRequest;
    c1->choice.rrcSetupRequest = make<RRC_RRCSetupRequest_t>();
    auto& ies = c1->choice.rrcSetupRequest->rrcSetupRequest;
    ies.ue_Identity.present = RRC_InitialUE_Identity_PR_randomValue;
    auto* rv = &ies.ue_Identity.choice.randomValue;
    rv->buf = static_cast<std::uint8_t*>(std::calloc(5, 1));
    rv->size = 5;
    rv->bits_unused = 1;  // 39 bits
    const std::uint8_t random[5] = {0x12, 0x34, 0x56, 0x78, 0x9a};
    std::memcpy(rv->buf, random, 5);
    ies.establishmentCause = RRC_EstablishmentCause_mo_Signalling;
    ies.spare.buf = static_cast<std::uint8_t*>(std::calloc(1, 1));
    ies.spare.size = 1;
    ies.spare.bits_unused = 7;  // 1 bit
    return roundtrip(&asn_DEF_RRC_UL_CCCH_Message, msg, Per::unaligned);
}

} // namespace ksim::test
