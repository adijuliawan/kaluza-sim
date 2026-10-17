// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The message an AP PDU carries, by name (P3 R3: the fault rules name messages; ADR 0013
// point 9): NGAP, F1AP, E1AP and XnAP, whose <PROTO>-PDU is a CHOICE of initiatingMessage,
// successfulOutcome and unsuccessfulOutcome, each with an open-type value whose alternative
// is named after the message's type.

#pragma once

#include <string>
#include <string_view>

#include "platform/buf.hpp"

namespace ksim::asn1 {

/// "InitialContextSetupRequest", or empty when `proto` is not an AP protocol or the bytes
/// do not decode.
std::string message_name(std::string_view proto, ByteView pdu);

} // namespace ksim::asn1
