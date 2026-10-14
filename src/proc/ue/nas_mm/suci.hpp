// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The subscription the UE reads from its USIM, and its null-scheme SUCI (P1
// N5; TS 31.102 §4.2.2 EF.IMSI, §4.2.18 EF.AD, §4.4.11.11
// EF.Routing_Indicator; TS 33.501 §6.12.2, TS 23.003 §2.2B). P1 runs the null
// scheme only (D6): the scheme output is the MSIN in BCD, not the whole IMSI.

#pragma once

#include <string>
#include <string_view>

#include "codec/nas/ie/ie.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::proc::ue {

struct Subscription {
    std::string imsi;      // the SUPI's digits
    nas::ie::Plmn home;    // MCC and MNC, the MNC's length from EF.AD
    std::string msin;
};

/// EF.IMSI (length octet, then BCD with the parity and type in the first
/// nibble) and EF.AD (the MNC length in octet 4, bits 1-4: 2 or 3).
Result<Subscription> read_subscription(ByteView ef_imsi, ByteView ef_ad);
/// EF.Routing_Indicator: up to four BCD digits, 'F' filled; "0" when absent or empty.
std::string read_routing_indicator(ByteView ef);
/// The null-scheme SUCI (protection scheme 0, home network key id 0).
nas::ie::MobileIdentity null_suci(const Subscription& s, std::string_view routing_indicator);

} // namespace ksim::proc::ue
