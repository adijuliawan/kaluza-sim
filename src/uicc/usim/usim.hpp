// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The USIM application on the soft card (P1 N3; 3GPP TS 31.102 §7;
// sim-uicc.md §4): AUTHENTICATE in the 3G context (P2 '81', the context 5G AKA
// uses), with the card's own algorithm and SQN check, and GET IDENTITY.
//
// The keys come from the key file EF.USIM_AUTH_KEY (AF20), in the sysmoISIM
// layout so one burn path serves soft and real cards: a configuration byte
// (algorithm in the low nibble, Milenage 4 or TUAK 6; b5 set when the next
// value is OPc, not OP), then for Milenage K (16) and OP/OPc (16), for TUAK a
// TUAK configuration byte, the Keccak iteration count, TOP/TOPc (32) and K.
// The SQN state lives in EF.USIM_SQN (AF30): two flag octets (SQN check, Δ
// check, the IND length), Δmax and the age limit (6 octets each), then the
// highest SQN accepted for each IND value (6 octets each; TS 33.102 Annex C).

#pragma once

#include <optional>

#include "uicc/os/card.hpp"

namespace ksim::uicc::usim {

/// The USIM's AID prefix (TS 101 220 Annex E: RID A000000087, application code 1002).
inline constexpr std::uint8_t kUsimAid[] = {0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02};

inline constexpr std::uint16_t kEfUst = 0x6F38;
inline constexpr std::uint16_t kEfAuthKey = 0xAF20;
inline constexpr std::uint16_t kEfSqn = 0xAF30;

class Usim final : public os::Application {
public:
    std::optional<Response> handle(os::Card& card, os::Channel& ch, const Command& c) override;

private:
    Response authenticate(os::Card& card, os::Channel& ch, const Command& c);
    Response get_identity(os::Card& card, os::Channel& ch, const Command& c);
};

/// Whether service `n` (1-based) is available in an EF.UST's contents.
bool service_available(ByteView ust, unsigned n) noexcept;

} // namespace ksim::uicc::usim
