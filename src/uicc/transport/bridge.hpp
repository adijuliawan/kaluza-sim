// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The card bridge's command filter (P2 Q1; lab.md §7, row
// ksim-p2.bridge-refuses-admin). The bridge (ksim-sim serve --pcsc) lends a
// real card to a UE on the lab VM; unless it was started with --admin it
// answers these itself, with 6982, and never sends them to the card:
//   - VERIFY, CHANGE, DISABLE, ENABLE and UNBLOCK of an ADM key (P2 0A..0E);
//   - UPDATE BINARY and UPDATE RECORD while the key files AF20 or AF30 are
//     selected (the card's ARR asks ADM1 there anyway);
//   - CREATE, DELETE and TERMINATE (DF, EF, card usage).
// A UE's own traffic (SELECT, READ, UPDATE of its EFs, AUTHENTICATE, PIN1)
// passes untouched.

#pragma once

#include <cstdint>
#include <optional>

#include "platform/buf.hpp"

namespace ksim::uicc::bridge {

class AdminFilter {
public:
    explicit AdminFilter(bool admin) noexcept : admin_(admin) {}

    /// Nothing: send the command to the card. A status word: answer it
    /// instead. Follows SELECT by FID or path to know the current file.
    std::optional<std::uint16_t> check(ByteView capdu);
    /// A reset leaves no file selected.
    void reset() noexcept { selected_ = 0; }
    std::uint64_t refused() const noexcept { return refused_; }

private:
    bool admin_;
    std::uint16_t selected_ = 0;
    std::uint64_t refused_ = 0;
};

} // namespace ksim::uicc::bridge
