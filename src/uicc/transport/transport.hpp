// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// How a terminal reaches its card (P1 N3; sim-uicc.md §5): asynchronous, so a
// card behind a socket or PC/SC looks the same as one in memory. InProc calls
// the soft card directly but still completes through the executor, so the
// terminal never sees an answer inside its own call.

#pragma once

#include <functional>

#include "platform/executor.hpp"
#include "platform/result.hpp"
#include "uicc/os/card.hpp"

namespace ksim::uicc {

class IApduTransport {
public:
    using Done = std::function<void(Result<Bytes> answer)>;

    virtual ~IApduTransport() = default;
    /// Powers the card (again): `done` gets the ATR, or Errc::closed with no card.
    virtual void reset(Done done) = 0;
    /// One command APDU: `done` gets the response APDU (data and SW1 SW2).
    virtual void transmit(Bytes capdu, Done done) = 0;
};

class InProcTransport final : public IApduTransport {
public:
    InProcTransport(Executor& exec, os::Card* card) : exec_(exec), card_(card) {}

    /// A card removed (nullptr) or inserted, as `sim remove|insert` do.
    void insert(os::Card* card) noexcept { card_ = card; }

    void reset(Done done) override;
    void transmit(Bytes capdu, Done done) override;

private:
    Executor& exec_;
    os::Card* card_;
};

} // namespace ksim::uicc
