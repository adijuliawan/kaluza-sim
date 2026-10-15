// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The listening side's association (P2 Q2; ADR 0011): the CU-CP listens for
// F1-C and E1, and a peer may go and come back, while the procedure holds one
// IAssoc for life. AssocSlot is that IAssoc. Each association a listener
// accepts is taken into it: the slot reports it `up` (an accepted association
// is born up and says nothing itself) and forwards its messages and events.
// One peer at a time in P2: a second association while one is up is aborted
// at once and counted (row ksim-p2.f1-reassociation's accepted-peer policy).
// Pure: no socket here, so memlink and SCTP serve alike.

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "platform/transport.hpp"

namespace ksim {

class AssocSlot final : public IAssoc {
public:
    AssocSlot() = default;
    ~AssocSlot() override;
    AssocSlot(const AssocSlot&) = delete;
    AssocSlot& operator=(const AssocSlot&) = delete;

    /// An accepted association. False when one is up already: then `a` is
    /// aborted and dropped. Call it from the listener's accept callback,
    /// never from inside an association's own callbacks.
    bool take(std::unique_ptr<IAssoc> a);
    std::uint64_t taken() const noexcept { return taken_; }
    std::uint64_t refused() const noexcept { return refused_; }

    void set_handlers(OnMessage on_message, OnEvent on_event) override;
    Result<void> send(ByteView msg, SctpMeta meta) override;
    bool up() const noexcept override;
    std::uint16_t out_streams() const noexcept override;
    std::uint16_t in_streams() const noexcept override;
    void shutdown() override;
    void abort() override;
    Endpoint peer() const override;

private:
    std::unique_ptr<IAssoc> cur_;
    std::vector<std::unique_ptr<IAssoc>> retired_;   // freed at the next take, never inside their callbacks
    OnMessage on_message_;
    OnEvent on_event_;
    std::uint64_t taken_ = 0;
    std::uint64_t refused_ = 0;
};

} // namespace ksim
