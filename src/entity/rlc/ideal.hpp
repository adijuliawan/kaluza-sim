// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The ideal RLC (P1 N6; ADR 0003): SDUs pass whole and in order to the MAC and
// back. The link below never segments; on an AM bearer nothing is lost (loss
// would be ARQ delay), on UM or TM an SDU may be dropped by the link's
// impairments (none in P1; abstraction ledger).

#pragma once

#include "entity/mac/iface.hpp"
#include "entity/rlc/iface.hpp"

namespace ksim::entity {

class IdealRlc final : public IRlcBearer {
public:
    IdealRlc(std::uint8_t lcid, RlcMode mode, IMacSap& mac) : lcid_(lcid), mode_(mode), mac_(mac) {
        mac_.attach(lcid_, this);
    }
    ~IdealRlc() override { mac_.attach(lcid_, nullptr); }
    IdealRlc(const IdealRlc&) = delete;
    IdealRlc& operator=(const IdealRlc&) = delete;

    void write_sdu(Bytes sdu) override { mac_.send(lcid_, mode_, std::move(sdu)); }
    RlcMode mode() const noexcept override { return mode_; }
    std::uint8_t lcid() const noexcept override { return lcid_; }
    void set_upper(std::function<void(Bytes)> upper) override { upper_ = std::move(upper); }
    void receive(Bytes sdu) override {
        if (upper_) {
            upper_(std::move(sdu));
        }
    }

private:
    std::uint8_t lcid_;
    RlcMode mode_;
    IMacSap& mac_;
    std::function<void(Bytes)> upper_;
};

} // namespace ksim::entity
