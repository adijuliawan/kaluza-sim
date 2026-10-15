// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A TUN device's descriptor behind IPacketPort (P1 N11; data-plane.md): one
// IP packet per read and per write (IFF_TUN | IFF_NO_PI). ksim-netd opens the
// device inside the UE's namespace and passes the descriptor (non-blocking);
// ksim reads it on its reactor and never touches the namespace. Any
// packet-preserving descriptor works the same (tests use a SOCK_SEQPACKET
// socketpair).

#pragma once

#include <cstdint>
#include <memory>

#include "platform/reactor.hpp"
#include "platform/transport.hpp"

namespace ksim::net {

class TunPort final : public IPacketPort {
public:
    static Result<std::unique_ptr<TunPort>> adopt(Reactor& reactor, Fd fd);
    ~TunPort() override;
    TunPort(const TunPort&) = delete;
    TunPort& operator=(const TunPort&) = delete;

    void set_handler(OnPacket on_packet) override { on_packet_ = std::move(on_packet); }
    Result<void> write(ByteView packet) override;
    std::uint64_t dropped() const noexcept override { return dropped_; }
    std::uint64_t received() const noexcept { return received_; }

private:
    TunPort(Reactor& r, Fd fd);
    void read_all();

    static constexpr std::size_t kMaxPacket = 65535;

    Reactor& reactor_;
    Fd fd_;
    OnPacket on_packet_;
    Bytes buf_;
    std::uint64_t dropped_ = 0;
    std::uint64_t received_ = 0;
};

} // namespace ksim::net
