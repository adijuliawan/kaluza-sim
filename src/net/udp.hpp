// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// UDP behind IDatagram (P1 N2): NG-U and later F1-U and Xn-U carry GTP-U on
// it. Bound to an explicit address (architecture §2.2), non-blocking, read in
// batches with recvmmsg (data-plane.md §3). A datagram the kernel cannot take
// at once is dropped and counted, as UDP would.

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "platform/reactor.hpp"
#include "platform/transport.hpp"

namespace ksim::net {

class UdpSocket final : public IDatagram {
public:
    /// Port 0 picks one; local() then tells which.
    static Result<std::unique_ptr<UdpSocket>> bind(Reactor& reactor, const Endpoint& local);
    /// From a socket already bound elsewhere (ksim-netd passes one in a netns).
    static Result<std::unique_ptr<UdpSocket>> adopt(Reactor& reactor, Fd fd);
    /// Binds a socket made elsewhere (ksim-netd's, still unbound) to `local`, then adopts it.
    static Result<std::unique_ptr<UdpSocket>> bind(Reactor& reactor, Fd fd, const Endpoint& local);
    ~UdpSocket() override;
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    void set_handler(OnDatagram on_datagram) override { on_datagram_ = std::move(on_datagram); }
    Result<void> send_to(ByteView payload, const Endpoint& to) override;
    Endpoint local() const override { return local_; }
    std::uint64_t dropped() const noexcept override { return dropped_; }
    std::uint64_t received() const noexcept { return received_; }

private:
    UdpSocket(Reactor& r, Fd fd, Endpoint local);
    void read_all();

    static constexpr std::size_t kBatch = 64;
    static constexpr std::size_t kMaxDatagram = 9216;   // a jumbo frame's payload

    Reactor& reactor_;
    Fd fd_;
    Endpoint local_;
    OnDatagram on_datagram_;
    std::vector<std::uint8_t> bufs_;
    std::uint64_t dropped_ = 0;
    std::uint64_t received_ = 0;
};

} // namespace ksim::net
