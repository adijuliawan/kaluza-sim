// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// In-memory transports (P1 N2, ADR 0009): an SCTP-like association between two
// ends, and a datagram network, each end on its own executor (one SimLoop, or
// different shards). Messages carry encoded bytes, as on a socket, and arrive
// one hop later: `delay_ms` plus a seeded jitter in [0, jitter_ms], never out
// of order within a direction (architecture §5: the ideal link adds 1 ms per
// hop plus seeded jitter). Used for F1 and E1 in the all-in-one `ksim` and for
// procedure tests; NG-C and NG-U stay real sockets.

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "platform/executor.hpp"
#include "platform/rng.hpp"
#include "platform/transport.hpp"

namespace ksim {

struct MemLinkConfig {
    Millis delay_ms = 1;
    Millis jitter_ms = 0;
    std::uint64_t seed = 0;
};

/// Two connected IAssoc ends. connect() brings both up one hop later; each
/// end's events and messages run on that end's executor. The pair must
/// outlive its ends' users; deliveries in flight to a destroyed pair are dropped.
class MemAssocPair {
public:
    MemAssocPair(Executor& a_exec, Endpoint a_addr, Executor& b_exec, Endpoint b_addr, std::uint16_t streams,
                 MemLinkConfig config = {});
    ~MemAssocPair();
    MemAssocPair(const MemAssocPair&) = delete;
    MemAssocPair& operator=(const MemAssocPair&) = delete;

    IAssoc& a() noexcept;
    IAssoc& b() noexcept;
    /// Establishes the association (again, after an end shut it down).
    void connect();

    struct Shared;

private:
    std::shared_ptr<Shared> s_;
};

/// A datagram network: bind() an address on an executor, then send to any
/// bound address. A datagram to an unbound address is dropped and counted.
class MemNet {
public:
    explicit MemNet(MemLinkConfig config = {});
    ~MemNet();
    MemNet(const MemNet&) = delete;
    MemNet& operator=(const MemNet&) = delete;

    /// Errc::invalid_argument when the address is bound already.
    Result<std::unique_ptr<IDatagram>> bind(Executor& exec, const Endpoint& local);
    std::uint64_t dropped() const noexcept;

    struct Shared;

private:
    std::shared_ptr<Shared> s_;
};

} // namespace ksim
