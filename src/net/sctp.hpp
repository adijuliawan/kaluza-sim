// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// SCTP over the kernel's own API (P1 N2; architecture §5: one-to-one sockets,
// <linux/sctp.h>, no libsctp). A listener hands out each accepted association
// as an IAssoc; a client keeps one association up, reconnecting with backoff
// after a refusal or a loss (TS 38.412 §7: NG Setup again on a new
// association; L11). Every message carries its stream and PPID through
// SCTP_SNDINFO and SCTP_RCVINFO; the PPID is in network order on the wire.
// Streams are bounded by the counts the association negotiated (L10).
//
// Everything runs on the thread of the Reactor (and TimerService) given. A
// handler may shut an association down or abort it, but must not destroy it.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "platform/executor.hpp"
#include "platform/reactor.hpp"
#include "platform/transport.hpp"

namespace ksim::net {

struct SctpOptions {
    std::uint16_t out_streams = 2;       // asked for (INIT's outbound streams)
    std::uint16_t max_in_streams = 2;    // allowed (INIT's maximum inbound streams)
    std::uint16_t max_attempts = 4;      // INIT retransmissions before giving up
    std::size_t max_message = 1U << 20;  // a longer reassembled message aborts the association
};

struct SctpBackoff {
    Millis initial_ms = 500;
    Millis max_ms = 30'000;
};

class SctpSocket;

class SctpListener {
public:
    using OnAccept = std::function<void(std::unique_ptr<IAssoc> assoc)>;

    /// Listens on `local` (the first address bound, the rest added with
    /// SCTP_SOCKOPT_BINDX_ADD; port 0 picks one). Each accepted association
    /// is born up: up() is true at once and no `up` event comes for it.
    static Result<std::unique_ptr<SctpListener>> listen(Reactor& reactor, const std::vector<Endpoint>& local,
                                                        SctpOptions options, OnAccept on_accept);
    ~SctpListener();
    SctpListener(const SctpListener&) = delete;
    SctpListener& operator=(const SctpListener&) = delete;

    /// The first local address, with the port actually bound.
    Endpoint local() const { return local_; }

private:
    SctpListener(Reactor& r, Fd fd, SctpOptions o, OnAccept a, Endpoint local);
    void accept_all();

    Reactor& reactor_;
    Fd fd_;
    SctpOptions options_;
    OnAccept on_accept_;
    Endpoint local_;
};

/// An association to `remote` that keeps itself up. Events: `up` on each
/// establishment, `refused` per failed attempt, `lost` or `shutdown` when the
/// association ends, `restart` when the peer restarts it. After `refused`,
/// `lost` or a `shutdown` the peer began, it reconnects after a backoff that
/// doubles from initial_ms to max_ms and resets on `up`. shutdown(), abort()
/// and stop() end it for good.
class SctpClient final : public IAssoc {
public:
    SctpClient(Reactor& reactor, TimerService& timers, std::vector<Endpoint> local, std::vector<Endpoint> remote,
               SctpOptions options = {}, SctpBackoff backoff = {});
    ~SctpClient() override;
    SctpClient(const SctpClient&) = delete;
    SctpClient& operator=(const SctpClient&) = delete;

    /// The first attempt, now.
    void start();
    void stop();
    std::uint64_t attempts() const noexcept { return attempts_; }

    void set_handlers(OnMessage on_message, OnEvent on_event) override;
    Result<void> send(ByteView msg, SctpMeta meta) override;
    bool up() const noexcept override;
    std::uint16_t out_streams() const noexcept override;
    std::uint16_t in_streams() const noexcept override;
    void shutdown() override;
    void abort() override;
    Endpoint peer() const override { return remote_.empty() ? Endpoint{} : remote_.front(); }

private:
    void attempt();
    void on_socket_event(LinkEvent e);
    void retry_later();

    Reactor& reactor_;
    TimerService& timers_;
    std::vector<Endpoint> local_;
    std::vector<Endpoint> remote_;
    SctpOptions options_;
    SctpBackoff backoff_;
    std::unique_ptr<SctpSocket> sock_;
    std::vector<std::unique_ptr<SctpSocket>> retired_;   // freed at the next attempt, never inside their callbacks
    TimerId retry_{};
    Millis next_delay_ = 0;
    std::uint64_t attempts_ = 0;
    bool running_ = false;
    OnMessage on_message_;
    OnEvent on_event_;
};

} // namespace ksim::net
