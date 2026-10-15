// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// UNIX SOCK_SEQPACKET behind IChannel (P2 Q2; ADR 0011 point 2): KAIR between
// the UE farm and the DU when they are separate processes on one host. Path
// sockets in the run directory, never abstract ones, since an abstract name is
// local to a network namespace and the roles live in different ones. Each
// send arrives as one message; a socket the peer cannot drain queues its
// sends in order. Everything runs on the given Reactor's thread; a handler may
// close a channel but must not destroy it.

#pragma once

#include <functional>
#include <memory>
#include <string>

#include "platform/reactor.hpp"
#include "platform/transport.hpp"

namespace ksim::net {

/// The longest message taken (a KAIR frame with several SDUs fits well).
inline constexpr std::size_t kSeqpacketMax = 65536;

class SeqpacketListener {
public:
    using OnAccept = std::function<void(std::unique_ptr<IChannel> channel)>;

    /// Listens on `path` (an existing socket file there is replaced, mode 0600).
    static Result<std::unique_ptr<SeqpacketListener>> listen(Reactor& reactor, std::string path, OnAccept on_accept);
    /// Stops listening and removes the socket file.
    ~SeqpacketListener();
    SeqpacketListener(const SeqpacketListener&) = delete;
    SeqpacketListener& operator=(const SeqpacketListener&) = delete;

    const std::string& path() const noexcept { return path_; }

private:
    SeqpacketListener(Reactor& r, Fd fd, std::string path, OnAccept a);
    void accept_all();

    Reactor& reactor_;
    Fd fd_;
    std::string path_;
    OnAccept on_accept_;
};

/// Connects to the listener at `path`; Errc::closed when nothing listens there.
Result<std::unique_ptr<IChannel>> seqpacket_connect(Reactor& reactor, const std::string& path);

} // namespace ksim::net
