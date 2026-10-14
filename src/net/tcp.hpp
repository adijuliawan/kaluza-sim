// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// TCP behind IStream (P1 N2): the vpcd card transport (sim-uicc.md §5) frames
// APDUs on it. Non-blocking, in the reactor; writes queue until the socket
// takes them. A handler may close a stream but must not destroy it.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>

#include "platform/reactor.hpp"
#include "platform/transport.hpp"

namespace ksim::net {

class TcpConn;

class TcpListener {
public:
    using OnAccept = std::function<void(std::unique_ptr<IStream> stream)>;

    static Result<std::unique_ptr<TcpListener>> listen(Reactor& reactor, const Endpoint& local, OnAccept on_accept);
    ~TcpListener();
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    Endpoint local() const { return local_; }

private:
    TcpListener(Reactor& r, Fd fd, Endpoint local, OnAccept a);
    void accept_all();

    Reactor& reactor_;
    Fd fd_;
    Endpoint local_;
    OnAccept on_accept_;
};

/// Connects to `remote`. The stream is open at once: what is sent before the
/// connection completes waits in its queue; a failed connect closes it.
Result<std::unique_ptr<IStream>> tcp_connect(Reactor& reactor, const Endpoint& remote);

} // namespace ksim::net
