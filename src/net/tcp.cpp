// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/tcp.hpp"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <deque>

#include "net/sockaddr.hpp"

namespace ksim::net {

class TcpConn final : public IStream {
public:
    TcpConn(Reactor& r, Fd fd, Endpoint peer, bool connecting)
        : reactor_(r), fd_(std::move(fd)), peer_(peer), connecting_(connecting) {
        const int one = 1;
        setsockopt(fd_.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    ~TcpConn() override { leave(); }
    TcpConn(const TcpConn&) = delete;
    TcpConn& operator=(const TcpConn&) = delete;

    Result<void> join() {
        auto r = reactor_.add(fd_.get(), EPOLLIN | (connecting_ ? EPOLLOUT : 0U), [this](std::uint32_t ev) { on_io(ev); });
        in_reactor_ = static_cast<bool>(r);
        return r;
    }

    void set_handlers(OnData on_data, OnClosed on_closed) override {
        on_data_ = std::move(on_data);
        on_closed_ = std::move(on_closed);
    }

    Result<void> send(ByteView data) override {
        if (!open_) {
            return make_error(Errc::closed, 0, "tcp: the stream is closed");
        }
        out_.insert(out_.end(), data.begin(), data.end());
        if (!connecting_) {
            flush();
        }
        return {};
    }

    bool open() const noexcept override { return open_; }
    void close() override { finish(false); }
    Endpoint peer() const override { return peer_; }

private:
    void leave() {
        if (in_reactor_) {
            (void)reactor_.remove(fd_.get());
            in_reactor_ = false;
        }
    }

    void on_io(std::uint32_t ev) {
        if (connecting_) {
            int err = 0;
            socklen_t n = sizeof err;
            getsockopt(fd_.get(), SOL_SOCKET, SO_ERROR, &err, &n);
            if (err != 0) {
                finish(true);
                return;
            }
            if ((ev & EPOLLOUT) == 0) {
                return;
            }
            connecting_ = false;
        }
        if ((ev & EPOLLOUT) != 0) {
            flush();
            if (!open_) {
                return;
            }
        }
        if ((ev & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0) {
            read_all();
        }
    }

    void flush() {
        while (!out_.empty()) {
            // A deque is not contiguous: send what the first block holds.
            std::uint8_t chunk[16 * 1024];
            std::size_t n = 0;
            for (auto it = out_.begin(); it != out_.end() && n < sizeof chunk; ++it) {
                chunk[n++] = *it;
            }
            const ssize_t sent = ::send(fd_.get(), chunk, n, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    (void)reactor_.modify(fd_.get(), EPOLLIN | EPOLLOUT);
                    return;
                }
                finish(true);
                return;
            }
            out_.erase(out_.begin(), out_.begin() + sent);
        }
        (void)reactor_.modify(fd_.get(), EPOLLIN);
    }

    void read_all() {
        std::uint8_t buf[16 * 1024];
        for (;;) {
            const ssize_t n = ::recv(fd_.get(), buf, sizeof buf, MSG_DONTWAIT);
            if (n > 0) {
                if (on_data_) {
                    on_data_(ByteView(buf, static_cast<std::size_t>(n)));
                    if (!open_) {
                        return;
                    }
                }
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            finish(true);   // EOF or an error
            return;
        }
    }

    void finish(bool notify) {
        if (!open_) {
            return;
        }
        open_ = false;
        leave();
        ::shutdown(fd_.get(), SHUT_RDWR);
        out_.clear();
        if (notify && on_closed_) {
            on_closed_();
        }
    }

    Reactor& reactor_;
    Fd fd_;
    Endpoint peer_;
    bool connecting_;
    bool open_ = true;
    bool in_reactor_ = false;
    std::deque<std::uint8_t> out_;
    OnData on_data_;
    OnClosed on_closed_;
};

Result<std::unique_ptr<TcpListener>> TcpListener::listen(Reactor& reactor, const Endpoint& local, OnAccept on_accept) {
    Fd fd(::socket(family_of(local), SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP));
    if (!fd) {
        return os_error("tcp: socket");
    }
    const int one = 1;
    setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_storage ss{};
    const socklen_t n = to_sockaddr(local, ss);
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&ss), n) != 0) {
        return os_error("tcp: bind");
    }
    if (::listen(fd.get(), 16) != 0) {
        return os_error("tcp: listen");
    }
    sockaddr_storage got{};
    socklen_t gn = sizeof got;
    getsockname(fd.get(), reinterpret_cast<sockaddr*>(&got), &gn);
    std::unique_ptr<TcpListener> l(
        new TcpListener(reactor, std::move(fd), from_sockaddr(reinterpret_cast<sockaddr*>(&got), gn), std::move(on_accept)));
    if (auto r = reactor.add(l->fd_.get(), EPOLLIN, [p = l.get()](std::uint32_t) { p->accept_all(); }); !r) {
        return r.error();
    }
    return l;
}

TcpListener::TcpListener(Reactor& r, Fd fd, Endpoint local, OnAccept a)
    : reactor_(r), fd_(std::move(fd)), local_(local), on_accept_(std::move(a)) {}

TcpListener::~TcpListener() {
    if (fd_) {
        (void)reactor_.remove(fd_.get());
    }
}

void TcpListener::accept_all() {
    for (;;) {
        sockaddr_storage ss{};
        socklen_t n = sizeof ss;
        Fd fd(::accept4(fd_.get(), reinterpret_cast<sockaddr*>(&ss), &n, SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (!fd) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        auto c = std::make_unique<TcpConn>(reactor_, std::move(fd), from_sockaddr(reinterpret_cast<sockaddr*>(&ss), n), false);
        if (!c->join()) {
            continue;
        }
        if (on_accept_) {
            on_accept_(std::move(c));
        }
    }
}

Result<std::unique_ptr<IStream>> tcp_connect(Reactor& reactor, const Endpoint& remote) {
    Fd fd(::socket(family_of(remote), SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP));
    if (!fd) {
        return os_error("tcp: socket");
    }
    sockaddr_storage ss{};
    const socklen_t n = to_sockaddr(remote, ss);
    if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&ss), n) != 0 && errno != EINPROGRESS) {
        return os_error("tcp: connect");
    }
    auto c = std::make_unique<TcpConn>(reactor, std::move(fd), remote, true);
    if (auto r = c->join(); !r) {
        return r.error();
    }
    return std::unique_ptr<IStream>(std::move(c));
}

} // namespace ksim::net
