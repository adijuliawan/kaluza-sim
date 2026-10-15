// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/seqpacket.hpp"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <deque>
#include <vector>

namespace ksim::net {

namespace {

Result<sockaddr_un> unix_addr(const std::string& path) {
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    if (path.empty() || path.size() >= sizeof a.sun_path) {
        return make_error(Errc::invalid_argument, 0, "seqpacket: a socket path is 1..107 octets");
    }
    std::memcpy(a.sun_path, path.data(), path.size());
    return a;
}

class SeqChannel final : public IChannel {
public:
    SeqChannel(Reactor& r, Fd fd) : reactor_(r), fd_(std::move(fd)) {}
    ~SeqChannel() override { leave(); }
    SeqChannel(const SeqChannel&) = delete;
    SeqChannel& operator=(const SeqChannel&) = delete;

    Result<void> join() {
        auto r = reactor_.add(fd_.get(), EPOLLIN, [this](std::uint32_t ev) { on_io(ev); });
        in_reactor_ = static_cast<bool>(r);
        return r;
    }

    void set_handlers(OnMessage on_message, OnClosed on_closed) override {
        on_message_ = std::move(on_message);
        on_closed_ = std::move(on_closed);
    }

    Result<void> send(ByteView m) override {
        if (!open_) {
            return make_error(Errc::closed, 0, "seqpacket: the channel is closed");
        }
        if (m.size() > kSeqpacketMax) {
            return make_error(Errc::out_of_range, static_cast<std::uint32_t>(m.size()), "seqpacket: a message too long");
        }
        if (!queue_.empty()) {
            queue_.emplace_back(m.begin(), m.end());
            return {};
        }
        const ssize_t n = ::send(fd_.get(), m.data(), m.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n == static_cast<ssize_t>(m.size())) {
            return {};
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            queue_.emplace_back(m.begin(), m.end());
            (void)reactor_.modify(fd_.get(), EPOLLIN | EPOLLOUT);
            return {};
        }
        finish();
        return make_error(Errc::closed, 0, "seqpacket: the peer is gone");
    }

    bool open() const noexcept override { return open_; }
    void close() override { finish(); }

private:
    void leave() {
        if (in_reactor_) {
            (void)reactor_.remove(fd_.get());
            in_reactor_ = false;
        }
    }

    void finish() {
        if (!open_) {
            return;
        }
        open_ = false;
        queue_.clear();
        leave();
        fd_ = Fd();   // closed now, so the peer sees the end at once
        if (on_closed_) {
            on_closed_();
        }
    }

    void on_io(std::uint32_t ev) {
        if ((ev & EPOLLOUT) != 0) {
            while (!queue_.empty()) {
                const Bytes& m = queue_.front();
                const ssize_t n = ::send(fd_.get(), m.data(), m.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    break;
                }
                if (n != static_cast<ssize_t>(m.size())) {
                    finish();
                    return;
                }
                queue_.pop_front();
            }
            if (queue_.empty()) {
                (void)reactor_.modify(fd_.get(), EPOLLIN);
            }
        }
        if ((ev & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0) {
            for (int i = 0; i < 64 && open_; ++i) {   // a batch per wake, so one busy peer cannot starve the loop
                const ssize_t n = ::recv(fd_.get(), buf_.data(), buf_.size(), MSG_DONTWAIT);
                if (n > 0) {
                    if (on_message_) {
                        on_message_(ByteView(buf_.data(), static_cast<std::size_t>(n)));
                    }
                    continue;
                }
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    break;
                }
                if (n < 0 && errno == EINTR) {
                    continue;
                }
                finish();   // 0: the peer closed; or an error
                return;
            }
        }
    }

    Reactor& reactor_;
    Fd fd_;
    bool open_ = true;
    bool in_reactor_ = false;
    std::deque<Bytes> queue_;
    std::vector<std::uint8_t> buf_ = std::vector<std::uint8_t>(kSeqpacketMax);
    OnMessage on_message_;
    OnClosed on_closed_;
};

} // namespace

Result<std::unique_ptr<SeqpacketListener>> SeqpacketListener::listen(Reactor& reactor, std::string path, OnAccept on_accept) {
    auto a = unix_addr(path);
    if (!a) {
        return a.error();
    }
    Fd fd(::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!fd) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "seqpacket: socket");
    }
    (void)::unlink(path.c_str());
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&*a), sizeof *a) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "seqpacket: bind");
    }
    (void)::chmod(path.c_str(), 0600);
    if (::listen(fd.get(), 16) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "seqpacket: listen");
    }
    std::unique_ptr<SeqpacketListener> l(new SeqpacketListener(reactor, std::move(fd), std::move(path), std::move(on_accept)));
    if (auto r = reactor.add(l->fd_.get(), EPOLLIN, [p = l.get()](std::uint32_t) { p->accept_all(); }); !r) {
        return r.error();
    }
    return l;
}

SeqpacketListener::SeqpacketListener(Reactor& r, Fd fd, std::string path, OnAccept a)
    : reactor_(r), fd_(std::move(fd)), path_(std::move(path)), on_accept_(std::move(a)) {}

SeqpacketListener::~SeqpacketListener() {
    if (fd_) {
        (void)reactor_.remove(fd_.get());
        (void)::unlink(path_.c_str());
    }
}

void SeqpacketListener::accept_all() {
    for (;;) {
        Fd fd(::accept4(fd_.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (!fd) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        auto c = std::make_unique<SeqChannel>(reactor_, std::move(fd));
        if (!c->join()) {
            continue;
        }
        if (on_accept_) {
            on_accept_(std::move(c));
        }
    }
}

Result<std::unique_ptr<IChannel>> seqpacket_connect(Reactor& reactor, const std::string& path) {
    auto a = unix_addr(path);
    if (!a) {
        return a.error();
    }
    Fd fd(::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!fd) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "seqpacket: socket");
    }
    // A UNIX connect completes or fails at once (EAGAIN only when the backlog is full).
    if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&*a), sizeof *a) != 0) {
        return make_error(errno == ENOENT || errno == ECONNREFUSED ? Errc::closed : Errc::io,
                          static_cast<std::uint32_t>(errno), "seqpacket: connect");
    }
    auto c = std::make_unique<SeqChannel>(reactor, std::move(fd));
    if (auto r = c->join(); !r) {
        return r.error();
    }
    return std::unique_ptr<IChannel>(std::move(c));
}

} // namespace ksim::net
