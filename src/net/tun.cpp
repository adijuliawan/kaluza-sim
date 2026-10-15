// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/tun.hpp"

#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <cerrno>

namespace ksim::net {

Result<std::unique_ptr<TunPort>> TunPort::adopt(Reactor& reactor, Fd fd) {
    if (!fd) {
        return make_error(Errc::invalid_argument, 0, "tun: no descriptor");
    }
    const int flags = ::fcntl(fd.get(), F_GETFL);
    if (flags < 0 || ::fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "tun: fcntl");
    }
    std::unique_ptr<TunPort> t(new TunPort(reactor, std::move(fd)));   // NOLINT(cppcoreguidelines-owning-memory): private constructor
    if (auto r = reactor.add(t->fd_.get(), EPOLLIN, [p = t.get()](std::uint32_t) { p->read_all(); }); !r) {
        return r.error();
    }
    return t;
}

TunPort::TunPort(Reactor& r, Fd fd) : reactor_(r), fd_(std::move(fd)), buf_(kMaxPacket) {}

TunPort::~TunPort() {
    if (fd_) {
        (void)reactor_.remove(fd_.get());
    }
}

Result<void> TunPort::write(ByteView packet) {
    for (;;) {
        if (::write(fd_.get(), packet.data(), packet.size()) >= 0) {
            return {};
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno == EINVAL) {
            ++dropped_;   // the device's queue is full, or the kernel refused the packet
            return {};
        }
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "tun: write");
    }
}

void TunPort::read_all() {
    for (;;) {
        const ssize_t n = ::read(fd_.get(), buf_.data(), buf_.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;   // EAGAIN: drained
        }
        if (n == 0) {
            return;   // the device went
        }
        ++received_;
        if (on_packet_) {
            on_packet_(ByteView(buf_.data(), static_cast<std::size_t>(n)));
        }
    }
}

} // namespace ksim::net
