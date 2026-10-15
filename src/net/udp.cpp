// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/udp.hpp"

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <array>

#include "net/sockaddr.hpp"

namespace ksim::net {

Result<std::unique_ptr<UdpSocket>> UdpSocket::bind(Reactor& reactor, const Endpoint& local) {
    Fd fd(::socket(family_of(local), SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP));
    if (!fd) {
        return os_error("udp: socket");
    }
    sockaddr_storage ss{};
    const socklen_t n = to_sockaddr(local, ss);
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&ss), n) != 0) {
        return os_error("udp: bind");
    }
    return adopt(reactor, std::move(fd));
}

Result<std::unique_ptr<UdpSocket>> UdpSocket::bind(Reactor& reactor, Fd fd, const Endpoint& local) {
    sockaddr_storage ss{};
    const socklen_t n = to_sockaddr(local, ss);
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&ss), n) != 0) {
        return os_error("udp: bind");
    }
    return adopt(reactor, std::move(fd));
}

Result<std::unique_ptr<UdpSocket>> UdpSocket::adopt(Reactor& reactor, Fd fd) {
    sockaddr_storage ss{};
    socklen_t n = sizeof ss;
    if (getsockname(fd.get(), reinterpret_cast<sockaddr*>(&ss), &n) != 0) {
        return os_error("udp: getsockname");
    }
    std::unique_ptr<UdpSocket> s(new UdpSocket(reactor, std::move(fd), from_sockaddr(reinterpret_cast<sockaddr*>(&ss), n)));
    if (auto r = reactor.add(s->fd_.get(), EPOLLIN, [p = s.get()](std::uint32_t) { p->read_all(); }); !r) {
        return r.error();
    }
    return s;
}

UdpSocket::UdpSocket(Reactor& r, Fd fd, Endpoint local)
    : reactor_(r), fd_(std::move(fd)), local_(local), bufs_(kBatch * kMaxDatagram) {}

UdpSocket::~UdpSocket() {
    if (fd_) {
        (void)reactor_.remove(fd_.get());
    }
}

Result<void> UdpSocket::send_to(ByteView payload, const Endpoint& to) {
    if (to.family != local_.family) {
        return make_error(Errc::invalid_argument, 0, "udp: address family mismatch");
    }
    sockaddr_storage ss{};
    const socklen_t n = to_sockaddr(to, ss);
    for (;;) {
        if (::sendto(fd_.get(), payload.data(), payload.size(), MSG_DONTWAIT | MSG_NOSIGNAL,
                     reinterpret_cast<const sockaddr*>(&ss), n) >= 0) {
            return {};
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno == ECONNREFUSED) {
            ++dropped_;   // best effort, as UDP
            return {};
        }
        return os_error("udp: sendto");
    }
}

void UdpSocket::read_all() {
    std::array<mmsghdr, kBatch> msgs{};
    std::array<iovec, kBatch> iovs{};
    std::array<sockaddr_storage, kBatch> from{};
    for (;;) {
        for (std::size_t i = 0; i < kBatch; ++i) {
            iovs[i].iov_base = bufs_.data() + i * kMaxDatagram;
            iovs[i].iov_len = kMaxDatagram;
            msgs[i] = mmsghdr{};
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = &from[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
        }
        const int n = ::recvmmsg(fd_.get(), msgs.data(), static_cast<unsigned>(kBatch), MSG_DONTWAIT, nullptr);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return;   // EAGAIN: drained
        }
        for (int i = 0; i < n; ++i) {
            const auto k = static_cast<std::size_t>(i);
            ++received_;
            if ((msgs[k].msg_hdr.msg_flags & MSG_TRUNC) != 0) {
                ++dropped_;   // larger than a jumbo frame: not ours to carry
                continue;
            }
            if (on_datagram_) {
                on_datagram_(ByteView(bufs_.data() + k * kMaxDatagram, msgs[k].msg_len),
                             from_sockaddr(reinterpret_cast<sockaddr*>(&from[k]), msgs[k].msg_hdr.msg_namelen));
            }
        }
        if (static_cast<std::size_t>(n) < kBatch) {
            return;
        }
    }
}

} // namespace ksim::net
