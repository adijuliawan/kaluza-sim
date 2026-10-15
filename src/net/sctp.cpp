// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/sctp.hpp"

#include <arpa/inet.h>
#include <linux/sctp.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <deque>
#include <utility>

#include "net/sockaddr.hpp"

namespace ksim::net {

namespace {

constexpr int kSolSctp = IPPROTO_SCTP;   // libsctp's SOL_SCTP
constexpr std::size_t kReadChunk = std::size_t{64} * 1024;

Result<void> set_opt(int fd, int level, int name, const void* v, socklen_t n, const char* what) {
    if (setsockopt(fd, level, name, v, n) != 0) {
        return os_error(what);
    }
    return {};
}

Result<void> configure(int fd, const SctpOptions& o) {
    sctp_initmsg init{};
    init.sinit_num_ostreams = o.out_streams;
    init.sinit_max_instreams = o.max_in_streams;
    init.sinit_max_attempts = o.max_attempts;
    if (auto r = set_opt(fd, kSolSctp, SCTP_INITMSG, &init, sizeof init, "sctp: SCTP_INITMSG"); !r) {
        return r;
    }
    const int one = 1;
    if (auto r = set_opt(fd, kSolSctp, SCTP_NODELAY, &one, sizeof one, "sctp: SCTP_NODELAY"); !r) {
        return r;
    }
    if (auto r = set_opt(fd, kSolSctp, SCTP_RECVRCVINFO, &one, sizeof one, "sctp: SCTP_RECVRCVINFO"); !r) {
        return r;
    }
    for (const std::uint16_t type : {static_cast<std::uint16_t>(SCTP_ASSOC_CHANGE),
                                     static_cast<std::uint16_t>(SCTP_SHUTDOWN_EVENT)}) {
        sctp_event ev{};
        ev.se_type = type;
        ev.se_on = 1;
        if (auto r = set_opt(fd, kSolSctp, SCTP_EVENT, &ev, sizeof ev, "sctp: SCTP_EVENT"); !r) {
            return r;
        }
    }
    return {};
}

Result<Fd> open_socket(int family, const SctpOptions& o) {
    Fd fd(::socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_SCTP));
    if (!fd) {
        return os_error("sctp: socket");
    }
    if (auto r = configure(fd.get(), o); !r) {
        return r.error();
    }
    return fd;
}

/// A socket from a SocketSource, made non-blocking and configured.
Result<Fd> configure_from(Result<Fd> fd, const SctpOptions& o) {
    if (!fd) {
        return fd.error();
    }
    const int flags = ::fcntl(fd->get(), F_GETFL);
    if (flags < 0 || ::fcntl(fd->get(), F_SETFL, flags | O_NONBLOCK) != 0) {
        return os_error("sctp: fcntl");
    }
    if (auto r = configure(fd->get(), o); !r) {
        return r.error();
    }
    return std::move(*fd);
}

Result<void> bind_all(int fd, const std::vector<Endpoint>& local) {
    if (local.empty()) {
        return {};
    }
    sockaddr_storage ss{};
    const socklen_t n = to_sockaddr(local.front(), ss);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&ss), n) != 0) {
        return os_error("sctp: bind");
    }
    if (local.size() > 1) {
        std::vector<Endpoint> rest(local.begin() + 1, local.end());
        auto packed = pack_sockaddrs(rest);
        if (auto r = set_opt(fd, kSolSctp, SCTP_SOCKOPT_BINDX_ADD, packed.data(),
                             static_cast<socklen_t>(packed.size()), "sctp: SCTP_SOCKOPT_BINDX_ADD");
            !r) {
            return r;
        }
    }
    return {};
}

} // namespace

/// One connected one-to-one SCTP socket in the reactor. Its owner learns of
/// messages and of the association's state through two callbacks; once it
/// reports a terminal event (shutdown, lost, refused) it has left the reactor
/// and does nothing more. It is never destroyed inside its own callbacks.
class SctpSocket {
public:
    using OnMessage = IAssoc::OnMessage;
    using OnEvent = IAssoc::OnEvent;

    SctpSocket(Reactor& r, Fd fd, SctpOptions o, Endpoint peer) : reactor_(r), fd_(std::move(fd)), options_(o), peer_(peer) {}
    ~SctpSocket() { leave_reactor(); }
    SctpSocket(const SctpSocket&) = delete;
    SctpSocket& operator=(const SctpSocket&) = delete;

    void set_callbacks(OnMessage m, OnEvent e) {
        on_message_ = std::move(m);
        on_event_ = std::move(e);
    }

    /// For an accepted socket: it is up already.
    Result<void> adopt_established() {
        read_status();
        up_ = true;
        return join_reactor(EPOLLIN);
    }

    /// For a client socket after a non-blocking connect.
    Result<void> await_connect() {
        connecting_ = true;
        return join_reactor(EPOLLIN | EPOLLOUT);
    }

    Result<void> send(ByteView msg, SctpMeta meta) {
        if (!up_) {
            return make_error(Errc::closed, 0, "sctp: the association is not up");
        }
        if (meta.stream >= out_streams_) {
            return make_error(Errc::out_of_range, meta.stream, "sctp: stream beyond the negotiated count");
        }
        if (!queue_.empty()) {
            queue_.push_back({Bytes(msg.begin(), msg.end()), meta});
            return {};
        }
        const int err = send_one(msg, meta);
        if (err == 0) {
            return {};
        }
        if (err == EAGAIN || err == EWOULDBLOCK) {
            queue_.push_back({Bytes(msg.begin(), msg.end()), meta});
            (void)reactor_.modify(fd_.get(), EPOLLIN | EPOLLOUT);
            return {};
        }
        return make_error(Errc::io, static_cast<std::uint32_t>(err), "sctp: sendmsg");
    }

    bool up() const noexcept { return up_; }
    std::uint16_t out_streams() const noexcept { return up_ ? out_streams_ : 0; }
    std::uint16_t in_streams() const noexcept { return up_ ? in_streams_ : 0; }
    Endpoint peer() const { return peer_; }

    /// Begins the graceful SHUTDOWN; `shutdown` follows when it completes.
    void shutdown() {
        if (up_) {
            ::shutdown(fd_.get(), SHUT_WR);
        }
    }

    /// Sends ABORT and closes at once; no event follows.
    void abort() {
        if (done_) {
            return;
        }
        send_abort();
        up_ = false;
        done_ = true;
    }

    bool done() const noexcept { return done_; }

private:
    struct Pending {
        Bytes bytes;
        SctpMeta meta;
    };

    Result<void> join_reactor(std::uint32_t events) {
        auto r = reactor_.add(fd_.get(), events, [this](std::uint32_t ev) { on_io(ev); });
        if (r) {
            in_reactor_ = true;
        }
        return r;
    }

    void send_abort() {
        if (!fd_) {
            return;
        }
        linger l{};
        l.l_onoff = 1;
        l.l_linger = 0;
        setsockopt(fd_.get(), SOL_SOCKET, SO_LINGER, &l, sizeof l);
        leave_reactor();
        fd_ = Fd();
    }

    void leave_reactor() {
        if (in_reactor_) {
            (void)reactor_.remove(fd_.get());
            in_reactor_ = false;
        }
    }

    void read_status() {
        sctp_status st{};
        socklen_t n = sizeof st;
        if (getsockopt(fd_.get(), kSolSctp, SCTP_STATUS, &st, &n) == 0) {
            in_streams_ = st.sstat_instrms;
            out_streams_ = st.sstat_outstrms;
        }
    }

    int send_one(ByteView msg, SctpMeta meta) {
        sctp_sndinfo info{};
        info.snd_sid = meta.stream;
        info.snd_ppid = htonl(meta.ppid);
        alignas(cmsghdr) char cbuf[CMSG_SPACE(sizeof(sctp_sndinfo))] = {};
        iovec iov{const_cast<std::uint8_t*>(msg.data()), msg.size()};
        msghdr mh{};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof cbuf;
        cmsghdr* c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = kSolSctp;
        c->cmsg_type = SCTP_SNDINFO;
        c->cmsg_len = CMSG_LEN(sizeof(sctp_sndinfo));
        std::memcpy(CMSG_DATA(c), &info, sizeof info);
        for (;;) {
            if (::sendmsg(fd_.get(), &mh, MSG_NOSIGNAL | MSG_DONTWAIT) >= 0) {
                return 0;
            }
            if (errno != EINTR) {
                return errno;
            }
        }
    }

    void on_io(std::uint32_t ev) {
        if (connecting_) {
            if ((ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)) == 0) {
                return;
            }
            int err = 0;
            socklen_t n = sizeof err;
            getsockopt(fd_.get(), SOL_SOCKET, SO_ERROR, &err, &n);
            connecting_ = false;
            if (err != 0) {
                finish(LinkEvent::refused);
                return;
            }
            read_status();
            up_ = true;
            (void)reactor_.modify(fd_.get(), EPOLLIN);
            if (on_event_) {
                on_event_(LinkEvent::up);
            }
            return;
        }
        if ((ev & EPOLLOUT) != 0 && !flush()) {
            return;
        }
        if ((ev & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0) {
            read_all();
        }
    }

    /// False when the socket finished meanwhile.
    bool flush() {
        while (!queue_.empty()) {
            const int err = send_one(queue_.front().bytes, queue_.front().meta);
            if (err == EAGAIN || err == EWOULDBLOCK) {
                return true;
            }
            if (err != 0) {
                finish(LinkEvent::lost);
                return false;
            }
            queue_.pop_front();
        }
        (void)reactor_.modify(fd_.get(), EPOLLIN);
        return true;
    }

    void read_all() {
        if (buf_.size() < kReadChunk) {
            buf_.resize(kReadChunk);
        }
        for (;;) {
            iovec iov{buf_.data(), buf_.size()};
            alignas(cmsghdr) char cbuf[CMSG_SPACE(sizeof(sctp_rcvinfo))] = {};
            msghdr mh{};
            mh.msg_iov = &iov;
            mh.msg_iovlen = 1;
            mh.msg_control = cbuf;
            mh.msg_controllen = sizeof cbuf;
            const ssize_t n = ::recvmsg(fd_.get(), &mh, 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    finish(LinkEvent::lost);
                }
                return;
            }
            if (n == 0) {
                finish(LinkEvent::shutdown);
                return;
            }
            const auto len = static_cast<std::size_t>(n);
            if ((mh.msg_flags & MSG_NOTIFICATION) != 0) {
                notification_.insert(notification_.end(), buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(len));
                if ((mh.msg_flags & MSG_EOR) != 0) {
                    Bytes note;
                    note.swap(notification_);
                    if (!on_notification(note)) {
                        return;
                    }
                }
                continue;
            }
            if (partial_.empty()) {
                meta_ = SctpMeta{};
                for (cmsghdr* c = CMSG_FIRSTHDR(&mh); c != nullptr; c = CMSG_NXTHDR(&mh, c)) {
                    if (c->cmsg_level == kSolSctp && c->cmsg_type == SCTP_RCVINFO) {
                        sctp_rcvinfo info{};
                        std::memcpy(&info, CMSG_DATA(c), sizeof info);
                        meta_.stream = info.rcv_sid;
                        meta_.ppid = ntohl(info.rcv_ppid);
                    }
                }
            }
            partial_.insert(partial_.end(), buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(len));
            if (partial_.size() > options_.max_message) {
                send_abort();
                finish(LinkEvent::lost);
                return;
            }
            if ((mh.msg_flags & MSG_EOR) != 0) {
                Bytes msg;
                msg.swap(partial_);
                if (up_ && on_message_) {
                    // A handler may end the association (never destroy it, see sctp.hpp).
                    on_message_(msg, meta_);
                    if (done_) {
                        return;
                    }
                }
            }
        }
    }

    /// False when the socket finished.
    bool on_notification(const Bytes& note) {
        if (note.size() < sizeof(sctp_assoc_change)) {
            return true;
        }
        sctp_notification n{};
        std::memcpy(&n, note.data(), note.size() < sizeof n ? note.size() : sizeof n);
        if (n.sn_header.sn_type != SCTP_ASSOC_CHANGE) {
            return true;   // SCTP_SHUTDOWN_EVENT: wait for SHUTDOWN_COMP or the end of the stream
        }
        const sctp_assoc_change& ac = n.sn_assoc_change;
        switch (ac.sac_state) {
        case SCTP_COMM_UP:
            in_streams_ = ac.sac_inbound_streams;
            out_streams_ = ac.sac_outbound_streams;
            return true;   // up was reported by connect or accept already
        case SCTP_RESTART:
            in_streams_ = ac.sac_inbound_streams;
            out_streams_ = ac.sac_outbound_streams;
            if (on_event_) {
                on_event_(LinkEvent::restart);
            }
            return !done_;
        case SCTP_SHUTDOWN_COMP:
            finish(LinkEvent::shutdown);
            return false;
        case SCTP_CANT_STR_ASSOC:
            finish(LinkEvent::refused);
            return false;
        case SCTP_COMM_LOST:
        default:
            finish(LinkEvent::lost);
            return false;
        }
    }

    void finish(LinkEvent e) {
        if (done_) {
            return;
        }
        done_ = true;
        up_ = false;
        leave_reactor();
        queue_.clear();
        if (on_event_) {
            on_event_(e);
        }
    }

    Reactor& reactor_;
    Fd fd_;
    SctpOptions options_;
    Endpoint peer_;
    bool in_reactor_ = false;
    bool connecting_ = false;
    bool up_ = false;
    bool done_ = false;
    std::uint16_t in_streams_ = 0;
    std::uint16_t out_streams_ = 0;
    std::deque<Pending> queue_;
    Bytes buf_;
    Bytes partial_;
    Bytes notification_;
    SctpMeta meta_{};
    OnMessage on_message_;
    OnEvent on_event_;
};

namespace {

class SctpAccepted final : public IAssoc {
public:
    explicit SctpAccepted(std::unique_ptr<SctpSocket> s) : s_(std::move(s)) {}
    void set_handlers(OnMessage on_message, OnEvent on_event) override {
        s_->set_callbacks(std::move(on_message), std::move(on_event));
    }
    Result<void> send(ByteView msg, SctpMeta meta) override { return s_->send(msg, meta); }
    bool up() const noexcept override { return s_->up(); }
    std::uint16_t out_streams() const noexcept override { return s_->out_streams(); }
    std::uint16_t in_streams() const noexcept override { return s_->in_streams(); }
    void shutdown() override { s_->shutdown(); }
    void abort() override { s_->abort(); }
    Endpoint peer() const override { return s_->peer(); }

private:
    std::unique_ptr<SctpSocket> s_;
};

} // namespace

// ---- the listener ----------------------------------------------------------

Result<std::unique_ptr<SctpListener>> SctpListener::listen(Reactor& reactor, const std::vector<Endpoint>& local,
                                                           SctpOptions options, OnAccept on_accept, const SocketSource& source) {
    if (local.empty()) {
        return make_error(Errc::invalid_argument, 0, "sctp: a listener needs an address");
    }
    auto fd = source ? configure_from(source(family_of(local.front())), options)
                     : open_socket(family_of(local.front()), options);
    if (!fd) {
        return fd.error();
    }
    const int one = 1;
    setsockopt(fd->get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (auto r = bind_all(fd->get(), local); !r) {
        return r.error();
    }
    if (::listen(fd->get(), 16) != 0) {
        return os_error("sctp: listen");
    }
    sockaddr_storage ss{};
    socklen_t n = sizeof ss;
    getsockname(fd->get(), reinterpret_cast<sockaddr*>(&ss), &n);
    std::unique_ptr<SctpListener> l(
        new SctpListener(reactor, std::move(*fd), options, std::move(on_accept), from_sockaddr(reinterpret_cast<sockaddr*>(&ss), n)));
    if (auto r = reactor.add(l->fd_.get(), EPOLLIN, [p = l.get()](std::uint32_t) { p->accept_all(); }); !r) {
        return r.error();
    }
    return l;
}

SctpListener::SctpListener(Reactor& r, Fd fd, SctpOptions o, OnAccept a, Endpoint local)
    : reactor_(r), fd_(std::move(fd)), options_(o), on_accept_(std::move(a)), local_(local) {}

SctpListener::~SctpListener() {
    if (fd_) {
        (void)reactor_.remove(fd_.get());
    }
}

void SctpListener::accept_all() {
    for (;;) {
        sockaddr_storage ss{};
        socklen_t n = sizeof ss;
        Fd fd(::accept4(fd_.get(), reinterpret_cast<sockaddr*>(&ss), &n, SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (!fd) {
            if (errno == EINTR) {
                continue;
            }
            return;   // EAGAIN, or an error the next readiness retries
        }
        auto s = std::make_unique<SctpSocket>(reactor_, std::move(fd), options_, from_sockaddr(reinterpret_cast<sockaddr*>(&ss), n));
        if (!s->adopt_established()) {
            continue;
        }
        if (on_accept_) {
            on_accept_(std::make_unique<SctpAccepted>(std::move(s)));
        }
    }
}

// ---- the client ------------------------------------------------------------

SctpClient::SctpClient(Reactor& reactor, TimerService& timers, std::vector<Endpoint> local, std::vector<Endpoint> remote,
                       SctpOptions options, SctpBackoff backoff, SocketSource source)
    : reactor_(reactor), timers_(timers), local_(std::move(local)), remote_(std::move(remote)), options_(options),
      backoff_(backoff), source_(std::move(source)), next_delay_(backoff.initial_ms) {}

SctpClient::~SctpClient() { stop(); }

void SctpClient::set_handlers(OnMessage on_message, OnEvent on_event) {
    on_message_ = std::move(on_message);
    on_event_ = std::move(on_event);
}

void SctpClient::start() {
    if (running_) {
        return;
    }
    running_ = true;
    next_delay_ = backoff_.initial_ms;
    attempt();
}

void SctpClient::stop() {
    running_ = false;
    if (retry_.valid()) {
        timers_.stop_timer(retry_);
        retry_ = {};
    }
    if (sock_) {
        sock_->abort();
        retired_.push_back(std::move(sock_));
    }
}

void SctpClient::attempt() {
    retry_ = {};
    retired_.clear();
    if (!running_ || remote_.empty()) {
        return;
    }
    ++attempts_;
    auto fd = source_ ? configure_from(source_(family_of(remote_.front())), options_)
                      : open_socket(family_of(remote_.front()), options_);
    if (!fd) {
        on_socket_event(LinkEvent::refused);
        return;
    }
    if (!bind_all(fd->get(), local_)) {
        on_socket_event(LinkEvent::refused);
        return;
    }
    int rc = 0;
    if (remote_.size() == 1) {
        sockaddr_storage ss{};
        const socklen_t n = to_sockaddr(remote_.front(), ss);
        rc = ::connect(fd->get(), reinterpret_cast<const sockaddr*>(&ss), n);
    } else {
        auto packed = pack_sockaddrs(remote_);
        rc = setsockopt(fd->get(), kSolSctp, SCTP_SOCKOPT_CONNECTX, packed.data(), static_cast<socklen_t>(packed.size()));
        rc = rc < 0 ? -1 : 0;
    }
    if (rc != 0 && errno != EINPROGRESS) {
        on_socket_event(LinkEvent::refused);
        return;
    }
    sock_ = std::make_unique<SctpSocket>(reactor_, std::move(*fd), options_, remote_.front());
    sock_->set_callbacks([this](ByteView m, SctpMeta meta) {
                             if (on_message_) {
                                 on_message_(m, meta);
                             }
                         },
                         [this](LinkEvent e) { on_socket_event(e); });
    if (!sock_->await_connect()) {
        retired_.push_back(std::move(sock_));
        on_socket_event(LinkEvent::refused);
    }
}

void SctpClient::on_socket_event(LinkEvent e) {
    if (e == LinkEvent::up) {
        next_delay_ = backoff_.initial_ms;
    }
    const bool terminal = e == LinkEvent::shutdown || e == LinkEvent::lost || e == LinkEvent::refused;
    if (terminal && sock_) {
        retired_.push_back(std::move(sock_));   // freed at the next attempt, not inside its callback
    }
    if (on_event_) {
        on_event_(e);
    }
    if (terminal) {
        retry_later();
    }
}

void SctpClient::retry_later() {
    if (!running_ || retry_.valid()) {
        return;
    }
    const Millis d = next_delay_;
    next_delay_ = next_delay_ * 2 > backoff_.max_ms ? backoff_.max_ms : next_delay_ * 2;
    retry_ = timers_.start_timer(d, [this] { attempt(); });
}

Result<void> SctpClient::send(ByteView msg, SctpMeta meta) {
    if (!sock_) {
        return make_error(Errc::closed, 0, "sctp: the association is not up");
    }
    return sock_->send(msg, meta);
}

bool SctpClient::up() const noexcept { return sock_ && sock_->up(); }
std::uint16_t SctpClient::out_streams() const noexcept { return sock_ ? sock_->out_streams() : 0; }
std::uint16_t SctpClient::in_streams() const noexcept { return sock_ ? sock_->in_streams() : 0; }

void SctpClient::shutdown() {
    running_ = false;
    if (retry_.valid()) {
        timers_.stop_timer(retry_);
        retry_ = {};
    }
    if (sock_) {
        sock_->shutdown();
    }
}

void SctpClient::abort() { stop(); }

} // namespace ksim::net
