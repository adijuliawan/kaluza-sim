// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/netd.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace ksim::net::netd {

namespace {

constexpr std::uint8_t kVersion = 1;
constexpr std::size_t kMaxString = 64;
constexpr std::size_t kMaxNames = 64;

class Writer {
public:
    void u8(std::uint8_t v) { b.push_back(v); }
    void u32(std::uint32_t v) {
        for (int s = 24; s >= 0; s -= 8) {
            b.push_back(static_cast<std::uint8_t>(v >> s));
        }
    }
    void str(const std::string& s) {
        const std::size_t n = std::min(s.size(), std::size_t{255});
        u8(static_cast<std::uint8_t>(n));
        b.insert(b.end(), s.begin(), s.begin() + static_cast<std::ptrdiff_t>(n));
    }
    Bytes b;
};

class Reader {
public:
    explicit Reader(ByteView in) : in_(in) {}
    bool u8(std::uint8_t& v) {
        if (pos_ >= in_.size()) {
            return false;
        }
        v = in_[pos_++];
        return true;
    }
    bool u32(std::uint32_t& v) {
        if (in_.size() - pos_ < 4) {
            return false;
        }
        v = 0;
        for (int i = 0; i < 4; ++i) {
            v = v << 8 | in_[pos_++];
        }
        return true;
    }
    bool str(std::string& s, std::size_t max) {
        std::uint8_t n = 0;
        if (!u8(n) || n > max || in_.size() - pos_ < n) {
            return false;
        }
        s.assign(reinterpret_cast<const char*>(in_.data() + pos_), n);
        pos_ += n;
        return true;
    }
    bool done() const noexcept { return pos_ == in_.size(); }

private:
    ByteView in_;
    std::size_t pos_ = 0;
};

Error malformed(const char* what) { return make_error(Errc::malformed, 0, what); }

bool in_range(const std::array<std::uint8_t, 4>& a, const std::array<std::uint8_t, 4>& lo,
              const std::array<std::uint8_t, 4>& hi) {
    return std::lexicographical_compare(a.begin(), a.end(), lo.begin(), lo.end()) == false &&
           std::lexicographical_compare(hi.begin(), hi.end(), a.begin(), a.end()) == false;
}

} // namespace

bool valid_name(const std::string& n) {
    if (n.size() < 6 || n.size() > 31 || n.rfind("ksim-", 0) != 0) {
        return false;
    }
    for (std::size_t i = 5; i < n.size(); ++i) {
        const char c = n[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 5);
        if (!ok) {
            return false;
        }
    }
    return true;
}

Bytes encode(const Request& r) {
    Writer w;
    w.u8(kVersion);
    w.u8(static_cast<std::uint8_t>(r.op));
    switch (r.op) {
    case Op::setup_node:
        w.str(r.netns);
        w.str(r.parent);
        for (std::uint8_t o : r.addr) {
            w.u8(o);
        }
        w.u8(r.prefix);
        break;
    case Op::teardown:
        w.str(r.netns);
        break;
    case Op::socket:
        w.str(r.netns);
        w.u8(static_cast<std::uint8_t>(r.kind));
        w.u8(r.family);
        break;
    case Op::list:
    case Op::gc:
        break;
    }
    return w.b;
}

Result<Request> decode_request(ByteView in) {
    if (in.size() > kMaxMessage) {
        return malformed("netd: request too long");
    }
    Reader r(in);
    std::uint8_t version = 0;
    std::uint8_t op = 0;
    if (!r.u8(version) || version != kVersion || !r.u8(op)) {
        return malformed("netd: not a version 1 request");
    }
    Request q;
    switch (op) {
    case static_cast<std::uint8_t>(Op::setup_node):
        q.op = Op::setup_node;
        if (!r.str(q.netns, kMaxString) || !r.str(q.parent, kMaxString)) {
            return malformed("netd: setup_node fields");
        }
        for (auto& o : q.addr) {
            if (!r.u8(o)) {
                return malformed("netd: setup_node address");
            }
        }
        if (!r.u8(q.prefix) || q.prefix > 32) {
            return malformed("netd: setup_node prefix");
        }
        break;
    case static_cast<std::uint8_t>(Op::teardown):
        q.op = Op::teardown;
        if (!r.str(q.netns, kMaxString)) {
            return malformed("netd: teardown name");
        }
        break;
    case static_cast<std::uint8_t>(Op::socket): {
        q.op = Op::socket;
        std::uint8_t kind = 0;
        if (!r.str(q.netns, kMaxString) || !r.u8(kind) || !r.u8(q.family) || (kind != 1 && kind != 2) ||
            (q.family != 4 && q.family != 6)) {
            return malformed("netd: socket fields");
        }
        q.kind = static_cast<SockKind>(kind);
        break;
    }
    case static_cast<std::uint8_t>(Op::list):
        q.op = Op::list;
        break;
    case static_cast<std::uint8_t>(Op::gc):
        q.op = Op::gc;
        break;
    default:
        return malformed("netd: unknown op");
    }
    if (!r.done()) {
        return malformed("netd: trailing octets");
    }
    return q;
}

Bytes encode(const Reply& r) {
    Writer w;
    w.u8(kVersion);
    w.u8(static_cast<std::uint8_t>(r.status));
    w.u32(r.err);
    w.str(r.message);
    const std::size_t n = std::min(r.names.size(), kMaxNames);
    w.u8(static_cast<std::uint8_t>(n));
    for (std::size_t i = 0; i < n; ++i) {
        w.str(r.names[i]);
    }
    return w.b;
}

Result<Reply> decode_reply(ByteView in) {
    Reader r(in);
    std::uint8_t version = 0;
    std::uint8_t status = 0;
    Reply out;
    std::uint8_t n = 0;
    if (!r.u8(version) || version != kVersion || !r.u8(status) || status > 3 || !r.u32(out.err) ||
        !r.str(out.message, 255) || !r.u8(n)) {
        return malformed("netd: not a version 1 reply");
    }
    out.status = static_cast<Status>(status);
    for (std::uint8_t i = 0; i < n; ++i) {
        std::string s;
        if (!r.str(s, kMaxString)) {
            return malformed("netd: reply names");
        }
        out.names.push_back(std::move(s));
    }
    if (!r.done()) {
        return malformed("netd: trailing octets");
    }
    return out;
}

Reply Server::refuse(const char* why) const {
    Reply r;
    r.status = Status::refused;
    r.message = why;
    return r;
}

Reply Server::handle(ByteView request, unsigned uid, std::optional<Fd>& fd) {
    fd.reset();
    if (uid != p_.uid) {
        return refuse("netd: this uid is not served");
    }
    auto q = decode_request(request);
    if (!q) {
        Reply r;
        r.status = Status::malformed;
        r.message = q.error().what;
        return r;
    }
    auto failed = [](const Error& e) {
        Reply r;
        r.status = Status::failed;
        r.err = e.offset;
        r.message = e.what;
        return r;
    };
    const auto owned = [&](const std::string& n) {
        const auto all = ops_.list();
        return std::find(all.begin(), all.end(), n) != all.end();
    };
    switch (q->op) {
    case Op::setup_node:
        if (!valid_name(q->netns)) {
            return refuse("netd: a namespace name is ksim- and [a-z0-9-], 31 characters at most");
        }
        if (!q->parent.empty() && (p_.parent.empty() || q->parent != p_.parent)) {
            return refuse("netd: that parent link is not allowed here");
        }
        if (!q->parent.empty() && (!in_range(q->addr, p_.first, p_.last) || q->prefix != p_.prefix)) {
            return refuse("netd: that address is outside the allowed range");
        }
        if (owned(q->netns)) {
            return refuse("netd: the namespace exists");
        }
        if (auto r = ops_.setup_node(q->netns, q->parent, q->addr, q->prefix); !r) {
            return failed(r.error());
        }
        return {};
    case Op::teardown:
        if (!valid_name(q->netns) || !owned(q->netns)) {
            return refuse("netd: no such ksim namespace");
        }
        if (auto r = ops_.teardown(q->netns); !r) {
            return failed(r.error());
        }
        return {};
    case Op::socket: {
        if (!valid_name(q->netns) || !owned(q->netns)) {
            return refuse("netd: no such ksim namespace");
        }
        auto s = ops_.socket(q->netns, q->kind, q->family == 4 ? AF_INET : AF_INET6);
        if (!s) {
            return failed(s.error());
        }
        fd = std::move(*s);
        return {};
    }
    case Op::list: {
        Reply r;
        for (auto& n : ops_.list()) {
            if (valid_name(n)) {
                r.names.push_back(n);
            }
        }
        return r;
    }
    case Op::gc: {
        Reply r;
        for (auto& n : ops_.list()) {
            if (valid_name(n) && ops_.teardown(n)) {
                r.names.push_back(n);
            }
        }
        return r;
    }
    }
    return refuse("netd: unknown op");
}

bool serve_one(int conn, Server& s) {
    ucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return false;
    }
    Bytes buf(kMaxMessage + 1);
    const ssize_t n = ::recv(conn, buf.data(), buf.size(), 0);
    if (n <= 0) {
        return false;
    }
    std::optional<Fd> fd;
    const Reply reply = s.handle(ByteView(buf.data(), static_cast<std::size_t>(n)), cred.uid, fd);
    Bytes out = encode(reply);
    iovec iov{out.data(), out.size()};
    msghdr m{};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int))> ctrl{};
    if (fd) {
        m.msg_control = ctrl.data();
        m.msg_controllen = ctrl.size();
        cmsghdr* c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        const int raw = fd->get();
        std::memcpy(CMSG_DATA(c), &raw, sizeof(int));
    }
    return ::sendmsg(conn, &m, MSG_NOSIGNAL) == static_cast<ssize_t>(out.size());
}

Result<void> run_server(const std::string& path, Server& s, const volatile int& stop) {
    const std::string dir = path.substr(0, path.rfind('/'));
    if (!dir.empty() && ::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: cannot create the socket's directory");
    }
    Fd listener(::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
    if (!listener) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: socket");
    }
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    if (path.size() >= sizeof(a.sun_path)) {
        return make_error(Errc::invalid_argument, 0, "netd: the socket path is too long");
    }
    std::memcpy(a.sun_path, path.c_str(), path.size() + 1);
    struct stat st {};
    if (::lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
        ::unlink(path.c_str());
    }
    if (::bind(listener.get(), reinterpret_cast<const sockaddr*>(&a), sizeof(a)) != 0 ||
        ::chmod(path.c_str(), 0666) != 0 || ::listen(listener.get(), 8) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: cannot listen");
    }
    constexpr std::size_t kMaxConns = 8;
    std::vector<Fd> conns;
    while (stop == 0) {
        std::vector<pollfd> fds;
        fds.push_back({listener.get(), POLLIN, 0});
        for (auto& c : conns) {
            fds.push_back({c.get(), POLLIN, 0});
        }
        const int n = ::poll(fds.data(), fds.size(), 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (std::size_t i = fds.size(); i-- > 1;) {
            if ((fds[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0 && !serve_one(fds[i].fd, s)) {
                conns.erase(conns.begin() + static_cast<std::ptrdiff_t>(i - 1));
            }
        }
        if ((fds[0].revents & POLLIN) != 0) {
            Fd c(::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
            if (c && conns.size() < kMaxConns) {
                conns.push_back(std::move(c));
            }
        }
    }
    ::unlink(path.c_str());
    return {};
}

// ---- the client ---------------------------------------------------------------------------

Result<Client> Client::connect(const std::string& path) {
    Fd fd(::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
    if (!fd) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: socket");
    }
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    if (path.size() >= sizeof(a.sun_path)) {
        return make_error(Errc::invalid_argument, 0, "netd: the socket path is too long");
    }
    std::memcpy(a.sun_path, path.c_str(), path.size() + 1);
    if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&a), sizeof(a)) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: no ksim-netd answers");
    }
    return Client(std::move(fd));
}

Result<Reply> Client::call(const Request& r, std::optional<Fd>* fd) {
    const Bytes req = encode(r);
    if (::send(fd_.get(), req.data(), req.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(req.size())) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: send");
    }
    Bytes buf(kMaxMessage + 512);
    iovec iov{buf.data(), buf.size()};
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int))> ctrl{};
    msghdr m{};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = ctrl.data();
    m.msg_controllen = ctrl.size();
    const ssize_t n = ::recvmsg(fd_.get(), &m, MSG_CMSG_CLOEXEC);
    if (n <= 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: no reply");
    }
    for (cmsghdr* c = CMSG_FIRSTHDR(&m); c != nullptr; c = CMSG_NXTHDR(&m, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int))) {
            int got = -1;
            std::memcpy(&got, CMSG_DATA(c), sizeof(int));
            Fd owned(got);
            if (fd != nullptr) {
                *fd = std::move(owned);
            }
        }
    }
    auto reply = decode_reply(ByteView(buf.data(), static_cast<std::size_t>(n)));
    if (!reply) {
        return reply.error();
    }
    if (reply->status != Status::ok) {
        last_ = reply->message;
        return make_error(reply->status == Status::failed ? Errc::io : Errc::invalid_argument, reply->err,
                          "netd: the request was not done (last_error())");
    }
    return reply;
}

Result<void> Client::setup_node(const std::string& netns, const std::string& parent, std::array<std::uint8_t, 4> addr,
                                std::uint8_t prefix) {
    Request r;
    r.op = Op::setup_node;
    r.netns = netns;
    r.parent = parent;
    r.addr = addr;
    r.prefix = prefix;
    auto out = call(r, nullptr);
    if (!out) {
        return out.error();
    }
    return {};
}

Result<void> Client::teardown(const std::string& netns) {
    Request r;
    r.op = Op::teardown;
    r.netns = netns;
    auto out = call(r, nullptr);
    if (!out) {
        return out.error();
    }
    return {};
}

Result<Fd> Client::socket(const std::string& netns, SockKind kind, int family) {
    Request r;
    r.op = Op::socket;
    r.netns = netns;
    r.kind = kind;
    r.family = family == AF_INET6 ? 6 : 4;
    std::optional<Fd> fd;
    auto out = call(r, &fd);
    if (!out) {
        return out.error();
    }
    if (!fd) {
        return make_error(Errc::internal, 0, "netd: the reply carried no socket");
    }
    return std::move(*fd);
}

Result<std::vector<std::string>> Client::list() {
    Request r;
    r.op = Op::list;
    auto out = call(r, nullptr);
    if (!out) {
        return out.error();
    }
    return out->names;
}

Result<void> Client::gc() {
    Request r;
    r.op = Op::gc;
    auto out = call(r, nullptr);
    if (!out) {
        return out.error();
    }
    return {};
}

} // namespace ksim::net::netd
