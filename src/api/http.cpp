// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "api/http.hpp"

#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <thread>
#include <utility>
#include <vector>

#include <httplib.h>

namespace ksim::api {

namespace {

constexpr std::size_t kThreads = 16;   // long polls hold a thread each

Request to_request(const httplib::Request& in) {
    Request r;
    r.method = in.method;
    r.path = in.path;
    for (const auto& [k, v] : in.path_params) {
        r.params[k] = v;
    }
    for (const auto& [k, v] : in.params) {
        r.query.emplace(k, v);
    }
    if (!in.body.empty()) {
        r.body = json::parse(in.body, nullptr, false);
    }
    return r;
}

void answer(httplib::Response& res, const Reply& r) {
    res.status = r.http_status();
    res.set_content(r.body(), "application/json");
}

} // namespace

std::string Request::arg(const std::string& key, std::string fallback) const {
    if (auto it = query.find(key); it != query.end()) {
        return it->second;
    }
    if (body.is_object()) {
        if (auto it = body.find(key); it != body.end()) {
            return it->is_string() ? it->get<std::string>() : it->dump();
        }
    }
    return fallback;
}

struct Server::Impl {
    struct Route {
        std::string method;
        std::string pattern;
        Handler handler;
        StreamHandler stream;
    };
    std::vector<Route> routes;
    std::vector<std::unique_ptr<httplib::Server>> servers;
    std::vector<std::thread> threads;

    std::unique_ptr<httplib::Server> make() const {
        auto s = std::make_unique<httplib::Server>();
        s->new_task_queue = [] { return new httplib::ThreadPool(kThreads); };   // NOLINT(cppcoreguidelines-owning-memory): httplib owns it
        for (const auto& route : routes) {
            if (route.stream) {
                s->Get(route.pattern, [h = route.stream](const httplib::Request& in, httplib::Response& res) {
                    Request req = to_request(in);
                    res.set_chunked_content_provider("application/x-ndjson",
                                                     [h, req](std::size_t, httplib::DataSink& sink) {
                                                         h(req, [&sink](std::string_view chunk) {
                                                             return sink.write(chunk.data(), chunk.size());
                                                         });
                                                         sink.done();
                                                         return true;
                                                     });
                });
                continue;
            }
            auto fn = [h = route.handler](const httplib::Request& in, httplib::Response& res) {
                Request req = to_request(in);
                if (req.body.is_discarded()) {
                    answer(res, Reply::fail(Exit::usage, "the request body is not JSON"));
                    return;
                }
                answer(res, h(req));
            };
            if (route.method == "GET") {
                s->Get(route.pattern, fn);
            } else {
                s->Post(route.pattern, fn);
            }
        }
        s->set_error_handler([](const httplib::Request&, httplib::Response& res) {
            if (res.body.empty()) {
                Reply r = Reply::fail(Exit::usage, "no such route");
                res.set_content(r.body(), "application/json");
            }
        });
        s->set_exception_handler([](const httplib::Request&, httplib::Response& res, const std::exception_ptr&) {
            answer(res, Reply::fail(Exit::internal, "the handler failed"));
        });
        return s;
    }

    Result<void> serve(std::unique_ptr<httplib::Server> s, const std::string& host, int port) {
        if (!s->bind_to_port(host, port)) {
            return make_error(Errc::io, 0, "control API: cannot bind its address");
        }
        httplib::Server* raw = s.get();
        servers.push_back(std::move(s));
        threads.emplace_back([raw] { raw->listen_after_bind(); });
        return {};
    }
};

Server::Server() : impl_(std::make_unique<Impl>()) {}

Server::~Server() { stop(); }

void Server::get(const std::string& pattern, Handler h) { impl_->routes.push_back({"GET", pattern, std::move(h), {}}); }

void Server::post(const std::string& pattern, Handler h) { impl_->routes.push_back({"POST", pattern, std::move(h), {}}); }

void Server::stream(const std::string& pattern, StreamHandler h) {
    impl_->routes.push_back({"GET", pattern, {}, std::move(h)});
}

namespace {

/// A short socket path for a long one: <runtime dir>/ksim-<16 hex of its hash>.sock.
std::string short_socket(const std::string& path) {
    const char* xdg = std::getenv("XDG_RUNTIME_DIR");   // NOLINT(concurrency-mt-unsafe): read at start-up only
    std::string dir;
    if (xdg != nullptr && *xdg != '\0') {
        dir = xdg;
    } else {
        dir = "/tmp/ksim-" + std::to_string(::getuid());
        ::mkdir(dir.c_str(), 0700);
        struct stat st {};
        if (::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::getuid() || (st.st_mode & 077) != 0) {
            return {};
        }
    }
    const std::size_t h = std::hash<std::string>{}(path);
    std::array<char, 24> hex{};
    std::snprintf(hex.data(), hex.size(), "%016zx", h);
    return dir + "/ksim-" + hex.data() + ".sock";
}

} // namespace

std::string socket_target(const std::string& path) {
    std::array<char, 4096> buf{};
    const ssize_t n = ::readlink(path.c_str(), buf.data(), buf.size() - 1);
    return n > 0 ? std::string(buf.data(), static_cast<std::size_t>(n)) : path;
}

Result<void> Server::listen_unix(const std::string& path) {
    if (path.size() >= sizeof(sockaddr_un::sun_path)) {
        const std::string target = short_socket(path);
        if (target.empty() || target.size() >= sizeof(sockaddr_un::sun_path)) {
            return make_error(Errc::invalid_argument, 0, "control API: the socket path is too long for AF_UNIX");
        }
        ::unlink(path.c_str());   // a stale link
        auto r = listen_unix(target);
        if (!r) {
            return r;
        }
        if (::symlink(target.c_str(), path.c_str()) != 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "control API: cannot link the socket");
        }
        return {};
    }
    struct stat st {};
    if (::lstat(path.c_str(), &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            return make_error(Errc::invalid_argument, 0, "control API: the socket path exists and is not a socket");
        }
        ::unlink(path.c_str());
    }
    auto s = impl_->make();
    s->set_address_family(AF_UNIX);
    return impl_->serve(std::move(s), path, 80);
}

Result<void> Server::listen_tcp(const std::string& host, std::uint16_t port) {
    if (host.rfind("127.", 0) != 0 && host != "::1") {
        return make_error(Errc::invalid_argument, 0, "control API: TCP only on a loopback address");
    }
    return impl_->serve(impl_->make(), host, port);
}

void Server::stop() {
    for (auto& s : impl_->servers) {
        s->stop();
    }
    for (auto& t : impl_->threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    impl_->threads.clear();
    impl_->servers.clear();
}

} // namespace ksim::api
