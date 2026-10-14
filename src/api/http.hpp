// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The control API's HTTP server (P1 N8; ADR 0009 point 7; architecture §9):
// HTTP/1.1 and JSON on a UNIX socket in the run directory, optionally on TCP
// at a loopback address too. cpp-httplib (vendored, MIT) serves it on its own
// threads; handlers never run procedure code there: they post to the node's
// shard and wait for the answer, or block on the event ring (wait, events).
// The run directory is 0700, so the socket is the run owner's only.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "api/reply.hpp"
#include "platform/result.hpp"

namespace ksim::api {

struct Request {
    std::string method;
    std::string path;
    std::map<std::string, std::string> params;        // the pattern's :name parts
    std::multimap<std::string, std::string> query;
    json body;                                        // the JSON body, or null when empty

    bool has(const std::string& key) const { return query.count(key) != 0 || (body.is_object() && body.contains(key)); }
    /// A query parameter, else a string member of the body, else `fallback`.
    std::string arg(const std::string& key, std::string fallback = {}) const;
};

class Server {
public:
    using Handler = std::function<Reply(const Request&)>;
    /// Writes one chunk of a stream; false once the client has gone.
    using Write = std::function<bool(std::string_view)>;
    using StreamHandler = std::function<void(const Request&, const Write&)>;

    Server();
    ~Server();   // stops and joins
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    /// Routes, set before listening. Patterns use :name parts ("/v1/ue/:sel/status").
    void get(const std::string& pattern, Handler h);
    void post(const std::string& pattern, Handler h);
    /// A GET answered as chunked NDJSON for as long as the handler writes.
    void stream(const std::string& pattern, StreamHandler h);

    /// Binds `path` (a stale socket file there is replaced) and serves it. An
    /// AF_UNIX path holds 107 octets; for a longer one the socket is bound in
    /// $XDG_RUNTIME_DIR (else a 0700 /tmp/ksim-<uid>) and `path` becomes a
    /// symbolic link to it, which clients follow (socket_target()).
    Result<void> listen_unix(const std::string& path);
    /// Binds a loopback address only (127.0.0.0/8 or ::1).
    Result<void> listen_tcp(const std::string& host, std::uint16_t port);
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// The socket a client connects to for `path`: the link's target if `path` is
/// a symbolic link, else `path`.
std::string socket_target(const std::string& path);

} // namespace ksim::api
