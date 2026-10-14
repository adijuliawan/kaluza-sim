// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "api/reply.hpp"

#include <utility>

namespace ksim::api {

Reply& Reply::set(const std::string& key, std::string value) {
    kv[key] = std::move(value);
    return *this;
}

Reply& Reply::set(const std::string& key, std::int64_t value) {
    kv[key] = std::to_string(value);
    return *this;
}

Reply Reply::fail(Exit e, std::string cause) {
    Reply r;
    r.exit = e;
    r.set("CAUSE", std::move(cause));
    return r;
}

json Reply::to_json() const {
    json j = json::object();
    j["exit"] = static_cast<int>(exit);
    j["kv"] = kv;
    return j;
}

Result<Reply> Reply::parse(std::string_view body) {
    const json j = json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.is_object() || !j.contains("exit") || !j["exit"].is_number_integer() ||
        !j.contains("kv") || !j["kv"].is_object()) {
        return make_error(Errc::malformed, 0, "not a control API reply");
    }
    Reply r;
    r.exit = static_cast<Exit>(j["exit"].get<int>());
    for (const auto& [k, v] : j["kv"].items()) {
        r.kv[k] = v.is_string() ? v.get<std::string>() : v.dump();
    }
    return r;
}

int Reply::http_status() const noexcept {
    switch (exit) {
    case Exit::ok: return 200;
    case Exit::failed: return 422;
    case Exit::usage: return 400;
    case Exit::timeout: return 504;
    case Exit::unknown: return 404;
    case Exit::capability: return 501;
    case Exit::wrong_state: return 409;
    case Exit::abort: return 503;
    case Exit::internal: return 500;
    }
    return 500;
}

std::string kv_lines(const json& kv) {
    std::string out;
    for (const auto& [k, v] : kv.items()) {
        std::string s = v.is_string() ? v.get<std::string>() : v.dump();
        std::string line;
        line.reserve(k.size() + s.size() + 2);
        line += k;
        line += '=';
        for (char c : s) {
            if (c == '\n') {
                line += "\\n";
            } else {
                line += c;
            }
        }
        out += line;
        out += '\n';
    }
    return out;
}

} // namespace ksim::api
