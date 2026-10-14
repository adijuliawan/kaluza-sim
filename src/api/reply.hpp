// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// What the control API answers (P1 N8; ADR 0009 point 7; cli.md §2): an exit
// code of cli.md's table and KEY=value pairs in a stable order. Over HTTP a
// reply is {"exit":n,"kv":{…}} with a status matching the exit code; ksim-ctl
// prints the pairs as KEY=value lines, or the object with --json, and exits
// with the code. Values are text: evidence, never key material (§3.6).

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "platform/result.hpp"

namespace ksim::api {

using json = nlohmann::ordered_json;

enum class Exit : int {
    ok = 0,
    failed = 1,        // the procedure was rejected or failed; CAUSE says why
    usage = 2,
    timeout = 3,
    unknown = 4,       // unknown node or UE
    capability = 5,    // capability absent
    wrong_state = 6,   // e.g. deregister while deregistered
    abort = 7,         // the environment is unsound
    internal = 10,
};

struct Reply {
    Exit exit = Exit::ok;
    json kv = json::object();

    Reply& set(const std::string& key, std::string value);
    Reply& set(const std::string& key, std::int64_t value);
    static Reply fail(Exit e, std::string cause);

    json to_json() const;
    std::string body() const { return to_json().dump(); }
    static Result<Reply> parse(std::string_view body);
    int http_status() const noexcept;
};

/// KEY=value lines in order, each ending in a newline. Newlines inside a
/// value are written as "\n" so one key stays one line.
std::string kv_lines(const json& kv);

} // namespace ksim::api
