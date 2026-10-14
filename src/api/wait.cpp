// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "api/wait.hpp"

#include <algorithm>
#include <cctype>

namespace ksim::api {

namespace {

bool listed(const std::vector<std::string>& names, const std::string& n) {
    return std::find(names.begin(), names.end(), n) != names.end();
}

std::string upper_key(std::string_view k) {
    std::string out;
    out.reserve(k.size());
    for (char c : k) {
        out += c == '.' || c == '-' ? '_' : static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return out;
}

} // namespace

bool WaitQuery::matches(const Event& e) const {
    if (!listed(until, e.name) && !listed(fail, e.name)) {
        return false;
    }
    if (!subject.empty() && e.subject != subject) {
        return false;
    }
    return std::all_of(where.begin(), where.end(), [&](const auto& w) {
        const std::string* v = e.find(w.first);
        return v != nullptr && *v == w.second;
    });
}

void add_evidence(Reply& r, const Event& e) {
    r.set("EVENT", e.name);
    r.set("SEQ", static_cast<std::int64_t>(e.seq));
    r.set("T_MS", static_cast<std::int64_t>(e.time_ms));
    r.set("SUBJECT", e.subject);
    if (e.subject.rfind("ue:", 0) == 0) {
        r.set("UE", e.subject.substr(3));
    }
    for (const auto& f : e.fields) {
        r.set(upper_key(f.key), f.value);
    }
}

Reply wait(const EventRing& ring, const WaitQuery& q) {
    auto e = ring.wait(q.since, [&](const Event& ev) { return q.matches(ev); }, q.timeout);
    if (!e) {
        Reply r = Reply::fail(Exit::timeout, "timeout");
        r.set("WAITED_MS", static_cast<std::int64_t>(q.timeout.count()));
        return r;
    }
    Reply r;
    if (listed(q.fail, e->name)) {
        r.exit = Exit::failed;
        const std::string* cause = e->find("cause");
        if (cause == nullptr) {
            cause = e->find("reason");
        }
        r.set("CAUSE", cause != nullptr ? *cause : e->name);
    }
    add_evidence(r, *e);
    return r;
}

std::vector<std::string> split_names(const std::string& list) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= list.size()) {
        const std::size_t comma = list.find(',', start);
        const std::size_t end = comma == std::string::npos ? list.size() : comma;
        if (end > start) {
            out.push_back(list.substr(start, end - start));
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return out;
}

} // namespace ksim::api
