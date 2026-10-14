// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/event.hpp"

#include <utility>

namespace ksim {

const std::string* Event::find(std::string_view key) const noexcept {
    for (const auto& f : fields) {
        if (f.key == key) {
            return &f.value;
        }
    }
    return nullptr;
}

EventRing::EventRing(std::size_t capacity, const Clock& clock) : capacity_(capacity > 0 ? capacity : 1), clock_(clock) {}

void EventRing::on_emit(std::function<void(const Event&)> listener) {
    const std::lock_guard lock(mu_);
    listener_ = std::move(listener);
}

void EventRing::emit(EventName name, std::string subject, std::vector<EventField> fields) {
    Event e;
    e.time_ms = clock_.now_ms();
    e.wall_ns = realtime_ns();
    e.name = name.name;
    e.subject = std::move(subject);
    e.fields = std::move(fields);
    {
        // The listener runs under the lock, so the NDJSON lines come out in seq
        // order even when several shards emit at once. It must not emit.
        const std::lock_guard lock(mu_);
        e.seq = ++seq_;
        if (ring_.size() == capacity_) {
            ring_.pop_front();
            ++dropped_;
        }
        ring_.push_back(std::move(e));
        if (listener_) {
            listener_(ring_.back());
        }
    }
    cv_.notify_all();
}

std::uint64_t EventRing::last_seq() const {
    const std::lock_guard lock(mu_);
    return seq_;
}

std::uint64_t EventRing::dropped() const {
    const std::lock_guard lock(mu_);
    return dropped_;
}

std::vector<Event> EventRing::since(std::uint64_t since, std::size_t max) const {
    const std::lock_guard lock(mu_);
    std::vector<Event> out;
    for (const auto& e : ring_) {
        if (e.seq > since) {
            if (out.size() == max) {
                break;
            }
            out.push_back(e);
        }
    }
    return out;
}

std::optional<Event> EventRing::wait(std::uint64_t since, const std::function<bool(const Event&)>& match,
                                     std::chrono::milliseconds timeout) const {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock lock(mu_);
    std::uint64_t seen = since;
    for (;;) {
        for (const auto& e : ring_) {
            if (e.seq > seen) {
                seen = e.seq;
                if (match(e)) {
                    return e;
                }
            }
        }
        if (cv_.wait_until(lock, deadline, [&] { return seq_ > seen; })) {
            continue;
        }
        return std::nullopt;
    }
}

namespace {

void json_string(std::string& out, std::string_view s) {
    static constexpr char kHex[] = "0123456789abcdef";
    out += '"';
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                out += "\\u00";
                out += kHex[c >> 4];
                out += kHex[c & 0xF];
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
}

} // namespace

std::string to_ndjson(const Event& e) {
    std::string out = "{\"seq\":" + std::to_string(e.seq) + ",\"t_ms\":" + std::to_string(e.time_ms) +
                      ",\"wall_ns\":" + std::to_string(e.wall_ns) + ",\"event\":";
    json_string(out, e.name);
    out += ",\"subject\":";
    json_string(out, e.subject);
    out += ",\"fields\":{";
    bool first = true;
    for (const auto& f : e.fields) {
        if (!first) {
            out += ',';
        }
        first = false;
        json_string(out, f.key);
        out += ':';
        json_string(out, f.value);
    }
    out += "}}";
    return out;
}

} // namespace ksim
