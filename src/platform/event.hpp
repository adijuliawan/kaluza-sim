// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The run's events (P1 N1, ADR 0009 point 6; architecture §9). A component
// reports what happened as a named event about a subject (a UE, a node) with
// KEY=value evidence. The run keeps them numbered in a ring: `ksim-ctl wait`
// long-polls it, and the NDJSON writer streams it to `events.ndjson`.
//
// An event name is a string literal (EventName's constructor is consteval), so
// tools/guards/check_events.py can find every name in the code and require it
// in src/api/events.tsv with its spec clause. Evidence must never hold key
// material: SecretBytes has no conversion to text (rule of §3.6).

#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "platform/clock.hpp"

namespace ksim {

struct EventName {
    consteval EventName(const char* n) : name(n) {}   // NOLINT(google-explicit-constructor): literals only
    const char* name;
};

struct EventField {
    std::string key;
    std::string value;
};

struct Event {
    std::uint64_t seq = 0;       // 1, 2, … in the order emitted
    Millis time_ms = 0;          // the run's clock (virtual in procedure tests)
    std::int64_t wall_ns = 0;    // CLOCK_REALTIME, for correlating with pcaps
    std::string name;
    std::string subject;         // "ue:imsi-001010000300001", "gnb:ksim-gnb1", …
    std::vector<EventField> fields;

    /// The value of field `key`, or nullptr.
    const std::string* find(std::string_view key) const noexcept;
};

class IEventSink {
public:
    virtual ~IEventSink() = default;
    virtual void emit(EventName name, std::string subject, std::vector<EventField> fields) = 0;
};

/// A bounded, numbered, thread-safe event log. When full the oldest event is
/// dropped (the NDJSON file keeps everything).
class EventRing final : public IEventSink {
public:
    EventRing(std::size_t capacity, const Clock& clock);

    void emit(EventName name, std::string subject, std::vector<EventField> fields) override;

    std::uint64_t last_seq() const;
    std::uint64_t dropped() const;
    /// Events with seq > `since`, oldest first, at most `max`.
    std::vector<Event> since(std::uint64_t since, std::size_t max = SIZE_MAX) const;
    /// The first event with seq > `since` that `match` accepts, waiting up to
    /// `timeout` of real time for one to arrive. Not for virtual-time loops,
    /// which read since() instead.
    std::optional<Event> wait(std::uint64_t since, const std::function<bool(const Event&)>& match,
                              std::chrono::milliseconds timeout) const;
    /// Called with each event after it is numbered, on the emitting thread and
    /// under the ring's lock (so in seq order); it must not emit. Set it before
    /// emitting starts.
    void on_emit(std::function<void(const Event&)> listener);

private:
    const std::size_t capacity_;
    const Clock& clock_;
    mutable std::mutex mu_;
    mutable std::condition_variable cv_;
    std::deque<Event> ring_;
    std::uint64_t seq_ = 0;
    std::uint64_t dropped_ = 0;
    std::function<void(const Event&)> listener_;
};

/// One NDJSON line (no trailing newline): {"seq":…,"t_ms":…,"wall_ns":…,
/// "event":…,"subject":…,"fields":{…}} with JSON string escaping.
std::string to_ndjson(const Event& e);

} // namespace ksim
