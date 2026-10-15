// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Metrics v0 (P2 Q7; ADR 0011 point 6; KS-CTL-005 in part): what a run's process
// reports on /v1/metrics, in the Prometheus text format. The events emitted, by
// name and cause; the CU-UP's bytes and packets per QFI and direction (N3 side);
// the one-way latency of each KAIR hop (the frame's send time, the processes'
// shared CLOCK_MONOTONIC, ms) as histograms; the process's resident size,
// threads and loop lag. TS 28.552's names are later. Observations come from any
// thread; render() from the control API's.

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>

#include "platform/clock.hpp"
#include "platform/event.hpp"

namespace ksim::node {

struct QfiCounters {
    std::uint64_t ul_bytes = 0;
    std::uint64_t dl_bytes = 0;
    std::uint64_t ul_packets = 0;
    std::uint64_t dl_packets = 0;
};

class Metrics {
public:
    enum class Hop : std::uint8_t { kair_ul, kair_dl };
    void count_event(const Event& e);
    void observe(Hop h, Millis latency);
    /// The text for one process: `role` labels nothing here (the supervisor adds it),
    /// `per_qfi` and `loop_lag_ms` are read on the shard by the caller.
    std::string render(const std::map<std::uint8_t, QfiCounters>& per_qfi, Millis loop_lag_ms) const;

    static constexpr std::array<double, 11> kBuckets{0.5, 1, 2, 5, 10, 20, 50, 100, 250, 500, 1000};   // ms

private:
    struct Histogram {
        std::array<std::uint64_t, kBuckets.size()> le{};   // cumulative at render
        std::uint64_t count = 0;
        double sum = 0;
    };
    mutable std::mutex mu_;
    std::map<std::pair<std::string, std::string>, std::uint64_t> events_;   // (name, cause)
    std::array<Histogram, 2> hops_{};
};

} // namespace ksim::node
