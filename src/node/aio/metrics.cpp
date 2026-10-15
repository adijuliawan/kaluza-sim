// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/metrics.hpp"

#include <unistd.h>

#include <fstream>
#include <sstream>

namespace ksim::node {

namespace {

/// A label value as the text format writes it: \, " and newlines escaped.
std::string label(const std::string& v) {
    std::string out;
    out.reserve(v.size());
    for (const char c : v) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::uint64_t resident_bytes() {
    std::ifstream in("/proc/self/statm");
    std::uint64_t size = 0;
    std::uint64_t resident = 0;
    in >> size >> resident;
    return resident * static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE));
}

std::uint64_t threads() {
    std::ifstream in("/proc/self/status");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("Threads:", 0) == 0) {
            return std::stoull(line.substr(8));
        }
    }
    return 0;
}

} // namespace

void Metrics::count_event(const Event& e) {
    std::string cause;
    for (const auto& f : e.fields) {
        if (f.key == "cause") {
            cause = f.value;
        }
    }
    const std::lock_guard lock(mu_);
    ++events_[{e.name, cause}];
}

void Metrics::observe(Hop h, Millis latency) {
    const double ms = latency < 0 ? 0.0 : static_cast<double>(latency);
    const std::lock_guard lock(mu_);
    Histogram& g = hops_[static_cast<std::size_t>(h)];
    ++g.count;
    g.sum += ms;
    for (std::size_t i = 0; i < kBuckets.size(); ++i) {
        if (ms <= kBuckets[i]) {
            ++g.le[i];
            break;
        }
    }
}

std::string Metrics::render(const std::map<std::uint8_t, QfiCounters>& per_qfi, Millis loop_lag_ms) const {
    std::ostringstream o;
    const std::lock_guard lock(mu_);
    o << "# HELP ksim_events_total Events emitted, by name and cause.\n# TYPE ksim_events_total counter\n";
    for (const auto& [k, n] : events_) {
        o << "ksim_events_total{event=\"" << label(k.first) << "\",cause=\"" << label(k.second) << "\"} " << n << "\n";
    }
    o << "# HELP ksim_qfi_bytes_total User-plane octets at the CU-UP's N3, by QFI and direction.\n"
         "# TYPE ksim_qfi_bytes_total counter\n";
    for (const auto& [qfi, c] : per_qfi) {
        o << "ksim_qfi_bytes_total{qfi=\"" << static_cast<unsigned>(qfi) << "\",direction=\"ul\"} " << c.ul_bytes << "\n";
        o << "ksim_qfi_bytes_total{qfi=\"" << static_cast<unsigned>(qfi) << "\",direction=\"dl\"} " << c.dl_bytes << "\n";
    }
    o << "# HELP ksim_qfi_packets_total User-plane packets at the CU-UP's N3, by QFI and direction.\n"
         "# TYPE ksim_qfi_packets_total counter\n";
    for (const auto& [qfi, c] : per_qfi) {
        o << "ksim_qfi_packets_total{qfi=\"" << static_cast<unsigned>(qfi) << "\",direction=\"ul\"} " << c.ul_packets << "\n";
        o << "ksim_qfi_packets_total{qfi=\"" << static_cast<unsigned>(qfi) << "\",direction=\"dl\"} " << c.dl_packets << "\n";
    }
    o << "# HELP ksim_hop_latency_ms One-way latency of a hop, from the frame's send time, ms.\n"
         "# TYPE ksim_hop_latency_ms histogram\n";
    const char* names[] = {"kair_ul", "kair_dl"};
    for (std::size_t h = 0; h < hops_.size(); ++h) {
        const Histogram& g = hops_[h];
        if (g.count == 0) {
            continue;
        }
        std::uint64_t cum = 0;
        for (std::size_t i = 0; i < kBuckets.size(); ++i) {
            cum += g.le[i];
            o << "ksim_hop_latency_ms_bucket{hop=\"" << names[h] << "\",le=\"" << kBuckets[i] << "\"} " << cum << "\n";
        }
        o << "ksim_hop_latency_ms_bucket{hop=\"" << names[h] << "\",le=\"+Inf\"} " << g.count << "\n";
        o << "ksim_hop_latency_ms_sum{hop=\"" << names[h] << "\"} " << g.sum << "\n";
        o << "ksim_hop_latency_ms_count{hop=\"" << names[h] << "\"} " << g.count << "\n";
    }
    o << "# HELP ksim_process_resident_bytes The process's resident set.\n# TYPE ksim_process_resident_bytes gauge\n"
      << "ksim_process_resident_bytes " << resident_bytes() << "\n"
      << "# HELP ksim_process_threads The process's threads.\n# TYPE ksim_process_threads gauge\n"
      << "ksim_process_threads " << threads() << "\n"
      << "# HELP ksim_loop_lag_max_ms The largest timer lateness seen, ms.\n# TYPE ksim_loop_lag_max_ms gauge\n"
      << "ksim_loop_lag_max_ms " << loop_lag_ms << "\n";
    return o.str();
}

} // namespace ksim::node
