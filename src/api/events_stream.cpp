// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "api/events_stream.hpp"

namespace ksim::api {

void stream_events(const EventRing& ring, std::uint64_t since, const std::function<bool(const Event&)>& keep,
                   bool follow, const std::atomic<bool>& stop, const Server::Write& write,
                   std::chrono::milliseconds beat) {
    for (;;) {
        for (const auto& e : ring.since(since, 1024)) {
            since = e.seq;
            if (keep(e) && !write(to_ndjson(e) + "\n")) {
                return;
            }
        }
        if (!follow || stop.load()) {
            return;
        }
        if (!ring.wait(since, [](const Event&) { return true; }, beat) && !write("\n")) {
            return;   // the client left while the node was quiet
        }
    }
}

} // namespace ksim::api
