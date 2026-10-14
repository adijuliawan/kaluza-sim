// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The all-in-one node (P1 N8; architecture §2.1, ADR 0009): a gNB (one DU,
// one CU-CP) and a UE farm in one process. F1 runs over memlink as encoded
// F1AP, the air link as encoded KAIR v1 frames over memlink datagrams (point
// 1), and NG-C over a real SCTP association to the AMF (§2.1: never memory).
// P1 runs everything on one real-time shard, the reactor for NG-C included; the
// [shard:4][gen:4][index:24] ID routing waits for a second shard (N7 note).
//
// Every procedure object lives and dies on the shard. The control API's
// threads reach them only through call(), which posts and waits.

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "node/aio/capture.hpp"
#include "node/aio/run_dir.hpp"
#include "node/aio/topology.hpp"
#include "node/ue/device.hpp"
#include "platform/clock.hpp"
#include "platform/event.hpp"
#include "platform/shard.hpp"

namespace ksim::net {
class SctpClient;
}
namespace ksim::proc::ran {
class CuCp;
class Du;
}
namespace ksim {
class MemAssocPair;
class MemNet;
class IDatagram;
}

namespace ksim::node {

struct AioStats {
    std::uint64_t kair_frames = 0;
    std::uint64_t kair_errors = 0;   // frames that did not encode or decode
};

class AllInOne {
public:
    /// Builds every node and UE on a new shard and starts them: NG-C connects,
    /// F1 comes up, the cell goes on air. `why` says what was wrong otherwise.
    static std::unique_ptr<AllInOne> start(const Topology& t, const std::string& run_dir, std::string& why);
    ~AllInOne();
    AllInOne(const AllInOne&) = delete;
    AllInOne& operator=(const AllInOne&) = delete;

    /// Tears everything down on the shard, then stops it. Idempotent.
    void stop();

    EventRing& events() noexcept { return events_; }
    const Topology& topology() const noexcept { return topo_; }
    const std::string& run_dir() const noexcept { return run_dir_; }
    Capture* capture() noexcept { return capture_.get(); }
    Millis max_lag_ms() const noexcept { return shard_->max_lag_ms(); }

    /// Runs `fn` on the shard and returns its result, or nullopt when the
    /// shard did not run it within `timeout` (an unsound environment, exit 7).
    template <class T>
    std::optional<T> call(std::function<T()> fn, std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        auto p = std::make_shared<std::promise<T>>();
        auto fut = p->get_future();
        if (!shard_->post([p, fn = std::move(fn)]() mutable { p->set_value(fn()); })) {
            return std::nullopt;
        }
        if (fut.wait_for(timeout) != std::future_status::ready) {
            return std::nullopt;
        }
        return fut.get();
    }

    // On the shard only.
    std::vector<UeDevice*> ues();
    /// "imsi-001010000300001", "001010000300001" or a farm index ("17").
    UeDevice* ue(const std::string& selector);
    proc::ran::CuCp& cucp() { return *cucp_; }
    proc::ran::Du& du() { return *du_; }
    bool ng_up() const;
    const std::vector<std::string>& groups() const noexcept { return groups_; }   // by farm index - 1
    AioStats stats() const noexcept { return stats_; }

private:
    AllInOne(Topology t, std::string run_dir);
    Result<void> build(std::string& why);   // on the shard
    void teardown();                         // on the shard
    void du_to_air(const air::Frame& f);
    void ue_to_air(std::size_t i, const air::Frame& f);

    Topology topo_;
    std::string run_dir_;
    MonotonicClock clock_;
    EventRing events_;
    std::unique_ptr<EventFile> event_file_;
    std::unique_ptr<Capture> capture_;
    std::unique_ptr<Shard> shard_;
    bool stopped_ = false;

    // On the shard.
    std::unique_ptr<net::SctpClient> ng_;
    std::unique_ptr<TapAssoc> ng_tap_;
    std::unique_ptr<MemAssocPair> f1_;
    std::unique_ptr<TapAssoc> f1_tap_;
    std::unique_ptr<MemNet> air_;
    std::unique_ptr<IDatagram> du_air_;
    std::unique_ptr<proc::ran::CuCp> cucp_;
    std::unique_ptr<proc::ran::Du> du_;
    std::vector<std::unique_ptr<UeDevice>> ues_;
    std::vector<std::unique_ptr<IDatagram>> ue_air_;
    std::vector<std::uint32_t> radio_ids_;
    std::vector<std::string> groups_;
    AioStats stats_;
};

} // namespace ksim::node
