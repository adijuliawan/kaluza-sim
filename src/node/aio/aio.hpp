// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The all-in-one node (P1 N8; architecture §2.1, ADR 0009): a gNB (one DU,
// one CU-CP, and from N10 one CU-UP) and a UE farm in one process. F1 and E1
// run over memlink as encoded F1AP and E1AP, F1-U as GTP-U over memlink
// datagrams, the air link as encoded KAIR v1 frames over memlink datagrams
// (point 1), and NG-C and N3 over real sockets to the core (§2.1: never
// memory): SCTP to the AMF, UDP 2152 to the UPF, each from its node's own
// namespace when the topology has netd.
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
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "node/aio/capture.hpp"
#include "node/aio/run_dir.hpp"
#include "node/aio/topology.hpp"
#include "node/ue/device.hpp"
#include "platform/assoc_slot.hpp"
#include "platform/blocking.hpp"
#include "platform/clock.hpp"
#include "platform/event.hpp"
#include "platform/memlink.hpp"
#include "platform/shard.hpp"

namespace ksim::net {
class SctpClient;
class SctpListener;
class SeqpacketListener;
namespace netd {
class Client;
}
}
namespace ksim::proc::ran {
class CuCp;
class CuUp;
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
    // P2 Q3: what this process hosts; in a split run one role each (ADR 0011).
    bool hosts_ues() const noexcept { return topo_.role == Role::all || topo_.role == Role::ue; }
    bool hosts_cucp() const noexcept { return topo_.role == Role::all || topo_.role == Role::cucp; }
    bool hosts_cuup() const noexcept { return topo_.role == Role::all || topo_.role == Role::cuup; }
    bool hosts_du() const noexcept { return topo_.role == Role::all || topo_.role == Role::du; }
    proc::ran::CuUp& cuup() { return *cuup_; }
    bool ng_up() const;
    /// The gNB's nodes stop and start again (P1 N12, ksim-ctl gnb restart).
    Result<void> restart_gnb();
    const std::vector<std::string>& groups() const noexcept { return groups_; }   // by farm index - 1
    AioStats stats() const noexcept { return stats_; }

private:
    AllInOne(Topology t, std::string run_dir);
    Result<void> build(std::string& why);   // on the shard
    Result<void> build_gnb(std::string& why);
    struct FarmCard {
        std::string imsi;
        std::string group;
        const UeGroup* g;
        std::unique_ptr<uicc::os::Card> card;
    };
    Result<void> build_farm(std::vector<FarmCard> cards, const std::map<const UeGroup*, Persona>& personas,
                            std::string& why);
    void kair_accept(std::unique_ptr<IChannel> c);   // P2 Q3: the DU's end of KAIR
    void kair_connect();                             // P2 Q3: the farm's end
    std::unique_ptr<uicc::IApduTransport> external_reader(const UeGroup& g, std::string& why);   // P2 Q1
    void connect_gnb();
    void teardown_gnb();
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
    std::unique_ptr<BlockingPool> blocking_;   // P2 Q1: PC/SC calls, made when a UE's card is pcsc:
    bool stopped_ = false;

    // On the shard.
    std::unique_ptr<net::netd::Client> netd_;   // with topology netd: the nodes' and UEs' namespaces
    std::unique_ptr<NetdUeNet> ue_net_;         // with netd ues: the UEs' TUN data plane
    std::unique_ptr<net::SctpClient> ng_;
    std::unique_ptr<TapAssoc> ng_tap_;
    std::unique_ptr<MemAssocPair> f1_;
    std::unique_ptr<TapAssoc> f1_tap_;
    std::unique_ptr<TapAssoc> du_f1_tap_;   // P2 Q4: the DU's F1-C, captured when the CU-CP is a peer
    std::unique_ptr<MemAssocPair> e1_;
    std::unique_ptr<TapAssoc> e1_tap_;
    std::unique_ptr<TapAssoc> cuup_e1_tap_;   // P2 Q5: the CU-UP's E1, captured when the CU-CP is a peer
    // P2 Q3, split: the real links of whichever roles this process hosts.
    std::unique_ptr<AssocSlot> f1_slot_;               // the CU-CP's F1-C
    std::unique_ptr<net::SctpListener> f1_listen_;
    std::unique_ptr<net::SctpClient> f1_client_;       // the DU's F1-C
    std::unique_ptr<AssocSlot> e1_slot_;               // the CU-CP's E1
    std::unique_ptr<net::SctpListener> e1_listen_;
    std::unique_ptr<net::SctpClient> e1_client_;       // the CU-UP's E1
    std::unique_ptr<net::SeqpacketListener> kair_listen_;   // the DU's KAIR
    std::vector<std::unique_ptr<IChannel>> kair_peers_;     // one per farm shard
    std::map<std::uint32_t, IChannel*> kair_route_;         // radio ID to the farm it spoke from
    std::unique_ptr<IChannel> kair_;                        // the farm's KAIR
    std::optional<TimerId> kair_retry_;
    std::unique_ptr<MemNet> f1u_net_;
    std::unique_ptr<IDatagram> cuup_f1u_;
    std::unique_ptr<IDatagram> du_f1u_;
    std::unique_ptr<IDatagram> n3_;
    std::unique_ptr<MemNet> air_;
    std::unique_ptr<IDatagram> du_air_;
    std::unique_ptr<proc::ran::CuCp> cucp_;
    std::unique_ptr<proc::ran::Du> du_;
    std::unique_ptr<proc::ran::CuUp> cuup_;
    std::vector<std::unique_ptr<UeDevice>> ues_;
    std::vector<std::unique_ptr<IDatagram>> ue_air_;
    std::vector<std::uint32_t> radio_ids_;
    std::vector<Slice> slices_;
    MemLinkConfig link_{};
    static constexpr Millis kRestartOffAir = 2'000;
    Millis air_off_until_ = 0;   // the cell is off the air before this (gnb restart)
    std::vector<std::string> groups_;
    AioStats stats_;
};

} // namespace ksim::node
