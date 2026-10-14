// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's ideal MAC over KAIR (P1 N6; ADR 0003, architecture.md §2.3).
// Random access is real at the level the core can see (TS 38.321 §5.1): a
// random preamble in an occasion, the RAR matched by RA-RNTI and RAPID, Msg3
// with the CCCH SDU on the TC-RNTI, contention resolution by the identity in
// Msg4 (the first 48 bits of that SDU), a retry after a random backoff, and
// an RA problem after preambleTransMax attempts. HARQ, scheduling, timing
// advance and power control are not simulated (abstraction ledger). With a
// C-RNTI, uplink SDUs go out as UL_SDU frames and downlink SDUs for the
// C-RNTI go to their logical channel.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>

#include "codec/air/kair.hpp"
#include "entity/mac/iface.hpp"
#include "platform/executor.hpp"
#include "platform/rng.hpp"

namespace ksim::entity {

struct UeMacConfig {
    std::uint32_t radio_id = 0;        // the farm's handle for this UE (addressing only)
    Millis ra_response_window = 10;    // ra-ResponseWindow (sl10 at 30 kHz SCS, about 5 ms; rounded up)
    Millis contention_resolution = 64; // ra-ContentionResolutionTimer sf64
    int preamble_trans_max = 10;       // preambleTransMax n10
    Millis backoff_max = 20;           // the backoff indicator's range (Table 7.2-1, index 5)
    std::uint8_t preambles = 56;       // contention-based preambles 0..55
};

struct UeMacStats {
    std::uint64_t ra_attempts = 0;
    std::uint64_t ra_successes = 0;
    std::uint64_t contention_lost = 0;
    std::uint64_t ul_sdus = 0;
    std::uint64_t dl_sdus = 0;
    std::uint64_t dropped = 0;   // no C-RNTI, or an LCID with no bearer
};

class UeIdealMac final : public IMacSap {
public:
    using AirSink = std::function<void(air::Frame)>;

    UeIdealMac(TimerService& timers, Rng rng, UeMacConfig cfg, AirSink to_air);
    ~UeIdealMac() override;
    UeIdealMac(const UeIdealMac&) = delete;
    UeIdealMac& operator=(const UeIdealMac&) = delete;

    /// The cell the UE camps on (its KAIR handle).
    void camp(std::uint32_t cell_handle) noexcept { cell_ = cell_handle; }
    /// Random access carrying `ccch_sdu` in Msg3. `done(true)` once contention
    /// resolution succeeded (the C-RNTI is set and Msg4's DL-CCCH SDU went to
    /// LCID 0), `done(false)` on an RA problem.
    void start_ra(Bytes ccch_sdu, std::function<void(bool)> done);
    /// Back to no C-RNTI (RRC release, or going idle); an RA in progress stops.
    void reset();

    void send(std::uint8_t lcid, RlcMode mode, Bytes sdu) override;
    void attach(std::uint8_t lcid, IRlcBearer* bearer) override;
    void on_frame(const air::Frame& f);

    std::optional<std::uint16_t> c_rnti() const noexcept { return c_rnti_; }
    bool ra_running() const noexcept { return ra_.has_value(); }
    const UeMacStats& stats() const noexcept { return stats_; }

private:
    struct Ra {
        Bytes ccch;
        std::function<void(bool)> done;
        int attempts = 0;
        std::uint8_t preamble = 0;
        std::uint16_t ra_rnti = 0;
        std::optional<std::uint16_t> tc_rnti;
        std::optional<TimerId> timer;
    };
    void send_preamble();
    void ra_failed_attempt();
    void finish_ra(bool ok);
    void stop_ra_timer();
    air::Frame frame(air::FrameType t) const;

    TimerService& timers_;
    Rng rng_;
    UeMacConfig cfg_;
    AirSink to_air_;
    std::shared_ptr<bool> alive_;
    std::uint32_t cell_ = 0;
    std::optional<std::uint16_t> c_rnti_;
    std::optional<Ra> ra_;
    std::map<std::uint8_t, IRlcBearer*> bearers_;
    std::uint16_t seq_ = 0;
    UeMacStats stats_;
};

} // namespace ksim::entity
