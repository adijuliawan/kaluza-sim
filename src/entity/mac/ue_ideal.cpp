// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "entity/mac/ue_ideal.hpp"

#include <utility>

namespace ksim::entity {

UeIdealMac::UeIdealMac(TimerService& timers, Rng rng, UeMacConfig cfg, AirSink to_air)
    : timers_(timers), rng_(rng), cfg_(cfg), to_air_(std::move(to_air)), alive_(std::make_shared<bool>(true)) {}

UeIdealMac::~UeIdealMac() {
    *alive_ = false;
    stop_ra_timer();
}

air::Frame UeIdealMac::frame(air::FrameType t) const {
    air::Frame f;
    f.type = t;
    f.cell_handle = cell_;
    f.radio_id = cfg_.radio_id;
    const Millis now = timers_.now();
    f.tx_time_ns = static_cast<std::uint64_t>(now) * 1'000'000;
    // 30 kHz SCS: two slots a millisecond, 20 a frame.
    f.sfn_slot = static_cast<std::uint32_t>(((now / 10) % 1024) << 8 | ((now % 10) * 2));
    return f;
}

void UeIdealMac::start_ra(Bytes ccch_sdu, std::function<void(bool)> done) {
    if (ra_) {
        done(false);
        return;
    }
    Ra& ra = ra_.emplace();
    ra.ccch = std::move(ccch_sdu);
    ra.done = std::move(done);
    send_preamble();
}

void UeIdealMac::send_preamble() {
    if (!ra_) {
        return;
    }
    Ra& ra = *ra_;
    if (++ra.attempts > cfg_.preamble_trans_max) {
        finish_ra(false);   // an RA problem (TS 38.321 §5.1.4)
        return;
    }
    ++stats_.ra_attempts;
    air::Frame f = frame(air::FrameType::prach);
    air::Prach p;
    p.preamble = static_cast<std::uint8_t>(rng_.below(cfg_.preambles));
    p.t_id = static_cast<std::uint8_t>(f.slot() % 20);
    ra.preamble = p.preamble;
    ra.ra_rnti = p.ra_rnti();
    ra.tc_rnti.reset();
    f.prach = p;
    f.seq = seq_++;
    ra.timer = timers_.start_timer(cfg_.ra_response_window, [this, alive = alive_] {
        if (*alive && ra_) {
            ra_->timer.reset();
            ra_failed_attempt();
        }
    });
    to_air_(std::move(f));
}

void UeIdealMac::ra_failed_attempt() {
    if (!ra_) {
        return;
    }
    Ra& ra = *ra_;
    if (ra.timer) {
        timers_.stop_timer(*ra.timer);
        ra.timer.reset();
    }
    ra.tc_rnti.reset();
    const auto backoff = static_cast<Millis>(rng_.uniform(0, cfg_.backoff_max));
    ra.timer = timers_.start_timer(backoff, [this, alive = alive_] {
        if (*alive && ra_) {
            ra_->timer.reset();
            send_preamble();
        }
    });
}

void UeIdealMac::finish_ra(bool ok) {
    if (!ra_) {
        return;
    }
    auto done = std::move(ra_->done);
    stop_ra_timer();
    ra_.reset();
    if (ok) {
        ++stats_.ra_successes;
    }
    if (done) {
        done(ok);
    }
}

void UeIdealMac::stop_ra_timer() {
    if (ra_ && ra_->timer) {
        timers_.stop_timer(*ra_->timer);
        ra_->timer.reset();
    }
}

void UeIdealMac::reset() {
    c_rnti_.reset();
    stop_ra_timer();
    ra_.reset();
}

void UeIdealMac::on_frame(const air::Frame& f) {
    switch (f.type) {
    case air::FrameType::rar:
        if (ra_ && !ra_->tc_rnti && f.rar && f.rnti == ra_->ra_rnti && f.rar->rapid == ra_->preamble) {
            Ra& ra = *ra_;
            const air::Rar& rar = *f.rar;
            stop_ra_timer();
            ra.tc_rnti = rar.tc_rnti;
            air::Frame m = frame(air::FrameType::msg3);
            m.rnti = rar.tc_rnti;
            m.seq = seq_++;
            m.sdus.push_back(air::Sdu{0, RlcMode::tm, ra.ccch});
            ra.timer = timers_.start_timer(cfg_.contention_resolution, [this, alive = alive_] {
                if (*alive && ra_) {
                    ra_->timer.reset();
                    ra_failed_attempt();
                }
            });
            to_air_(std::move(m));
        }
        return;
    case air::FrameType::msg4:
        if (ra_ && ra_->tc_rnti && f.rnti == *ra_->tc_rnti && f.contention_id && f.sdus.size() == 1) {
            if (*f.contention_id != air::contention_id_of(ra_->ccch)) {
                ++stats_.contention_lost;   // another UE's Msg3 won (TS 38.321 §5.1.5)
                ra_failed_attempt();
                return;
            }
            c_rnti_ = ra_->tc_rnti;
            Bytes ccch = f.sdus.front().data;
            finish_ra(true);
            auto it = bearers_.find(0);
            if (it != bearers_.end() && it->second != nullptr) {
                ++stats_.dl_sdus;
                it->second->receive(std::move(ccch));
            }
        }
        return;
    case air::FrameType::dl_sdu:
        if (!c_rnti_ || f.rnti != *c_rnti_) {
            ++stats_.dropped;
            return;
        }
        for (const air::Sdu& s : f.sdus) {
            auto it = bearers_.find(s.lcid);
            if (it == bearers_.end() || it->second == nullptr) {
                ++stats_.dropped;
                continue;
            }
            ++stats_.dl_sdus;
            it->second->receive(s.data);
        }
        return;
    default:
        return;
    }
}

void UeIdealMac::send(std::uint8_t lcid, RlcMode mode, Bytes sdu) {
    if (!c_rnti_ || lcid == 0) {
        ++stats_.dropped;   // CCCH goes in Msg3 (start_ra)
        return;
    }
    air::Frame f = frame(air::FrameType::ul_sdu);
    f.rnti = *c_rnti_;
    f.seq = seq_++;
    f.sdus.push_back(air::Sdu{lcid, mode, std::move(sdu)});
    ++stats_.ul_sdus;
    to_air_(std::move(f));
}

void UeIdealMac::attach(std::uint8_t lcid, IRlcBearer* bearer) {
    if (bearer == nullptr) {
        bearers_.erase(lcid);
    } else {
        bearers_[lcid] = bearer;
    }
}

} // namespace ksim::entity
