// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/ue/device.hpp"

#include <fmt/format.h>

namespace ksim::node {

namespace {

constexpr Millis kPollMs = 10;
constexpr int kPollTries = 1000;   // 10 s for the card read

} // namespace

std::string guti_text(const nas::ie::MobileIdentity& g) {
    return fmt::format("{}{}-{:02x}-{:03x}-{:02x}-{:08x}", g.plmn.mcc, g.plmn.mnc, g.amf_region, g.amf_set, g.amf_pointer,
                       g.tmsi);
}

UeDevice::UeDevice(Executor& ex, IEventSink& events, UeDeviceConfig cfg, std::unique_ptr<uicc::os::Card> card,
                   std::function<void(air::Frame)> to_air, const UeTaps& taps)
    : ex_(ex), cfg_(std::move(cfg)), card_(std::move(card)), transport_(ex, card_.get()), terminal_(transport_) {
    const std::string subject = "ue:imsi-" + cfg_.supi;
    proc::ue::RrcConfig rc;
    rc.id = subject;
    rc.plmn = {cfg_.plmn.mcc, cfg_.plmn.mnc};
    rc.mac.radio_id = cfg_.radio_id;
    rc.allow_null_integrity = cfg_.allow_null_integrity;
    if (taps.rrc) {
        rc.tap = [tap = taps.rrc, supi = cfg_.supi](std::string_view channel, ByteView pdu) { tap(channel, pdu, supi); };
    }
    proc::ue::RrcUpper up;
    up.nas = [this](Bytes b) { mm_->on_nas(b); };
    up.released = [this] { mm_->on_released(); };
    up.kgnb = [this] { return mm_->kgnb(); };
    up.s_tmsi = [this] { return mm_->s_tmsi(); };
    up.paged = [] {};   // the service request is N12
    rrc_ = std::make_unique<proc::ue::UeRrc>(ex_, Rng(cfg_.seed, {cfg_.index, 1}), events, rc, up, std::move(to_air));
    proc::ue::MmConfig mc;
    mc.id = subject;
    mc.plmn = cfg_.plmn;
    mc.requested_nssai = cfg_.nssai;
    mc.imeisv = cfg_.imeisv;
    if (taps.nas) {
        mc.tap = [tap = taps.nas, supi = cfg_.supi](bool uplink, ByteView plain) { tap(uplink, plain, supi); };
    }
    mm_ = std::make_unique<proc::ue::Mm>(ex_, terminal_, *rrc_, events, mc);
}

UeDevice::~UeDevice() { *alive_ = false; }

void UeDevice::on_frame(const air::Frame& f) { rrc_->on_frame(f); }

Result<void> UeDevice::power_on() {
    if (powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is already on");
    }
    powered_ = true;
    mm_->power_on();
    poll_registration(kPollTries);
    return {};
}

void UeDevice::poll_registration(int left) {
    // The card read is asynchronous; registration starts once 5GMM leaves
    // 5GMM-NULL with a valid USIM. The RRC holds it until the UE camps.
    if (mm_->state() != proc::ue::MmState::null) {
        if (mm_->usim_valid()) {
            mm_->register_initial();
        }
        return;
    }
    if (left == 0) {
        return;
    }
    ex_.start_timer(kPollMs, [this, alive = alive_, left] {
        if (*alive) {
            poll_registration(left - 1);
        }
    });
}

Result<void> UeDevice::register_initial() {
    if (!powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is off");
    }
    if (!mm_->usim_valid() || !proc::ue::is_deregistered(mm_->state())) {
        return make_error(Errc::invalid_argument, 0, "the UE is not deregistered with a valid USIM");
    }
    mm_->register_initial();
    return {};
}

Result<void> UeDevice::deregister(bool switch_off) {
    if (mm_->state() != proc::ue::MmState::registered_initiated && !proc::ue::is_registered(mm_->state())) {
        return make_error(Errc::invalid_argument, 0, "the UE is not registered");
    }
    mm_->deregister(switch_off);
    if (switch_off) {
        powered_ = false;   // 5GMM-NULL at once: the UE is off (§5.5.2.2.1)
    }
    return {};
}

std::vector<std::pair<std::string, std::string>> UeDevice::status() const {
    using proc::ue::MmState;
    const MmState s = mm_->state();
    std::vector<std::pair<std::string, std::string>> out;
    out.emplace_back("UE", "imsi-" + cfg_.supi);
    out.emplace_back("INDEX", std::to_string(cfg_.index));
    out.emplace_back("POWER", powered_ ? "on" : "off");
    out.emplace_back("RM_STATE", proc::ue::is_registered(s) ? "RM-REGISTERED" : "RM-DEREGISTERED");
    out.emplace_back("CM_STATE", rrc_->state() == proc::ue::RrcState::idle ? "CM-IDLE" : "CM-CONNECTED");
    out.emplace_back("RRC_STATE", proc::ue::rrc_state_name(rrc_->state()));
    out.emplace_back("MM_STATE", proc::ue::mm_state_name(s));
    out.emplace_back("UPDATE_STATUS", proc::ue::update_status_name(mm_->update_status()));
    out.emplace_back("USIM", mm_->usim_valid() ? "valid" : "invalid");
    out.emplace_back("CAMPED", rrc_->camped() ? "1" : "0");
    out.emplace_back("AS_SECURITY", rrc_->as_security() ? "1" : "0");
    if (const auto& g = mm_->guti()) {
        out.emplace_back("GUTI", guti_text(*g));
    }
    if (const auto& tl = mm_->tai_list(); tl && !tl->tais.empty()) {
        const auto& t = tl->tais.front();
        out.emplace_back("TAI", fmt::format("{}{}-{:06x}", t.plmn.mcc, t.plmn.mnc, t.tac));
    }
    if (const auto c = rrc_->c_rnti()) {
        out.emplace_back("C_RNTI", fmt::format("0x{:04x}", *c));
    }
    if (const auto t = mm_->t3512()) {
        out.emplace_back("T3512_S", std::to_string(*t / 1000));
    }
    return out;
}

} // namespace ksim::node
