// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/ue/device.hpp"

#include <fmt/format.h>

#include <algorithm>

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
    : ex_(ex), cfg_(std::move(cfg)), card_(std::move(card)), transport_(ex, card_.get()), terminal_(transport_),
      events_(events) {
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
    up.dl_data = [this](std::uint8_t psi, std::optional<sdap::DlHeader>, Bytes sdu) { on_dl_ip(psi, std::move(sdu)); };
    rrc_ = std::make_unique<proc::ue::UeRrc>(ex_, Rng(cfg_.seed, {cfg_.index, 1}), events, rc, up, std::move(to_air));
    proc::ue::MmConfig mc;
    mc.id = subject;
    mc.plmn = cfg_.plmn;
    mc.requested_nssai = cfg_.nssai;
    mc.imeisv = cfg_.imeisv;
    if (taps.nas) {
        mc.tap = [tap = taps.nas, supi = cfg_.supi](bool uplink, ByteView plain) { tap(uplink, plain, supi); };
    }
    mc.sm = [this](const proc::ue::SmDownlink& d) { sm_->on_downlink(d); };
    mm_ = std::make_unique<proc::ue::Mm>(ex_, terminal_, *rrc_, events, mc);
    proc::ue::SmConfig sc;
    sc.id = subject;
    proc::ue::SmUpper su;
    su.down = [this](std::uint8_t psi) {
        if (ping_ && ping_->psi == psi) {
            ping_done("session released");
        }
    };
    sm_ = std::make_unique<proc::ue::Sm>(ex_, events, sc, [this](const proc::ue::SmUplink& u) { return mm_->send_sm(u); }, su);
}

UeDevice::~UeDevice() {
    *alive_ = false;
    if (ping_ && ping_->timer) {
        ex_.stop_timer(*ping_->timer);
    }
}

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
    // TS 24.501 §5.5.2.2.1: the UE's PDU sessions go with its registration.
    sm_->release_all_local(switch_off ? "switch-off" : "deregistration");
    if (switch_off) {
        powered_ = false;   // 5GMM-NULL at once: the UE is off (§5.5.2.2.1)
    }
    return {};
}

Result<void> UeDevice::ps_establish(const proc::ue::SessionRequest& r) {
    if (!proc::ue::is_registered(mm_->state())) {
        return make_error(Errc::invalid_argument, 0, "the UE is not registered");
    }
    auto psi = sm_->establish(r);
    if (!psi) {
        return psi.error();
    }
    return {};
}

Result<void> UeDevice::ps_release(std::uint8_t psi) { return sm_->release(psi); }

// ---- the inject-mode ping ----------------------------------------------------------------------

Result<void> UeDevice::ping(const PingRequest& p) {
    if (ping_) {
        return make_error(Errc::invalid_argument, 0, "a ping is running on this UE");
    }
    const proc::ue::SessionInfo* s = nullptr;
    if (p.psi != 0) {
        s = sm_->session(p.psi);
    } else {
        for (const auto& info : sm_->sessions()) {
            if (info.state == proc::ue::SmState::active) {
                s = sm_->session(info.psi);
                break;
            }
        }
    }
    if (s == nullptr || s->state != proc::ue::SmState::active || !s->ipv4) {
        return make_error(Errc::invalid_argument, p.psi, "no active IPv4 PDU session");
    }
    Ping g;
    g.id = ++ping_id_;
    g.req = p;
    g.psi = s->psi;
    g.src = *s->ipv4;
    ping_ = std::move(g);
    ping_next();
    return {};
}

void UeDevice::ping_next() {
    if (!ping_) {
        return;
    }
    Ping& g = *ping_;
    g.timer.reset();
    if (g.sent >= g.req.count) {
        ping_done("done");
        return;
    }
    const auto seq = static_cast<std::uint16_t>(g.sent + 1);
    const proc::ue::SessionInfo* s = sm_->session(g.psi);
    if (s == nullptr) {
        ping_done("session released");
        return;
    }
    auto sent = rrc_->send_data(g.psi, s->default_qfi, ip::ping(g.src, g.req.dst, g.id, seq, g.req.size));
    ++g.sent;
    if (sent) {
        ++ul_packets_;
        g.outstanding[seq] = ex_.now();
    } else {
        events_.emit("ue.ping.error", subject(), {{"seq", std::to_string(seq)}, {"what", sent.error().what}});
    }
    const Millis wait = g.sent >= g.req.count ? g.req.linger : g.req.interval;
    g.timer = ex_.start_timer(wait, [this, alive = alive_] {
        if (*alive && ping_) {
            ping_next();
        }
    });
}

void UeDevice::ping_done(const char* why) {
    if (!ping_) {
        return;
    }
    Ping g = std::move(*ping_);
    ping_.reset();
    if (g.timer) {
        ex_.stop_timer(*g.timer);
    }
    const int loss = g.sent == 0 ? 100 : (g.sent - g.received) * 100 / g.sent;
    events_.emit("ue.ping.done", subject(),
                 {{"psi", std::to_string(g.psi)},
                  {"dst", fmt::format("{}.{}.{}.{}", g.req.dst[0], g.req.dst[1], g.req.dst[2], g.req.dst[3])},
                  {"sent", std::to_string(g.sent)},
                  {"received", std::to_string(g.received)},
                  {"loss_pct", std::to_string(loss)},
                  {"rtt_min_ms", std::to_string(g.rtt_min)},
                  {"rtt_avg_ms", std::to_string(g.received == 0 ? 0 : g.rtt_sum / g.received)},
                  {"rtt_max_ms", std::to_string(g.rtt_max)},
                  {"why", why}});
}

void UeDevice::on_dl_ip(std::uint8_t psi, Bytes packet) {
    ++dl_packets_;
    auto p = ip::decode(packet);
    if (!p || p->protocol != ip::kIcmp) {
        return;
    }
    auto e = ip::decode_icmp(p->payload);
    if (!e || !*e) {
        return;
    }
    const ip::Echo& echo = **e;
    if (!echo.reply) {
        // An echo request to the UE (a ping from the DN): answered on the same session.
        const proc::ue::SessionInfo* s = sm_->session(psi);
        if (s != nullptr && s->ipv4 && p->dst == *s->ipv4) {
            ip::Echo r = echo;
            r.reply = true;
            ip::Ipv4 out;
            out.id = p->id;
            out.protocol = ip::kIcmp;
            out.src = p->dst;
            out.dst = p->src;
            out.payload = ip::encode_icmp(r);
            if (rrc_->send_data(psi, s->default_qfi, ip::encode(out))) {
                ++ul_packets_;
            }
            events_.emit("ue.ping.answered", subject(),
                         {{"psi", std::to_string(psi)},
                          {"from", fmt::format("{}.{}.{}.{}", p->src[0], p->src[1], p->src[2], p->src[3])},
                          {"seq", std::to_string(echo.seq)}});
        }
        return;
    }
    if (!ping_ || echo.id != ping_->id || ping_->psi != psi) {
        return;
    }
    auto it = ping_->outstanding.find(echo.seq);
    if (it == ping_->outstanding.end()) {
        return;
    }
    const Millis rtt = ex_.now() - it->second;
    ping_->outstanding.erase(it);
    ++ping_->received;
    ping_->rtt_sum += rtt;
    ping_->rtt_min = ping_->received == 1 ? rtt : std::min(ping_->rtt_min, rtt);
    ping_->rtt_max = std::max(ping_->rtt_max, rtt);
    events_.emit("ue.ping.reply", subject(),
                 {{"psi", std::to_string(psi)}, {"seq", std::to_string(echo.seq)}, {"rtt_ms", std::to_string(rtt)},
                  {"ttl", std::to_string(p->ttl)}});
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
    out.emplace_back("PDU_SESSIONS", std::to_string(sm_->sessions().size()));
    out.emplace_back("UL_PACKETS", std::to_string(ul_packets_));
    out.emplace_back("DL_PACKETS", std::to_string(dl_packets_));
    return out;
}

} // namespace ksim::node
