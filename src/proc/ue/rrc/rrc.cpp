// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/rrc/rrc.hpp"

#include <algorithm>
#include <utility>

#include "crypto/keys5g.hpp"

namespace ksim::proc::ue {

namespace {

using crypto::keys5g::AlgType;

constexpr std::uint64_t kPart1Mask = (std::uint64_t{1} << 39) - 1;

std::string str(std::int64_t v) { return std::to_string(v); }

template <class... F>
struct Overload : F... {
    using F::operator()...;
};
template <class... F>
Overload(F...) -> Overload<F...>;

} // namespace

const char* rrc_state_name(RrcState s) noexcept {
    switch (s) {
    case RrcState::idle: return "RRC_IDLE";
    case RrcState::connecting: return "RRC_IDLE (setup)";
    case RrcState::connected: return "RRC_CONNECTED";
    }
    return "?";
}

UeRrc::UeRrc(Executor& ex, Rng rng, IEventSink& events, RrcConfig cfg, RrcUpper upper,
             std::function<void(air::Frame)> to_air)
    : ex_(ex), rng_(rng.stream({2})), events_(events), cfg_(std::move(cfg)), upper_(std::move(upper)),
      alive_(std::make_shared<bool>(true)),
      mac_(std::make_unique<entity::UeIdealMac>(ex, rng.stream({1}), cfg_.mac, std::move(to_air))),
      srb0_(std::make_unique<entity::IdealRlc>(0, entity::RlcMode::tm, *mac_)), t300_(cfg_.t300_default) {
    srb0_->set_upper([this](Bytes b) { on_ccch(std::move(b)); });
}

UeRrc::~UeRrc() {
    *alive_ = false;
    if (t300_timer_) {
        ex_.stop_timer(*t300_timer_);
    }
    if (supervision_) {
        ex_.stop_timer(*supervision_);
    }
}

void UeRrc::power(bool on) {
    off_after_setup_ = false;
    radio_on_ = on;
    mac_->mute(!on);
    if (!on) {
        if (state_ != RrcState::idle) {
            go_idle();   // gone without a word: the network finds out by itself
        }
        camped_ = false;
        mib_ok_ = false;
        events_.emit("rrc.power", cfg_.id, {{"on", "0"}});
        return;
    }
    events_.emit("rrc.power", cfg_.id, {{"on", "1"}});
}

void UeRrc::power_off_after_nas() {
    if (pending_nas_) {
        off_after_setup_ = true;
        return;
    }
    power(false);
}

void UeRrc::supervise() {
    supervision_.reset();
    if (state_ != RrcState::connected) {
        return;
    }
    // TS 38.331 §5.3.10 in the ideal link: the cell's downlink gone for `rlf`
    // is a radio link failure; otherwise the KEEPALIVE keeps the DU's view.
    if (ex_.now() - last_dl_ > cfg_.rlf) {
        lost("radio link failure");
        return;
    }
    mac_->keepalive();
    supervision_ = ex_.start_timer(cfg_.keepalive, [this, alive = alive_] {
        if (*alive) {
            supervise();
        }
    });
}

// ---- broadcast and paging (§5.2.2, §5.3.2) ---------------------------------------------------

void UeRrc::on_frame(const air::Frame& f) {
    if (!radio_on_) {
        return;
    }
    if (camped_ && f.cell_handle == cell_) {
        last_dl_ = ex_.now();
    }
    switch (f.type) {
    case air::FrameType::bch:
        on_mib(f);
        return;
    case air::FrameType::si:
        on_sib1(f);
        return;
    case air::FrameType::pcch:
        on_paging(f);
        return;
    default:
        if (camped_ && f.cell_handle == cell_) {
            mac_->on_frame(f);
        }
        return;
    }
}

void UeRrc::on_mib(const air::Frame& f) {
    auto mib = rrc::decode_mib(f.sdus.front().data);
    if (!mib) {
        return;
    }
    if (!mib_ok_ && !mib->barred && cfg_.tap) {
        cfg_.tap("nr-rrc.bcch.bch", f.sdus.front().data);
    }
    if (mib->barred) {
        if (camped_ && f.cell_handle == cell_) {
            camped_ = false;
            events_.emit("rrc.cell_barred", cfg_.id, {{"cell", str(f.cell_handle)}});
        }
        mib_ok_ = false;
        return;
    }
    mib_ok_ = true;
}

void UeRrc::on_sib1(const air::Frame& f) {
    if (!mib_ok_) {
        return;
    }
    auto sib1 = rrc::decode_sib1(f.sdus.front().data);
    if (!sib1) {
        return;
    }
    const auto it = std::find(sib1->plmns.begin(), sib1->plmns.end(), cfg_.plmn);
    if (it == sib1->plmns.end()) {
        return;   // not a suitable cell for the selected PLMN (TS 38.304 §4.5)
    }
    if (camped_ && cell_ == f.cell_handle && tac_ == sib1->tac && nci_ == sib1->cell_identity) {
        return;   // the same SIB1 again
    }
    camped_ = true;
    cell_ = f.cell_handle;
    tac_ = sib1->tac;
    nci_ = sib1->cell_identity;
    plmn_index_ = static_cast<std::uint8_t>(it - sib1->plmns.begin() + 1);
    t300_ = sib1->timers ? sib1->timers->t300 : cfg_.t300_default;
    mac_->camp(cell_);
    if (cfg_.tap) {
        cfg_.tap("nr-rrc.bcch.dl.sch", f.sdus.front().data);
    }
    events_.emit("rrc.camped", cfg_.id,
                 {{"cell", str(cell_)}, {"tac", str(tac_)}, {"nci", str(static_cast<std::int64_t>(nci_))},
                  {"plmn", cfg_.plmn.mcc + cfg_.plmn.mnc}});
    if (upper_.camped) {
        upper_.camped(tac_);
    }
    if (pending_nas_ && state_ == RrcState::idle) {
        establish();
    }
}

void UeRrc::on_paging(const air::Frame& f) {
    auto p = rrc::decode_paging(f.sdus.front().data);
    if (!p || !upper_.s_tmsi) {
        return;
    }
    const auto mine = upper_.s_tmsi();
    if (!mine || std::find(p->s_tmsis.begin(), p->s_tmsis.end(), *mine) == p->s_tmsis.end()) {
        return;
    }
    if (cfg_.tap) {
        cfg_.tap("nr-rrc.pcch", f.sdus.front().data);
    }
    events_.emit("rrc.paging", cfg_.id, {{"state", rrc_state_name(state_)}});
    if (state_ == RrcState::idle && upper_.paged) {
        upper_.paged();
    }
}

// ---- establishment (§5.3.3) -------------------------------------------------------------------

void UeRrc::send_nas(Bytes pdu) {
    switch (state_) {
    case RrcState::connected:
        ul_nas(std::move(pdu));
        return;
    case RrcState::connecting:
        pending_ul_.push_back(std::move(pdu));
        return;
    case RrcState::idle:
        pending_nas_ = std::move(pdu);
        if (camped_) {
            establish();
        }
        return;   // otherwise once a suitable cell is found
    }
}

void UeRrc::establish() {
    state_ = RrcState::connecting;
    rrc::SetupRequest req;
    const std::optional<std::uint64_t> s_tmsi = upper_.s_tmsi ? upper_.s_tmsi() : std::nullopt;
    if (s_tmsi) {
        req.s_tmsi_part1 = true;
        req.identity = *s_tmsi & kPart1Mask;
        s_tmsi_part2_ = static_cast<std::uint16_t>((*s_tmsi >> 39) & 0x1FF);
    } else {
        req.identity = rng_.next() & kPart1Mask;
        s_tmsi_part2_.reset();
    }
    req.cause = rrc::EstablishmentCause::mo_signalling;
    auto wire = rrc::encode(req);
    if (!wire) {
        setup_failed("encode");
        return;
    }
    if (cfg_.tap) {
        cfg_.tap("nr-rrc.ul.ccch", *wire);
    }
    events_.emit("rrc.setup.request", cfg_.id,
                 {{"identity", req.s_tmsi_part1 ? "ng-5G-S-TMSI-Part1" : "randomValue"},
                  {"cause", rrc::cause_name(req.cause)}});
    t300_timer_ = ex_.start_timer(t300_, [this, alive = alive_] {
        if (*alive) {
            t300_timer_.reset();
            setup_failed("T300");
        }
    });
    mac_->start_ra(std::move(*wire), [this, alive = alive_](bool ok) {
        if (*alive && !ok && state_ == RrcState::connecting) {
            setup_failed("random access");
        }
    });
}

void UeRrc::setup_failed(const char* reason) {
    // §5.3.3.7: reset the MAC and tell the upper layers the setup failed.
    events_.emit("rrc.setup.failure", cfg_.id, {{"reason", reason}});
    go_idle();
    if (upper_.released) {
        upper_.released();
    }
    if (std::exchange(off_after_setup_, false)) {
        power(false);
    }
}

void UeRrc::on_ccch(Bytes sdu) {
    if (state_ != RrcState::connecting) {
        return;
    }
    if (cfg_.tap) {
        cfg_.tap("nr-rrc.dl.ccch", sdu);
    }
    auto d = rrc::decode_dl_ccch(sdu);
    if (!d) {
        setup_failed("undecodable DL-CCCH");
        return;
    }
    if (std::holds_alternative<rrc::Reject>(*d)) {
        setup_failed("RRCReject");
        return;
    }
    const auto& setup = std::get<rrc::Setup>(*d);
    if (t300_timer_) {
        ex_.stop_timer(*t300_timer_);
        t300_timer_.reset();
    }
    for (const auto& b : setup.cell_group.bearers) {
        lcids_[{b.srb, b.rb_id}] = Lcid{b.lcid, b.am};
    }
    add_srb(1);
    state_ = RrcState::connected;
    last_dl_ = ex_.now();
    if (!supervision_) {
        supervision_ = ex_.start_timer(cfg_.keepalive, [this, alive = alive_] {
            if (*alive) {
                supervise();
            }
        });
    }
    rrc::SetupComplete c;
    c.tid = setup.tid;
    c.selected_plmn = plmn_index_;
    c.nas = pending_nas_ ? std::move(*pending_nas_) : Bytes{};
    c.s_tmsi_part2 = s_tmsi_part2_;
    pending_nas_.reset();
    events_.emit("rrc.setup.complete", cfg_.id, {{"c_rnti", str(mac_->c_rnti().value_or(0))}});
    send_dcch(rrc::encode(c));
    while (!pending_ul_.empty()) {
        ul_nas(std::move(pending_ul_.front()));
        pending_ul_.pop_front();
    }
    if (std::exchange(off_after_setup_, false)) {
        power(false);   // the switch-off's DEREGISTRATION REQUEST went in RRCSetupComplete
    }
}

// ---- bearers ----------------------------------------------------------------------------------

void UeRrc::add_srb(std::uint8_t id) {
    if (srbs_.count(id) != 0) {
        return;
    }
    const auto lc = lcids_.find({true, id});
    const Lcid l = lc != lcids_.end() ? lc->second : Lcid{id, true};
    Bearer b;
    b.rlc = std::make_unique<entity::IdealRlc>(l.lcid, l.am ? entity::RlcMode::am : entity::RlcMode::um, *mac_);
    entity::PdcpConfig pc;
    pc.srb = true;
    pc.rb_id = id;
    pc.side = entity::PdcpSide::ue;
    entity::IdealRlc* rlc = b.rlc.get();
    b.pdcp = std::make_unique<entity::Pdcp>(
        ex_, pc, [rlc](Bytes p) { rlc->write_sdu(std::move(p)); },
        [this, id](Bytes sdu) { on_dcch(id, std::move(sdu)); });
    entity::Pdcp* pdcp = b.pdcp.get();
    b.pdcp->on_integrity_failure([this, id](std::uint32_t count) {
        events_.emit("rrc.integrity_failure", cfg_.id, {{"bearer", "srb" + str(id)}, {"count", str(count)}});
        // Re-establishment (§5.3.7) is not in P1: the connection is lost (ledger A-13).
        lost("integrity failure");
    });
    b.rlc->set_upper([pdcp](Bytes p) { pdcp->on_pdu(p); });
    srbs_.emplace(id, std::move(b));
}

Result<void> UeRrc::add_drb(const rrc::DrbAdd& d) {
    const auto lc = lcids_.find({false, d.drb_id});
    if (lc == lcids_.end()) {
        return make_error(Errc::invalid_argument, d.drb_id, "RRC: a DRB without a logical channel in the cell group");
    }
    drbs_.erase(d.drb_id);
    Bearer b;
    b.psi = d.pdu_session;
    b.rlc = std::make_unique<entity::IdealRlc>(lc->second.lcid,
                                                lc->second.am ? entity::RlcMode::am : entity::RlcMode::um, *mac_);
    entity::PdcpConfig pc;
    pc.srb = false;
    pc.rb_id = d.drb_id;
    pc.side = entity::PdcpSide::ue;
    pc.sn_tx = d.pdcp.sn18_ul ? pdcp::SnSize::len18 : pdcp::SnSize::len12;
    pc.sn_rx = d.pdcp.sn18_dl ? pdcp::SnSize::len18 : pdcp::SnSize::len12;
    pc.drb_integrity = d.pdcp.integrity;
    pc.sdap_header_tx = d.sdap_header_ul;
    pc.sdap_header_rx = d.sdap_header_dl;
    pc.out_of_order = d.pdcp.out_of_order;
    if (d.pdcp.t_reordering_ms) {
        pc.t_reordering = *d.pdcp.t_reordering_ms;
    }
    entity::IdealRlc* rlc = b.rlc.get();
    const std::uint8_t id = d.drb_id;
    b.pdcp = std::make_unique<entity::Pdcp>(
        ex_, pc, [rlc](Bytes p) { rlc->write_sdu(std::move(p)); }, [this, id](Bytes sdu) { on_drb(id, std::move(sdu)); });
    if (nia_ && nea_) {
        auto keys = b.pdcp->set_keys(*nia_, k_up_int_.clone(), *nea_, k_up_enc_.clone());
        if (!keys) {
            return keys.error();
        }
        b.pdcp->set_integrity(d.pdcp.integrity, d.pdcp.integrity);
        b.pdcp->set_ciphering(true, true);
    }
    entity::Pdcp* pdcp = b.pdcp.get();
    b.rlc->set_upper([pdcp](Bytes p) { pdcp->on_pdu(p); });
    drbs_.emplace(id, std::move(b));
    auto [it, fresh] = sdaps_.try_emplace(d.pdu_session, d.pdu_session);
    (void)fresh;
    it->second.configure(entity::SdapDrb{d.drb_id, d.sdap_header_ul, d.sdap_header_dl, d.default_drb, d.qfis});
    return {};
}

// ---- DCCH (§5.3.4, §5.3.5, §5.3.8, §5.6.1, §5.7) -------------------------------------------------

void UeRrc::send_dcch(Result<Bytes> msg, std::uint8_t srb) {
    if (!msg) {
        events_.emit("rrc.encode_error", cfg_.id, {{"what", msg.error().what}});
        return;
    }
    auto it = srbs_.find(srb);
    if (it == srbs_.end()) {
        it = srbs_.find(1);
    }
    if (it != srbs_.end()) {
        if (cfg_.tap) {
            cfg_.tap("nr-rrc.ul.dcch", *msg);
        }
        it->second.pdcp->write_sdu(std::move(*msg));
    }
}

void UeRrc::ul_nas(Bytes pdu) {
    // §5.7.2: on SRB2 once it is set up, else SRB1.
    send_dcch(rrc::encode(rrc::UlInformationTransfer{std::move(pdu)}), srbs_.count(2) != 0 ? 2 : 1);
}

void UeRrc::on_dcch(std::uint8_t srb, Bytes sdu) {
    if (cfg_.tap) {
        cfg_.tap("nr-rrc.dl.dcch", sdu);
    }
    auto d = rrc::decode_dl_dcch(sdu);
    if (!d) {
        events_.emit("rrc.decode_error", cfg_.id, {{"bearer", "srb" + str(srb)}, {"what", d.error().what}});
        return;
    }
    std::visit(Overload{
                   [this](const rrc::SecurityModeCommand& m) { on_security_mode_command(m); },
                   [this](const rrc::Reconfiguration& m) { on_reconfiguration(m); },
                   [this](const rrc::Release&) {
                       events_.emit("rrc.release", cfg_.id, {});
                       // After this PDCP delivery returns: going idle destroys the bearer.
                       ex_.post([this, alive = alive_] {
                           if (*alive && state_ != RrcState::idle) {
                               go_idle();
                               if (upper_.released) {
                                   upper_.released();
                               }
                           }
                       });
                   },
                   [this](const rrc::CapabilityEnquiry& m) {
                       auto cap = cfg_.nr_capability ? Result<Bytes>(*cfg_.nr_capability) : rrc::generic_nr_capability();
                       if (!cap) {
                           return;
                       }
                       events_.emit("rrc.capability.sent", cfg_.id, {{"octets", str(static_cast<std::int64_t>(cap->size()))}});
                       send_dcch(rrc::encode(rrc::CapabilityInformation{m.tid, std::move(*cap)}));
                   },
                   [this](const rrc::DlInformationTransfer& m) {
                       if (!m.nas.empty() && upper_.nas) {
                           upper_.nas(m.nas);
                       }
                   },
               },
               *d);
}

void UeRrc::on_security_mode_command(const rrc::SecurityModeCommand& m) {
    auto fail = [&](const char* reason) {
        // §5.3.4.3: continue with the configuration used before; the failure
        // goes neither integrity protected nor ciphered.
        events_.emit("rrc.smc.failure", cfg_.id, {{"reason", reason}});
        send_dcch(rrc::encode(rrc::SecurityModeFailure{m.tid}));
    };
    auto srb1 = srbs_.find(1);
    if (srb1 == srbs_.end()) {
        return;
    }
    if (as_security_) {
        fail("AS security is already active");
        return;
    }
    if (m.nia == 3 || m.nea == 3) {
        fail("128-NIA3/NEA3 are a declared gap (KS-SEC-G1)");
        return;
    }
    if (m.nia == 0 && !cfg_.allow_null_integrity) {
        fail("NIA0 outside emergency (TS 33.501 5.3.3)");
        return;
    }
    auto kgnb = upper_.kgnb ? upper_.kgnb() : Result<SecretBytes>(make_error(Errc::invalid_argument, 0, "no NAS"));
    if (!kgnb) {
        fail("no K_gNB");
        return;
    }
    auto rrc_int = crypto::keys5g::algorithm_key(*kgnb, AlgType::rrc_int, m.nia);
    auto rrc_enc = crypto::keys5g::algorithm_key(*kgnb, AlgType::rrc_enc, m.nea);
    auto up_int = crypto::keys5g::algorithm_key(*kgnb, AlgType::up_int, m.nia);
    auto up_enc = crypto::keys5g::algorithm_key(*kgnb, AlgType::up_enc, m.nea);
    if (!rrc_int || !rrc_enc || !up_int || !up_enc) {
        fail("key derivation");
        return;
    }
    const auto nia = static_cast<crypto::Nia>(m.nia);
    const auto nea = static_cast<crypto::Nea>(m.nea);
    entity::Pdcp& pdcp = *srb1->second.pdcp;
    if (!pdcp.set_keys(nia, rrc_int->clone(), nea, rrc_enc->clone())) {
        fail("key length");
        return;
    }
    // The command's own MAC-I, now that its keys are known (TS 38.323 §5.9 NOTE 1).
    auto verified = pdcp.verify_last_unprotected();
    if (!verified || !*verified) {
        fail("integrity check of the SecurityModeCommand");
        return;
    }
    pdcp.set_integrity(true, true);
    nia_ = nia;
    nea_ = nea;
    k_up_int_ = std::move(*up_int);
    k_up_enc_ = std::move(*up_enc);
    as_security_ = true;
    const std::string alg = "nia" + str(m.nia) + "/nea" + str(m.nea);
    events_.emit("rrc.smc.complete", cfg_.id, {{"nia", str(m.nia)}, {"nea", str(m.nea)}, {"alg", alg}});
    send_dcch(rrc::encode(rrc::SecurityModeComplete{m.tid}));   // integrity protected, not ciphered
    pdcp.set_ciphering(true, true);
    // SRBs added later take the same keys (§5.3.5.6.3).
    for (auto& [id, b] : srbs_) {
        if (id != 1) {
            (void)b.pdcp->set_keys(nia, rrc_int->clone(), nea, rrc_enc->clone());
            b.pdcp->set_integrity(true, true);
            b.pdcp->set_ciphering(true, true);
        }
    }
    rrc_keys_int_ = std::move(*rrc_int);
    rrc_keys_enc_ = std::move(*rrc_enc);
}

void UeRrc::on_reconfiguration(const rrc::Reconfiguration& m) {
    if (!as_security_ && (m.bearers || m.cell_group)) {
        // §5.3.5.3: bearers before AS security is active: go to RRC_IDLE, cause "other".
        lost("RRCReconfiguration before AS security");
        return;
    }
    if (m.cell_group) {
        for (std::uint8_t lcid : m.cell_group->release_lcids) {
            for (auto it = lcids_.begin(); it != lcids_.end();) {
                it = it->second.lcid == lcid ? lcids_.erase(it) : std::next(it);
            }
        }
        for (const auto& b : m.cell_group->bearers) {
            lcids_[{b.srb, b.rb_id}] = Lcid{b.lcid, b.am};
        }
    }
    std::string added;
    if (m.bearers) {
        for (std::uint8_t id : m.bearers->drb_release) {
            auto it = drbs_.find(id);
            if (it != drbs_.end()) {
                if (auto s = sdaps_.find(it->second.psi); s != sdaps_.end()) {
                    s->second.release(id);
                }
                drbs_.erase(it);
            }
        }
        for (const auto& s : m.bearers->srbs) {
            if (s.srb_id == 2 && nia_ && nea_) {
                const crypto::Nia nia = *nia_;
                const crypto::Nea nea = *nea_;
                add_srb(2);
                auto& p = *srbs_.at(2).pdcp;
                (void)p.set_keys(nia, rrc_keys_int_.clone(), nea, rrc_keys_enc_.clone());
                p.set_integrity(true, true);
                p.set_ciphering(true, true);
                added += "srb2 ";
            }
        }
        for (const auto& d : m.bearers->drbs) {
            auto ok = add_drb(d);
            if (!ok) {
                events_.emit("rrc.reconfiguration.failure", cfg_.id, {{"what", ok.error().what}});
                lost("RRCReconfiguration the UE cannot comply with");
                return;
            }
            added += "drb" + str(d.drb_id) + " ";
        }
    }
    events_.emit("rrc.reconfiguration.complete", cfg_.id,
                 {{"added", added.empty() ? "" : added.substr(0, added.size() - 1)},
                  {"nas", str(static_cast<std::int64_t>(m.nas.size()))}});
    send_dcch(rrc::encode(rrc::ReconfigurationComplete{m.tid}));
    // The NAS messages go up after the RRCReconfigurationComplete is out.
    for (const Bytes& nas : m.nas) {
        ex_.post([this, alive = alive_, nas] {
            if (*alive && upper_.nas) {
                upper_.nas(nas);
            }
        });
    }
    if (m.bearers && !m.bearers->drbs.empty() && upper_.bearers_up) {
        // After the NAS: data held for a service request goes once the DRBs are there.
        ex_.post([this, alive = alive_] {
            if (*alive && upper_.bearers_up) {
                upper_.bearers_up();
            }
        });
    }
}

// ---- user plane --------------------------------------------------------------------------------

Result<void> UeRrc::send_data(std::uint8_t psi, std::uint8_t qfi, Bytes ip) {
    auto s = sdaps_.find(psi);
    if (s == sdaps_.end()) {
        return make_error(Errc::invalid_argument, psi, "RRC: no DRB for this PDU session");
    }
    auto ul = s->second.map_ul(qfi, std::move(ip));
    if (!ul) {
        return make_error(Errc::invalid_argument, qfi, "RRC: the QoS flow maps to no DRB");
    }
    auto d = drbs_.find(ul->drb_id);
    if (d == drbs_.end()) {
        return make_error(Errc::internal, ul->drb_id, "RRC: SDAP names a DRB that is gone");
    }
    d->second.pdcp->write_sdu(std::move(ul->pdu));
    return {};
}

void UeRrc::on_drb(std::uint8_t drb, Bytes sdu) {
    auto d = drbs_.find(drb);
    if (d == drbs_.end()) {
        return;
    }
    auto s = sdaps_.find(d->second.psi);
    if (s == sdaps_.end()) {
        return;
    }
    auto dl = s->second.on_dl(drb, std::move(sdu));
    if (dl && upper_.dl_data) {
        upper_.dl_data(d->second.psi, dl->header, std::move(dl->sdu));
    }
}

// ---- going idle --------------------------------------------------------------------------------

void UeRrc::release_local() { go_idle(); }

void UeRrc::lost(const char* why) {
    events_.emit("rrc.connection_lost", cfg_.id, {{"reason", why}});
    // Called from a PDCP delivery: the bearers go once it has returned.
    ex_.post([this, alive = alive_] {
        if (*alive && state_ != RrcState::idle) {
            // §5.3.11: no re-establishment in P1, so the failure goes up as such.
            std::uint16_t up = 0;
            for (const auto& [id, b] : drbs_) {
                up = static_cast<std::uint16_t>(up | (1U << (b.psi & 0x0FU)));
            }
            go_idle();
            if (upper_.connection_failure) {
                upper_.connection_failure(up);
            }
            if (upper_.released) {
                upper_.released();
            }
        }
    });
}

void UeRrc::go_idle() {
    if (t300_timer_) {
        ex_.stop_timer(*t300_timer_);
        t300_timer_.reset();
    }
    if (supervision_) {
        ex_.stop_timer(*supervision_);
        supervision_.reset();
    }
    drbs_.clear();
    srbs_.clear();
    sdaps_.clear();
    lcids_.clear();
    mac_->reset();
    as_security_ = false;
    nia_.reset();
    nea_.reset();
    k_up_int_ = SecretBytes{};
    k_up_enc_ = SecretBytes{};
    rrc_keys_int_ = SecretBytes{};
    rrc_keys_enc_ = SecretBytes{};
    state_ = RrcState::idle;
    pending_nas_.reset();
    pending_ul_.clear();
    s_tmsi_part2_.reset();
}

// ---- read side -----------------------------------------------------------------------------------

const entity::Pdcp* UeRrc::srb(std::uint8_t id) const {
    auto it = srbs_.find(id);
    return it != srbs_.end() ? it->second.pdcp.get() : nullptr;
}

const entity::Pdcp* UeRrc::drb(std::uint8_t id) const {
    auto it = drbs_.find(id);
    return it != drbs_.end() ? it->second.pdcp.get() : nullptr;
}

std::vector<std::uint8_t> UeRrc::drbs() const {
    std::vector<std::uint8_t> out;
    out.reserve(drbs_.size());
    for (const auto& [id, b] : drbs_) {
        out.push_back(id);
    }
    return out;
}

} // namespace ksim::proc::ue
