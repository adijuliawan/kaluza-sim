// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ran/du.hpp"

#include <utility>

#include "codec/asn1/msg/ngap.hpp"
#include "platform/mutation.hpp"

namespace ksim::proc::ran {

namespace {

std::string str(std::int64_t v) { return std::to_string(v); }

constexpr std::uint8_t kDuF1uTag = 0x21;   // TEIDs of the DU's F1-U ends

/// TS 38.321 Table 6.2.1-1: LCIDs 4..32 for DRBs here, DRB n on LCID 3 + n.
constexpr std::uint8_t lcid_of_drb(std::uint8_t drb) noexcept { return static_cast<std::uint8_t>(3 + drb); }

template <class... F>
struct Overload : F... {
    using F::operator()...;
};
template <class... F>
Overload(F...) -> Overload<F...>;

Millis wait_of(const std::optional<std::string>& t) {
    if (!t || t->size() < 3) {
        return 5'000;
    }
    return static_cast<Millis>(std::stoi(t->substr(1, t->size() - 2))) * 1'000;   // "v10s" -> 10 s
}

} // namespace

Du::Du(Executor& ex, IEventSink& events, DuConfig cfg, IAssoc& f1, std::function<void(air::Frame)> to_air, IDatagram* f1u)
    : ex_(ex), events_(events), cfg_(std::move(cfg)), f1_(f1), to_air_(std::move(to_air)),
      alive_(std::make_shared<bool>(true)) {
    f1_.set_handlers(
        [this](ByteView msg, SctpMeta m) {
            if (m.ppid != kF1apPpid && m.ppid != 0) {   // 0: memlink in tests carries none
                ++stats_.wrong_ppid;
                events_.emit("ran.link.wrong_ppid", cfg_.id, {{"link", "f1ap"}, {"ppid", std::to_string(m.ppid)}});
                return;
            }
            on_f1(msg);
        },
        [this](LinkEvent e) { on_f1_event(e); });
    if (f1u != nullptr) {
        f1u_ = std::make_unique<entity::gtpu::Endpoint>(*f1u, kDuF1uTag);
        f1u_->on_error_indication([this](std::uint32_t teid, const ksim::Endpoint& from) {
            events_.emit("ran.gtpu.error_indication", cfg_.id, {{"direction", "rx"}, {"teid", str(teid)}, {"from", from.to_string()}});
        });
    }
}

Du::~Du() {
    *alive_ = false;
    for (auto* t : {&setup_retry_, &mib_timer_, &sib1_timer_, &supervision_}) {
        if (*t) {
            ex_.stop_timer(**t);
        }
    }
}

void Du::supervise() {
    supervision_ = ex_.start_timer(cfg_.supervision, [this, alive = alive_] {
        if (!*alive) {
            return;
        }
        // TS 38.473 8.3.2: a UE the DU no longer hears from (radio link failure)
        // is reported in UE CONTEXT RELEASE REQUEST, once.
        for (auto& [id, ue] : ues_) {
            if (!ue.cu_ue || ue.lost || ex_.now() - ue.last_ul <= cfg_.rlf) {
                continue;
            }
            ue.lost = true;
            ++stats_.rlf;
            events_.emit("ran.du.rlf", cfg_.id, {{"du_ue", str(id)}, {"rnti", str(ue.rnti)}, {"reason", "no uplink"}});
            if (!KSIM_MUTANT("no_release_on_radio_loss")) {
                send_f1(f1ap::UeContextReleaseRequest{*ue.cu_ue, ue.du_ue, f1ap::Cause{"radioNetwork", "rl-failure-others"}},
                        true);
            }
        }
        supervise();
    });
}

void Du::cell_power(bool on) {
    if (on == powered_) {
        return;
    }
    powered_ = on;
    if (on) {
        events_.emit("ran.du.cell_on", cfg_.id, {{"cell", str(cfg_.cell_handle)}, {"active", active_ ? "1" : "0"}});
        if (active_) {
            broadcast();
            schedule_si(cfg_.mib_period, true);
            schedule_si(cfg_.sib1_period, false);
        }
        return;
    }
    for (auto* t : {&mib_timer_, &sib1_timer_}) {
        if (*t) {
            ex_.stop_timer(**t);
            t->reset();
        }
    }
    // KS-L2R-005: its UEs have lost the cell; the DU asks for each one's release (TS 38.473 8.3.2).
    std::int64_t released = 0;
    for (auto& [id, ue] : ues_) {
        if (!ue.cu_ue || ue.lost) {
            continue;
        }
        ue.lost = true;
        ++stats_.rlf;
        ++released;
        send_f1(f1ap::UeContextReleaseRequest{*ue.cu_ue, ue.du_ue, f1ap::Cause{"radioNetwork", "cell-not-available"}}, true);
    }
    events_.emit("ran.du.cell_off", cfg_.id, {{"cell", str(cfg_.cell_handle)}, {"released", str(released)}});
}

void Du::radio_link_failure(std::uint16_t rnti, const char* why) {
    auto r = by_rnti_.find(rnti);
    Ue* ue = r != by_rnti_.end() ? by_du(r->second) : nullptr;
    if (ue == nullptr || !ue->cu_ue || ue->lost) {
        return;
    }
    ue->lost = true;
    ++stats_.rlf;
    events_.emit("ran.du.rlf", cfg_.id, {{"du_ue", str(ue->du_ue)}, {"rnti", str(ue->rnti)}, {"reason", why}});
    send_f1(f1ap::UeContextReleaseRequest{*ue->cu_ue, ue->du_ue, f1ap::Cause{"radioNetwork", "rl-failure-rlc"}}, true);
}

f1ap::NrCgi Du::cgi() const { return {ngap::plmn_id(cfg_.plmn.mcc, cfg_.plmn.mnc), cfg_.nci}; }

std::uint16_t Du::sfn() const noexcept {
    const std::int64_t ms = cfg_.sfn_clock_ms ? cfg_.sfn_clock_ms() : static_cast<std::int64_t>(ex_.now());
    return static_cast<std::uint16_t>((ms / 10) % 1024);
}

air::Frame Du::frame(air::FrameType t, std::uint32_t radio_id) const {
    air::Frame f;
    f.type = t;
    f.cell_handle = cfg_.cell_handle;
    f.radio_id = radio_id;
    const std::int64_t now = cfg_.sfn_clock_ms ? cfg_.sfn_clock_ms() : static_cast<std::int64_t>(ex_.now());
    f.tx_time_ns = static_cast<std::uint64_t>(now) * 1'000'000;
    f.sfn_slot = static_cast<std::uint32_t>(sfn()) << 8 | static_cast<std::uint32_t>((now % 10) * 2);
    return f;
}

// ---- F1 ----------------------------------------------------------------------------------

void Du::on_f1_event(LinkEvent e) {
    if (e == LinkEvent::up || e == LinkEvent::restart) {
        if (KSIM_MUTANT("f1_no_reassociation") && f1_ups_ > 0) {
            return;   // the mutant: no F1 Setup on a new association (row ksim-p2.f1-reassociation)
        }
        ++f1_ups_;
        f1_setup();
        return;
    }
    // The association is gone: the cell goes down and so do its UEs.
    active_ = false;
    for (auto* t : {&mib_timer_, &sib1_timer_, &supervision_}) {
        if (*t) {
            ex_.stop_timer(**t);
            t->reset();
        }
    }
    for (auto& [id, ue] : ues_) {
        drop_drbs(ue);
    }
    ues_.clear();
    by_rnti_.clear();
    ra_.clear();
}

void Du::send_f1(const f1ap::Pdu& p, bool ue_associated) {
    auto wire = f1ap::encode(p);
    if (!wire) {
        ++stats_.f1_errors;
        events_.emit("ran.encode_error", cfg_.id, {{"what", wire.error().what}});
        return;
    }
    const auto ue = ue_associated ? f1ap::du_ue_of(p) : std::nullopt;
    const std::uint16_t stream = ue && !KSIM_MUTANT("single_ue_stream") ? ue_stream(f1_.out_streams(), *ue)
                                 : (ue_associated && f1_.out_streams() > 1 ? std::uint16_t{1} : std::uint16_t{0});
    (void)f1_.send(*wire, SctpMeta{kF1apPpid, stream});
}

void Du::f1_setup() {
    rrc::Sib1 sib1;
    sib1.plmns = {cfg_.plmn};
    sib1.tac = cfg_.tac;
    sib1.cell_identity = cfg_.nci;
    sib1.timers = cfg_.timers;
    auto mib = rrc::mib_ie(rrc::Mib{});
    auto sib = rrc::sib1_ie(sib1);
    rrc::SsbTiming ssb;
    ssb.ssb_arfcn = cfg_.ssb_arfcn;
    ssb.pci = cfg_.pci;
    auto mtc = rrc::measurement_timing_configuration(ssb);
    auto sib_frame = rrc::encode(sib1);
    if (!mib || !sib || !mtc || !sib_frame) {
        events_.emit("ran.encode_error", cfg_.id, {{"what", "the cell's system information"}});
        return;
    }
    sib1_frame_ = std::move(*sib_frame);
    f1ap::ServedCell cell;
    cell.cgi = cgi();
    cell.pci = cfg_.pci;
    cell.tac = cfg_.tac;
    cell.plmns = {cgi().plmn};
    cell.arfcn = cfg_.arfcn;
    cell.meas_timing = std::move(*mtc);
    cell.mib = std::move(*mib);
    cell.sib1 = std::move(*sib);
    transaction_ = static_cast<std::uint8_t>(transaction_ + 1);
    send_f1(f1ap::F1SetupRequest{transaction_, cfg_.du_id, cfg_.name, {cell}}, false);
}

void Du::on_f1(ByteView msg) {
    auto p = f1ap::decode(msg);
    if (!p) {
        ++stats_.f1_errors;
        auto h = f1ap::peek(msg);
        events_.emit("ran.f1.error", cfg_.id, {{"what", p.error().what}});
        if (h && h->reject) {
            f1ap::ErrorIndication e;
            e.cu_ue = h->cu_ue;
            e.du_ue = h->du_ue;
            e.cause = f1ap::Cause{"protocol", "abstract-syntax-error-reject"};
            send_f1(e, h->du_ue.has_value());
        }
        return;
    }
    std::visit(Overload{
                   [this](const f1ap::F1SetupResponse& m) { handle(m); },
                   [this](const f1ap::F1SetupFailure& m) { handle(m); },
                   [this](const f1ap::DlRrcMessageTransfer& m) { handle(m); },
                   [this](const f1ap::UeContextSetupRequest& m) { handle(m); },
                   [this](const f1ap::UeContextModificationRequest& m) { handle(m); },
                   [this](const f1ap::UeContextReleaseCommand& m) { handle(m); },
                   [this](const f1ap::Paging& m) { handle(m); },
                   [this](const f1ap::GnbCuConfigurationUpdate& m) { handle(m); },
                   [this](const f1ap::ErrorIndication& m) {
                       events_.emit("ran.f1.error_indication", cfg_.id,
                                    {{"cause", m.cause ? m.cause->group + "/" + m.cause->value : ""}});
                   },
                   [this](const auto&) { ++stats_.f1_errors; },
               },
               *p);
}

void Du::handle(const f1ap::F1SetupResponse& m) {
    if (m.transaction != transaction_) {
        return;
    }
    if (setup_retry_) {
        ex_.stop_timer(*setup_retry_);
        setup_retry_.reset();
    }
    active_ = false;   // a new F1: the cell is on air only if this setup activates it
    set_active(std::find(m.activate.begin(), m.activate.end(), cgi()) != m.activate.end());
    events_.emit("ran.f1.setup", cfg_.id, {{"cu", m.cu_name}, {"cell_active", active_ ? "1" : "0"}});
}

void Du::set_active(bool on) {
    if (on == active_) {
        return;
    }
    active_ = on;
    if (on && powered_) {
        broadcast();
        schedule_si(cfg_.mib_period, true);
        schedule_si(cfg_.sib1_period, false);
        if (!supervision_) {
            supervise();
        }
        return;
    }
    for (auto* t : {&mib_timer_, &sib1_timer_}) {   // off the air: no MIB, no SIB1, no paging
        if (*t) {
            ex_.stop_timer(**t);
            t->reset();
        }
    }
}

// TS 38.473 8.2.5.2 (P2 Q4): the cells to be activated go on air, those to be deactivated
// off; a cell that is not this DU's cannot be activated and is listed as failed.
void Du::handle(const f1ap::GnbCuConfigurationUpdate& m) {
    f1ap::GnbCuConfigurationUpdateAcknowledge a;
    a.transaction = m.transaction;
    for (const auto& c : m.activate) {
        if (c == cgi()) {
            set_active(true);
        } else {
            a.failed.push_back(f1ap::CellFailed{c, f1ap::Cause{"radioNetwork", "cell-not-available"}});
        }
    }
    for (const auto& c : m.deactivate) {
        if (c == cgi()) {
            set_active(false);
        }
    }
    events_.emit("ran.f1.cu_config_update", cfg_.id,
                 {{"activate", str(static_cast<std::int64_t>(m.activate.size()))},
                  {"deactivate", str(static_cast<std::int64_t>(m.deactivate.size()))},
                  {"failed", str(static_cast<std::int64_t>(a.failed.size()))}, {"cell_active", active_ ? "1" : "0"}});
    send_f1(a, false);
}

void Du::handle(const f1ap::F1SetupFailure& m) {
    const Millis wait = wait_of(m.time_to_wait);
    events_.emit("ran.f1.setup.failure", cfg_.id,
                 {{"cause", m.cause.group + "/" + m.cause.value}, {"retry_ms", str(wait)}});
    setup_retry_ = ex_.start_timer(wait, [this, alive = alive_] {
        if (*alive) {
            setup_retry_.reset();
            f1_setup();
        }
    });
}

// ---- broadcast and paging ------------------------------------------------------------------

void Du::send_mib() {
    rrc::Mib mib;
    mib.sfn = sfn();
    if (auto wire = rrc::encode(mib)) {
        air::Frame b = frame(air::FrameType::bch, 0);
        b.sdus.push_back({0, air::RlcMode::tm, std::move(*wire)});
        b.seq = seq_++;
        ++stats_.si_tx;
        air_out(std::move(b));
    }
}

void Du::send_sib1() {
    air::Frame si = frame(air::FrameType::si, 0);
    si.sdus.push_back({0, air::RlcMode::tm, sib1_frame_});
    si.seq = seq_++;
    ++stats_.si_tx;
    air_out(std::move(si));
}

void Du::send_announce() {
    // P3 R2 (ADR 0011 point 2, made true): the cell's identity and carrier, so a farm knows
    // the cells before their system information.
    air::Frame a = frame(air::FrameType::cell_announce, 0);
    const auto p = ngap::plmn_id(cfg_.plmn.mcc, cfg_.plmn.mnc);
    a.cell = air::CellInfo{cfg_.nci, cfg_.pci, cfg_.ssb_arfcn, {p[0], p[1], p[2]}, cfg_.tac};
    a.seq = seq_++;
    ++stats_.announces;
    air_out(std::move(a));
}

void Du::broadcast() {
    if (on_air()) {
        send_announce();
        send_mib();
        send_sib1();
    }
}

void Du::schedule_si(Millis period, bool mib) {
    auto& timer = mib ? mib_timer_ : sib1_timer_;
    timer = ex_.start_timer(period, [this, period, mib, alive = alive_] {
        if (!*alive || !on_air()) {
            return;
        }
        if (mib) {
            mib_timer_.reset();
            send_mib();
        } else {
            sib1_timer_.reset();
            send_announce();
            send_sib1();
        }
        schedule_si(period, mib);
    });
}

void Du::handle(const f1ap::Paging& m) {
    if (!on_air() || std::find(m.cells.begin(), m.cells.end(), cgi()) == m.cells.end()) {
        return;
    }
    auto pcch = rrc::encode(rrc::Paging{{m.s_tmsi}});
    if (!pcch) {
        return;
    }
    // TS 38.304 §7.1 with T = 128, N = T, Ns = 1: PF where SFN mod T = UE_ID mod N; i_s 0.
    const std::uint16_t now = sfn();
    const std::uint16_t pf = static_cast<std::uint16_t>(m.ue_identity_index % 128);
    const auto ahead = static_cast<std::uint16_t>((pf - (now % 128) + 128) % 128);
    air::Frame p = frame(air::FrameType::pcch, 0);
    p.paging = air::PagingStamp{static_cast<std::uint16_t>((now + ahead) % 1024), 0, false};
    p.sdus.push_back({0, air::RlcMode::tm, std::move(*pcch)});
    p.seq = seq_++;
    events_.emit("ran.du.paging", cfg_.id, {{"pf", str(p.paging->pf_sfn)}});
    air_out(std::move(p));
}

// ---- MAC: random access and SDUs -------------------------------------------------------------

void Du::on_frame(const air::Frame& f) {
    if (!on_air() || f.cell_handle != cfg_.cell_handle) {
        return;
    }
    switch (f.type) {
    case air::FrameType::prach:
        on_prach(f);
        return;
    case air::FrameType::msg3:
        on_msg3(f);
        return;
    case air::FrameType::ul_sdu:
        on_ul_sdu(f);
        return;
    case air::FrameType::keepalive:
        if (auto r = by_rnti_.find(f.rnti); r != by_rnti_.end()) {
            if (Ue* ue = by_du(r->second)) {
                ue->last_ul = ex_.now();
            }
        }
        return;
    default:
        return;
    }
}

void Du::on_prach(const air::Frame& f) {
    if (!f.prach) {
        return;
    }
    ++stats_.prach;
    const air::Prach& p = *f.prach;
    const std::uint32_t key = static_cast<std::uint32_t>(p.ra_rnti()) << 8 | p.preamble;
    const Millis now = ex_.now();
    auto it = ra_.find(key);
    if (it == ra_.end() || now - it->second.at > 10) {
        while (by_rnti_.count(next_rnti_) != 0 || next_rnti_ < 0x4601 || next_rnti_ > 0xFFEF) {
            next_rnti_ = next_rnti_ < 0x4601 || next_rnti_ > 0xFFEF ? std::uint16_t{0x4601}
                                                                    : static_cast<std::uint16_t>(next_rnti_ + 1);
        }
        it = ra_.insert_or_assign(key, Ra{next_rnti_++, now}).first;
    }
    air::Frame r = frame(air::FrameType::rar, f.radio_id);
    r.rnti = p.ra_rnti();
    r.rar = air::Rar{p.preamble, it->second.tc_rnti, 0, 0};
    r.seq = seq_++;
    ++stats_.rar;
    air_out(std::move(r));
}

Result<Bytes> Du::cell_group(const std::set<std::uint8_t>& srbs, const std::vector<Ue::Drb>& drbs,
                              const std::vector<std::uint8_t>& release_lcids) const {
    rrc::CellGroup cg;
    for (std::uint8_t s : srbs) {
        cg.bearers.push_back(rrc::RlcBearer{s, true, s, true});
    }
    for (const auto& d : drbs) {
        cg.bearers.push_back(rrc::RlcBearer{d.lcid, false, d.id, true});
    }
    cg.release_lcids = release_lcids;
    return rrc::encode(cg);
}

std::vector<f1ap::DrbSetup> Du::drbs_change(Ue& ue, const std::vector<f1ap::DrbToSetup>& add,
                                            const std::vector<std::uint8_t>& release, std::vector<Ue::Drb>& added,
                                            std::vector<std::uint8_t>& released_lcids) {
    for (std::uint8_t id : release) {
        auto it = ue.drbs.find(id);
        if (it == ue.drbs.end()) {
            continue;
        }
        if (f1u_) {
            f1u_->unbind(it->second.dl_teid);
        }
        released_lcids.push_back(it->second.lcid);
        ue.drbs.erase(it);
    }
    std::vector<f1ap::DrbSetup> out;
    if (!f1u_) {
        return out;   // no F1-U here: the DRBs are not set up
    }
    for (const auto& d : add) {
        if (d.drb_id < 1 || d.drb_id > 29) {
            continue;
        }
        if (auto old = ue.drbs.find(d.drb_id); old != ue.drbs.end()) {
            f1u_->unbind(old->second.dl_teid);
            ue.drbs.erase(old);
        }
        Ue::Drb drb;
        drb.id = d.drb_id;
        drb.lcid = lcid_of_drb(d.drb_id);
        drb.ul = d.ul;
        drb.sn_bits = d.dl_pdcp_sn_bits;
        for (const auto& f : d.flows) {
            drb.qfis.push_back(f.qfi);
            if (f.gbr) {
                drb.gfbr_dl += f.gbr->gfbr_dl;   // P2 Q11
                drb.gfbr_ul += f.gbr->gfbr_ul;
            }
        }
        const std::uint32_t du_ue = ue.du_ue;
        const std::uint8_t drb_id = drb.id;
        drb.dl_teid = f1u_->bind([this, alive = alive_, du_ue, drb_id](const entity::gtpu::UserData& u, const ksim::Endpoint&) {
            if (*alive && !u.end_marker) {   // F1-U carries none (TS 38.425); a stray one is dropped
                on_dl_user(du_ue, drb_id, u);
            }
        });
        out.push_back(f1ap::DrbSetup{drb.id, drb.lcid, f1ap::GtpTunnel{cfg_.f1u_addr, drb.dl_teid}});
        added.push_back(drb);
        ue.drbs.emplace(drb.id, drb);
        // The initial DL DATA DELIVERY STATUS (TS 38.425 5.4.2.1, "as soon as the
        // corresponding node detects the successful RACH access by the UE"): the UE
        // is on the cell already, so now. A CU-UP may hold DL data until it has a
        // buffer size (OCUDU's does), and the core sends its buffered DL data the
        // moment the session's tunnel is up, so a later report would lose it.
        send_ddds(ue.drbs.at(drb_id), std::nullopt);
    }
    return out;
}

namespace {

// A PDCP data PDU's SN (TS 38.323 6.2.2.2, 6.2.2.3): D/C 1, then 12 or 18 bits.
std::optional<std::uint32_t> pdcp_sn(ByteView pdu, std::uint8_t bits) {
    if (pdu.empty() || (pdu[0] & 0x80U) == 0) {
        return std::nullopt;   // a control PDU
    }
    if (bits == 12) {
        if (pdu.size() < 2) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(((pdu[0] & 0x0FU) << 8) | pdu[1]);
    }
    if (pdu.size() < 3) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(((pdu[0] & 0x03U) << 16) | (static_cast<std::uint32_t>(pdu[1]) << 8) | pdu[2]);
}

} // namespace

void Du::on_dl_user(std::uint32_t du_ue, std::uint8_t drb_id, const entity::gtpu::UserData& u) {
    Ue* ue = by_du(du_ue);
    if (ue == nullptr) {
        return;
    }
    auto it = ue->drbs.find(drb_id);
    if (it == ue->drbs.end()) {
        return;
    }
    Ue::Drb& d = it->second;
    ++stats_.dl_user;
    if (const auto sn = pdcp_sn(u.payload, d.sn_bits)) {
        d.highest_sn = sn;   // the ideal link keeps F1-U's order
    }
    dl_sdu(*ue, d.lcid, u.payload);
    if (u.report_polling) {
        send_ddds(d, u.nru_sn);   // TS 38.425 5.4.2.1: polled, the report goes now
        return;
    }
    arm_ddds(du_ue, drb_id);
}

void Du::arm_ddds(std::uint32_t du_ue, std::uint8_t drb_id) {
    Ue* ue = by_du(du_ue);
    if (ue == nullptr || ue->drbs.count(drb_id) == 0 || ue->drbs.at(drb_id).report_due) {
        return;
    }
    ue->drbs.at(drb_id).report_due = true;
    ex_.start_timer(cfg_.ddds_delay, [this, alive = alive_, du_ue, drb_id] {
        if (!*alive) {
            return;
        }
        if (Ue* u = by_du(du_ue); u != nullptr && u->drbs.count(drb_id) != 0) {
            send_ddds(u->drbs.at(drb_id), std::nullopt);
        }
    });
}

void Du::send_ddds(Ue::Drb& d, std::optional<std::uint32_t> polling_nru_sn) {
    d.report_due = false;
    if (!f1u_ || KSIM_MUTANT("no_ddds")) {
        return;   // the mutant: no feedback, so OCUDU's CU-UP sends no DL data (row ksim-p2.ocudu-ddds)
    }
    entity::gtpu::DeliveryStatus s;
    s.desired_buffer = cfg_.ddds_buffer;
    // RLC AM over the ideal link: a PDU sent to the UE arrives, in sequence.
    s.highest_delivered = d.highest_sn;
    s.highest_transmitted = d.highest_sn;
    s.polling_nru_sn = polling_nru_sn;
    entity::gtpu::UserData g;
    g.teid = d.ul.teid;
    g.ddds = s;
    const auto& a = d.ul.addr;
    ++stats_.ddds_tx;
    (void)f1u_->send(ksim::Endpoint::v4(a[0], a[1], a[2], a[3], cfg_.gtpu_port), g);
}

void Du::drop_drbs(Ue& ue) {
    if (f1u_) {
        for (const auto& [id, d] : ue.drbs) {
            f1u_->unbind(d.dl_teid);
        }
    }
    ue.drbs.clear();
}

void Du::on_msg3(const air::Frame& f) {
    if (by_rnti_.count(f.rnti) != 0) {
        ++stats_.msg3_lost_contention;   // another UE's Msg3 for this TC-RNTI came first
        return;
    }
    const air::Sdu& ccch = f.sdus.front();
    if (ccch.lcid != 0) {
        return;   // a C-RNTI Msg3 (resume, re-establishment) is not in P1
    }
    Ue ue;
    ue.du_ue = next_du_ue_++;
    ue.rnti = f.rnti;
    ue.radio_id = f.radio_id;
    ue.contention = air::contention_id_of(ccch.data);
    ue.last_ul = ex_.now();
    auto cg = cell_group({1});
    if (!cg) {
        return;
    }
    by_rnti_[ue.rnti] = ue.du_ue;
    ues_.emplace(ue.du_ue, ue);
    send_f1(f1ap::InitialUlRrcMessageTransfer{ue.du_ue, cgi(), ue.rnti, ccch.data, std::move(*cg), 0}, true);
}

void Du::on_ul_sdu(const air::Frame& f) {
    auto r = by_rnti_.find(f.rnti);
    if (r == by_rnti_.end()) {
        return;
    }
    Ue* ue = by_du(r->second);
    if (ue == nullptr || !ue->cu_ue) {
        return;
    }
    ue->last_ul = ex_.now();
    for (const air::Sdu& s : f.sdus) {
        ++stats_.ul_sdus;
        if (ue->srbs.count(s.lcid) != 0) {
            send_f1(f1ap::UlRrcMessageTransfer{*ue->cu_ue, ue->du_ue, s.lcid, s.data}, true);
            continue;
        }
        for (const auto& [id, d] : ue->drbs) {
            if (d.lcid == s.lcid && f1u_) {
                ++stats_.ul_user;
                const auto& a = d.ul.addr;
                (void)f1u_->send(ksim::Endpoint::v4(a[0], a[1], a[2], a[3], cfg_.gtpu_port),
                                 entity::gtpu::UserData::plain(d.ul.teid, s.data));
            }
        }
    }
}

void Du::dl_sdu(const Ue& ue, std::uint8_t lcid, Bytes sdu) {
    air::Frame d = frame(air::FrameType::dl_sdu, ue.radio_id);
    d.rnti = ue.rnti;
    d.sdus.push_back({lcid, lcid == 0 ? air::RlcMode::tm : air::RlcMode::am, std::move(sdu)});
    d.seq = seq_++;
    ++stats_.dl_sdus;
    air_out(std::move(d));
}

Du::Ue* Du::by_du(std::uint32_t id) {
    auto it = ues_.find(id);
    return it != ues_.end() ? &it->second : nullptr;
}

// ---- UE-associated F1 ----------------------------------------------------------------------

void Du::handle(const f1ap::DlRrcMessageTransfer& m) {
    Ue* ue = by_du(m.du_ue);
    if (ue == nullptr) {
        ++stats_.f1_errors;
        send_f1(f1ap::ErrorIndication{0, m.cu_ue, m.du_ue, f1ap::Cause{"radioNetwork", "unknown-or-already-allocated-gnb-du-ue-f1ap-id"}},
                true);
        return;
    }
    ue->cu_ue = m.cu_ue;
    if (m.srb == 0 && ue->contention) {
        air::Frame m4 = frame(air::FrameType::msg4, ue->radio_id);
        m4.rnti = ue->rnti;
        m4.contention_id = *ue->contention;
        m4.sdus.push_back({0, air::RlcMode::tm, m.rrc});
        m4.seq = seq_++;
        ue->contention.reset();
        ++stats_.dl_sdus;
        air_out(std::move(m4));
        return;
    }
    dl_sdu(*ue, m.srb, m.rrc);
}

void Du::handle(const f1ap::UeContextSetupRequest& m) {
    Ue* ue = m.du_ue ? by_du(*m.du_ue) : nullptr;
    if (ue == nullptr) {
        send_f1(f1ap::UeContextSetupFailure{m.cu_ue, m.du_ue, f1ap::Cause{"radioNetwork", "unknown-or-already-allocated-gnb-du-ue-f1ap-id"}},
                true);
        return;
    }
    ue->cu_ue = m.cu_ue;
    std::set<std::uint8_t> added(m.srbs.begin(), m.srbs.end());
    added.erase(0);
    ue->srbs.insert(added.begin(), added.end());
    std::vector<Ue::Drb> new_drbs;
    std::vector<std::uint8_t> released;
    auto drbs = drbs_change(*ue, m.drbs, {}, new_drbs, released);
    auto cg = cell_group(added, new_drbs);
    if (!cg) {
        send_f1(f1ap::UeContextSetupFailure{m.cu_ue, ue->du_ue, f1ap::Cause{"misc", "unspecified"}}, true);
        return;
    }
    std::vector<std::pair<std::uint8_t, std::uint8_t>> setup;
    setup.reserve(added.size());
    for (std::uint8_t s : added) {
        setup.emplace_back(s, s);
    }
    send_f1(f1ap::UeContextSetupResponse{m.cu_ue, ue->du_ue, std::move(*cg), setup, std::move(drbs), std::nullopt}, true);
    if (m.rrc) {
        dl_sdu(*ue, 1, *m.rrc);
    }
}

std::vector<Du::DrbView> Du::drb_list() const {
    std::vector<DrbView> out;
    for (const auto& [id, ue] : ues_) {
        for (const auto& [d, drb] : ue.drbs) {
            out.push_back(DrbView{ue.rnti, d, drb.lcid, drb.qfis, drb.gfbr_dl, drb.gfbr_ul});
        }
    }
    return out;
}

void Du::handle(const f1ap::UeContextModificationRequest& m) {
    Ue* ue = by_du(m.du_ue);
    if (ue == nullptr) {
        ++stats_.f1_errors;
        send_f1(f1ap::ErrorIndication{0, m.cu_ue, m.du_ue, f1ap::Cause{"radioNetwork", "unknown-or-already-allocated-gnb-du-ue-f1ap-id"}},
                true);
        return;
    }
    std::set<std::uint8_t> added(m.srbs.begin(), m.srbs.end());
    added.erase(0);
    ue->srbs.insert(added.begin(), added.end());
    std::vector<Ue::Drb> new_drbs;
    std::vector<std::uint8_t> released;
    auto drbs = drbs_change(*ue, m.drbs, m.release_drbs, new_drbs, released);
    // P2 Q10 (TS 38.473 8.3.4.2): a DRB whose QoS flows change keeps its RLC and F1-U ends.
    std::vector<f1ap::DrbSetup> modified;
    for (const auto& d : m.modify_drbs) {
        auto it = ue->drbs.find(d.drb_id);
        if (it == ue->drbs.end()) {
            continue;
        }
        if (d.ul.teid != 0) {
            it->second.ul = d.ul;   // the CU-UP's end, as it was unless the CU-CP names another
        }
        it->second.qfis.clear();
        it->second.gfbr_dl = it->second.gfbr_ul = 0;
        for (const auto& f : d.flows) {
            it->second.qfis.push_back(f.qfi);
            if (f.gbr) {
                it->second.gfbr_dl += f.gbr->gfbr_dl;
                it->second.gfbr_ul += f.gbr->gfbr_ul;
            }
        }
        modified.push_back(f1ap::DrbSetup{it->second.id, std::nullopt, f1ap::GtpTunnel{cfg_.f1u_addr, it->second.dl_teid}});
    }
    // TS 38.473 8.3.4.3 (P2 Q4): when none of the requested modifications can be made.
    const bool asked = !m.drbs.empty() || !m.release_drbs.empty() || !m.modify_drbs.empty() || !added.empty() || m.rrc.has_value();
    const bool made = !drbs.empty() || !released.empty() || !modified.empty() || !added.empty() || m.rrc.has_value();
    if (asked && !made) {
        const f1ap::Cause why = f1u_ ? f1ap::Cause{"radioNetwork", "unspecified"}
                                     : f1ap::Cause{"transport", "transport-resource-unavailable"};
        events_.emit("ran.f1.ue_mod_failure", cfg_.id, {{"du_ue", str(ue->du_ue)}, {"cause", why.group + "/" + why.value}});
        send_f1(f1ap::UeContextModificationFailure{m.cu_ue, ue->du_ue, why}, true);
        return;
    }
    std::optional<Bytes> cg;
    if (!added.empty() || !new_drbs.empty() || !released.empty()) {
        if (auto c = cell_group(added, new_drbs, released)) {
            cg = std::move(*c);
        }
    }
    send_f1(f1ap::UeContextModificationResponse{m.cu_ue, ue->du_ue, std::move(cg), std::move(drbs), std::move(modified)}, true);
    if (m.rrc) {
        dl_sdu(*ue, 1, *m.rrc);
    }
}

void Du::handle(const f1ap::UeContextReleaseCommand& m) {
    Ue* ue = by_du(m.du_ue);
    if (ue != nullptr) {
        if (m.rrc && m.srb) {
            dl_sdu(*ue, *m.srb, *m.rrc);
        }
        by_rnti_.erase(ue->rnti);
        drop_drbs(*ue);
        ues_.erase(m.du_ue);
    }
    send_f1(f1ap::UeContextReleaseComplete{m.cu_ue, m.du_ue}, true);
}

} // namespace ksim::proc::ran
