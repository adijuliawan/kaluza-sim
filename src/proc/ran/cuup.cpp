// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ran/cuup.hpp"

#include <variant>

#include "codec/sdap/sdap.hpp"
#include "platform/mutation.hpp"

namespace ksim::proc::ran {

namespace {

template <class... F>
struct Overload : F... {
    using F::operator()...;
};
template <class... F>
Overload(F...) -> Overload<F...>;

constexpr std::uint8_t kN3Tag = 0x31;    // TEIDs of the CU-UP's N3 ends
constexpr std::uint8_t kF1uTag = 0x32;   // and of its F1-U ends

std::string str(std::uint64_t v) { return std::to_string(v); }

ksim::Endpoint at(const e1ap::GtpTunnel& t, std::uint16_t port) {
    return ksim::Endpoint::v4(t.addr[0], t.addr[1], t.addr[2], t.addr[3], port);
}

} // namespace

CuUp::CuUp(Executor& ex, IEventSink& events, CuUpConfig cfg, IAssoc& e1, IDatagram& n3, IDatagram& f1u)
    : ex_(ex), events_(events), cfg_(std::move(cfg)), e1_(e1), n3_(n3, kN3Tag), f1u_(f1u, kF1uTag),
      alive_(std::make_shared<bool>(true)) {
    e1_.set_handlers(
        [this](ByteView m, SctpMeta meta) {
            if (meta.ppid != kE1apPpid && meta.ppid != 0) {   // 0: memlink in tests carries none
                ++stats_.e1_errors;
                events_.emit("ran.link.wrong_ppid", cfg_.id, {{"link", "e1ap"}, {"ppid", std::to_string(meta.ppid)}});
                return;
            }
            on_e1(m);
        },
        [this](LinkEvent e) { on_e1_event(e); });
    n3_.on_error_indication([this](std::uint32_t teid, const ksim::Endpoint& from) {
        // TS 29.281 7.3.1: the peer has no tunnel for a TEID we sent to.
        events_.emit("ran.gtpu.error_indication", cfg_.id, {{"direction", "rx"}, {"teid", str(teid)}, {"from", from.to_string()}});
    });
    if (e1_.up()) {
        on_e1_event(LinkEvent::up);
    }
}

CuUp::~CuUp() { *alive_ = false; }

CuUp::Context* CuUp::by_up(std::uint32_t id) {
    auto it = ctx_.find(id);
    return it != ctx_.end() ? &it->second : nullptr;
}

void CuUp::send_e1(const e1ap::Pdu& p, bool ue) {
    auto wire = e1ap::encode(p);
    if (!wire) {
        events_.emit("ran.encode_error", cfg_.id, {{"what", wire.error().what}});
        return;
    }
    const auto id = ue ? e1ap::cu_up_ue_of(p) : std::nullopt;
    const std::uint16_t stream = id ? ue_stream(e1_.out_streams(), *id) : (ue && e1_.out_streams() > 1 ? std::uint16_t{1} : std::uint16_t{0});
    (void)e1_.send(*wire, SctpMeta{kE1apPpid, stream});
}

void CuUp::on_e1_event(LinkEvent e) {
    if (e == LinkEvent::up || e == LinkEvent::restart) {
        e1_ready_ = false;
        e1ap::E1SetupRequest r;
        r.transaction = ++transaction_;
        r.cu_up_id = cfg_.cu_up_id;
        r.name = cfg_.name;
        r.plmns = {{cfg_.plmn, cfg_.slices}};
        send_e1(r, false);
        return;
    }
    // E1 lost: every bearer context goes (TS 38.462 with the transport gone).
    e1_ready_ = false;
    for (auto& [id, c] : ctx_) {
        for (auto& [psi, s] : c.sessions) {
            release_session(s);
        }
    }
    ctx_.clear();
}

void CuUp::on_e1(ByteView msg) {
    auto p = e1ap::decode(msg);
    if (!p) {
        ++stats_.e1_errors;
        events_.emit("ran.e1.error", cfg_.id, {{"what", p.error().what}});
        if (p.error().code != Errc::unsupported) {
            send_e1(e1ap::ErrorIndication{0, std::nullopt, std::nullopt, e1ap::Cause{"protocol", "transfer-syntax-error"}}, false);
        }
        return;
    }
    std::visit(Overload{
                   [this](const e1ap::E1SetupResponse& m) { handle(m); },
                   [this](const e1ap::E1SetupFailure& m) { handle(m); },
                   [this](const e1ap::BearerContextSetupRequest& m) { handle(m); },
                   [this](const e1ap::BearerContextModificationRequest& m) { handle(m); },
                   [this](const e1ap::BearerContextReleaseCommand& m) { handle(m); },
                   [this](const e1ap::ErrorIndication& m) {
                       events_.emit("ran.e1.error", cfg_.id, {{"what", "ERROR INDICATION " + (m.cause ? m.cause->value : std::string("-"))}});
                   },
                   [this](const auto&) {
                       ++stats_.e1_errors;
                       events_.emit("ran.e1.error", cfg_.id, {{"what", "an E1AP message the CU-UP does not take"}});
                   },
               },
               *p);
}

void CuUp::handle(const e1ap::E1SetupResponse& m) {
    e1_ready_ = true;
    events_.emit("ran.e1.setup", cfg_.id, {{"cu_cp", m.cu_cp_name}});
}

void CuUp::handle(const e1ap::E1SetupFailure& m) {
    events_.emit("ran.e1.setup.failure", cfg_.id, {{"cause", m.cause.group + "/" + m.cause.value}});
}

Result<e1ap::SessionSetup> CuUp::setup_session(Context& c, const e1ap::SessionToSetup& s) {
    if (c.sessions.count(s.psi) != 0) {
        return make_error(Errc::invalid_argument, s.psi, "CU-UP: the PDU session exists");
    }
    const std::uint32_t up_id = c.cu_up_ue;
    const std::uint8_t psi = s.psi;
    Session& sess = c.sessions[psi];
    sess.psi = psi;
    sess.ng_ul = s.ng_ul;
    // UP security policy: integrity only when required (with the CU-CP's NIA),
    // ciphering unless not needed.
    sess.integrity = s.security.integrity == "required" && c.nia.has_value();
    sess.ciphering = s.security.confidentiality != "not-needed";
    sess.ng_dl_teid = n3_.bind([this, alive = alive_, up_id, psi](const entity::gtpu::UserData& d, const ksim::Endpoint&) {
        if (*alive) {
            on_n3(up_id, psi, d);
        }
    });
    e1ap::SessionSetup out;
    out.psi = psi;
    out.security = e1ap::SecurityResult{sess.integrity, sess.ciphering};
    out.ng_dl = e1ap::GtpTunnel{cfg_.n3_addr, sess.ng_dl_teid};
    for (const auto& d : s.drbs) {
        Drb& drb = sess.drbs[d.drb_id];
        drb.id = d.drb_id;
        drb.sdap_ul = d.sdap_ul;
        drb.sdap_dl = d.sdap_dl;
        for (const auto& f : d.flows) {
            drb.qfis.push_back(f.qfi);
            sess.qfi_to_drb[f.qfi] = d.drb_id;
        }
        if (d.default_drb) {
            sess.default_drb = d.drb_id;
        }
        entity::PdcpConfig pc;
        pc.srb = false;
        pc.rb_id = d.drb_id;
        pc.side = entity::PdcpSide::gnb;
        pc.sn_tx = pc.sn_rx = d.sn_bits == 12 ? pdcp::SnSize::len12 : pdcp::SnSize::len18;
        pc.drb_integrity = sess.integrity;
        pc.sdap_header_tx = d.sdap_dl;
        pc.sdap_header_rx = d.sdap_ul;
        const std::uint8_t drb_id = d.drb_id;
        drb.pdcp = std::make_unique<entity::Pdcp>(
            ex_, pc,
            [this, alive = alive_, up_id, psi, drb_id](Bytes pdu) {
                // DL PDCP PDU -> F1-U with the NR-U DL user data header.
                if (!*alive) {
                    return;
                }
                Context* cx = by_up(up_id);
                auto si = cx != nullptr ? cx->sessions.find(psi) : decltype(cx->sessions.find(psi)){};
                if (cx == nullptr || si == cx->sessions.end() || si->second.drbs.count(drb_id) == 0) {
                    return;
                }
                Drb& r = si->second.drbs.at(drb_id);
                if (!r.f1u_dl) {
                    ++stats_.dropped;   // the DU's end is not known yet
                    return;
                }
                const auto u = entity::gtpu::UserData::nru(r.f1u_dl->teid, r.nru_sn, std::move(pdu));
                r.nru_sn = (r.nru_sn + 1) & 0xFFFFFF;
                ++stats_.dl_packets;
                activity(*cx);
                (void)f1u_.send(at(*r.f1u_dl, cfg_.gtpu_port), u);
            },
            [this, alive = alive_, up_id, psi, drb_id](Bytes sdu) {
                // UL SDU -> SDAP header -> N3 with the UL PDU Session Container.
                if (!*alive) {
                    return;
                }
                Context* cx = by_up(up_id);
                if (cx == nullptr || cx->sessions.count(psi) == 0) {
                    return;
                }
                Session& ss = cx->sessions.at(psi);
                const Drb& r = ss.drbs.at(drb_id);
                std::uint8_t qfi = r.qfis.empty() ? 0 : r.qfis.front();
                if (r.sdap_ul) {
                    if (sdu.empty()) {
                        ++stats_.dropped;
                        return;
                    }
                    const auto h = sdap::decode_ul(sdu.front());
                    if (!h.data) {
                        return;   // an end-marker control PDU
                    }
                    qfi = h.qfi;
                    sdu.erase(sdu.begin());
                }
                ++stats_.ul_packets;
                QfiTraffic& q = per_qfi_[qfi];
                ++q.ul_packets;
                q.ul_bytes += sdu.size();
                activity(*cx);
                (void)n3_.send(at(ss.ng_ul, cfg_.gtpu_port),
                               entity::gtpu::UserData::ul_psc(ss.ng_ul.teid, qfi, std::move(sdu)));
            });
        const auto nea = static_cast<crypto::Nea>(sess.ciphering ? c.nea : 0);
        const auto nia = static_cast<crypto::Nia>(sess.integrity ? *c.nia : 0);
        if (auto r = drb.pdcp->set_keys(nia, sess.integrity ? c.k_int.clone() : SecretBytes{}, nea,
                                        sess.ciphering ? c.k_enc.clone() : SecretBytes{});
            !r) {
            return r.error();
        }
        drb.pdcp->set_integrity(sess.integrity, sess.integrity);
        drb.pdcp->set_ciphering(sess.ciphering, sess.ciphering);
        drb.f1u_ul_teid = f1u_.bind([this, alive = alive_, up_id, psi, drb_id](const entity::gtpu::UserData& u, const ksim::Endpoint&) {
            if (*alive) {
                on_f1u(up_id, psi, drb_id, u);
            }
        });
        out.drbs.push_back(e1ap::DrbSetup{d.drb_id, e1ap::GtpTunnel{cfg_.f1u_addr, drb.f1u_ul_teid}, drb.qfis});
    }
    events_.emit("ran.cuup.bearer.setup", cfg_.id,
                 {{"cu_up_ue", str(up_id)}, {"psi", str(psi)}, {"drbs", str(s.drbs.size())},
                  {"integrity", sess.integrity ? "1" : "0"}, {"ciphering", sess.ciphering ? "1" : "0"}});
    return out;
}

void CuUp::release_session(Session& s) {
    n3_.unbind(s.ng_dl_teid);
    for (auto& [id, d] : s.drbs) {
        f1u_.unbind(d.f1u_ul_teid);
    }
}

void CuUp::handle(const e1ap::BearerContextSetupRequest& m) {
    const std::uint32_t id = next_ue_++;
    Context& c = ctx_[id];
    c.cu_cp_ue = m.cu_cp_ue;
    c.cu_up_ue = id;
    c.nea = m.security.nea;
    c.nia = m.security.nia;
    // TS 33.501 A.8: a 128-bit algorithm's key is the 128 least significant bits of the
    // KDF output. TS 37.483 9.3.1.32 does not say which the IE carries; we send the
    // algorithm key, a CU-CP may send the whole output (OCUDU's does; KS-E1AP-S2).
    const auto alg_key = [](const Bytes& k) { return k.size() == 32 ? ByteView(k).subspan(16) : ByteView(k); };
    c.k_enc = SecretBytes::copy_of(alg_key(m.security.enc_key));
    if (m.security.int_key) {
        c.k_int = SecretBytes::copy_of(alg_key(*m.security.int_key));
    }
    e1ap::BearerContextSetupResponse r;
    r.cu_cp_ue = m.cu_cp_ue;
    r.cu_up_ue = id;
    for (const auto& s : m.sessions) {
        auto done = setup_session(c, s);
        if (!done) {
            for (auto& [psi, ss] : c.sessions) {
                release_session(ss);
            }
            ctx_.erase(id);
            send_e1(e1ap::BearerContextSetupFailure{m.cu_cp_ue, std::nullopt, e1ap::Cause{"radioNetwork", "unspecified"}}, true);
            return;
        }
        r.sessions.push_back(std::move(*done));
    }
    ++stats_.contexts_setup;
    send_e1(r, true);
    // TS 37.483 8.3.1.2: the UE Inactivity Timer, taken into account for inactivity monitoring.
    if (m.activity_level == "ue" && m.ue_inactivity_s) {
        c.inactivity = Millis{*m.ue_inactivity_s} * 1'000;
        c.last_activity = ex_.now();
        watch_inactivity(id);
    }
}

void CuUp::activity(Context& c) {
    c.last_activity = ex_.now();
    if (c.reported_inactive) {
        c.reported_inactive = false;   // active again: watched again
        watch_inactivity(c.cu_up_ue);
    }
}

void CuUp::watch_inactivity(std::uint32_t cu_up_ue) {
    const Context* c = by_up(cu_up_ue);
    if (c == nullptr || !c->inactivity) {
        return;
    }
    ex_.start_timer_at(c->last_activity + *c->inactivity, [this, alive = alive_, cu_up_ue] {
        if (!*alive) {
            return;
        }
        Context* cx = by_up(cu_up_ue);
        if (cx == nullptr || !cx->inactivity || cx->reported_inactive) {
            return;
        }
        if (ex_.now() < cx->last_activity + *cx->inactivity) {
            watch_inactivity(cu_up_ue);   // data came meanwhile
            return;
        }
        // TS 37.483 8.6.3: no user data for the timer's length; reported once until data again.
        cx->reported_inactive = true;
        if (KSIM_MUTANT("no_inactivity_notification")) {
            return;   // the mutant: the CU-CP never learns (row ksim-p2.e1-inactivity)
        }
        ++stats_.inactivity_reports;
        events_.emit("ran.e1.inactivity", cfg_.id, {{"cu_up_ue", str(cu_up_ue)}, {"active", "0"}});
        send_e1(e1ap::BearerContextInactivityNotification{cx->cu_cp_ue, cu_up_ue, false}, true);
    });
}

void CuUp::handle(const e1ap::BearerContextModificationRequest& m) {
    Context* c = by_up(m.cu_up_ue);
    if (c == nullptr || c->cu_cp_ue != m.cu_cp_ue) {
        send_e1(e1ap::BearerContextModificationFailure{m.cu_cp_ue, m.cu_up_ue,
                                                       e1ap::Cause{"radioNetwork", "unknown-or-inconsistent-pair-of-ue-e1ap-id"}},
                true);
        return;
    }
    e1ap::BearerContextModificationResponse r;
    r.cu_cp_ue = m.cu_cp_ue;
    r.cu_up_ue = m.cu_up_ue;
    for (std::uint8_t psi : m.remove) {
        auto it = c->sessions.find(psi);
        if (it != c->sessions.end()) {
            release_session(it->second);
            c->sessions.erase(it);
            events_.emit("ran.cuup.bearer.release", cfg_.id, {{"cu_up_ue", str(m.cu_up_ue)}, {"psi", str(psi)}});
        }
    }
    for (const auto& s : m.add) {
        auto done = setup_session(*c, s);
        if (!done) {
            send_e1(e1ap::BearerContextModificationFailure{m.cu_cp_ue, m.cu_up_ue, e1ap::Cause{"radioNetwork", "unspecified"}}, true);
            return;
        }
        r.added.push_back(std::move(*done));
    }
    for (const auto& s : m.modify) {
        auto it = c->sessions.find(s.psi);
        if (it == c->sessions.end()) {
            continue;
        }
        e1ap::SessionModified done{s.psi, {}};
        for (const auto& d : s.drbs) {
            auto dit = it->second.drbs.find(d.drb_id);
            if (dit != it->second.drbs.end() && d.f1u_dl) {
                dit->second.f1u_dl = d.f1u_dl;
                done.drbs.push_back(d.drb_id);
            }
        }
        r.modified.push_back(std::move(done));
    }
    send_e1(r, true);
}

void CuUp::handle(const e1ap::BearerContextReleaseCommand& m) {
    if (Context* c = by_up(m.cu_up_ue)) {
        for (auto& [psi, s] : c->sessions) {
            release_session(s);
        }
        ctx_.erase(m.cu_up_ue);
        events_.emit("ran.cuup.bearer.release", cfg_.id, {{"cu_up_ue", str(m.cu_up_ue)}, {"psi", "all"}});
    }
    send_e1(e1ap::BearerContextReleaseComplete{m.cu_cp_ue, m.cu_up_ue}, true);
}

void CuUp::on_n3(std::uint32_t cu_up_ue, std::uint8_t psi, const entity::gtpu::UserData& d) {
    Context* c = by_up(cu_up_ue);
    if (c == nullptr || c->sessions.count(psi) == 0) {
        return;
    }
    Session& s = c->sessions.at(psi);
    const std::uint8_t qfi = d.dl_qfi.value_or(0);
    QfiTraffic& q = per_qfi_[qfi];
    ++q.dl_packets;
    q.dl_bytes += d.payload.size();
    auto m = s.qfi_to_drb.find(qfi);
    const std::optional<std::uint8_t> drb = m != s.qfi_to_drb.end() ? std::optional<std::uint8_t>(m->second) : s.default_drb;
    if (!drb || s.drbs.count(*drb) == 0) {
        ++stats_.dropped;   // TS 37.324 5.2.2: no DRB for the flow
        return;
    }
    Drb& r = s.drbs.at(*drb);
    Bytes sdu;
    sdu.reserve(d.payload.size() + 1);
    if (r.sdap_dl) {
        sdu.push_back(sdap::encode(sdap::DlHeader{false, false, qfi}));
    }
    sdu.insert(sdu.end(), d.payload.begin(), d.payload.end());
    r.pdcp->write_sdu(std::move(sdu));
}

void CuUp::on_f1u(std::uint32_t cu_up_ue, std::uint8_t psi, std::uint8_t drb, const entity::gtpu::UserData& d) {
    Context* c = by_up(cu_up_ue);
    if (c == nullptr || c->sessions.count(psi) == 0 || c->sessions.at(psi).drbs.count(drb) == 0) {
        return;
    }
    if (d.ddds) {
        // The DU's feedback (TS 38.425 5.4.2). P2 sends DL data regardless: the
        // DU's buffer is ideal (ledger), so the report is counted, not obeyed.
        ++stats_.ddds_rx;
        last_ddds_ = d.ddds;
        if (d.payload.empty()) {
            return;
        }
    }
    c->sessions.at(psi).drbs.at(drb).pdcp->on_pdu(d.payload);
}

} // namespace ksim::proc::ran
