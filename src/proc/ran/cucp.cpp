// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ran/cucp.hpp"

#include <algorithm>
#include <utility>

#include "crypto/keys5g.hpp"

namespace ksim::proc::ran {

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

Millis wait_of(const std::optional<std::string>& t) {
    if (!t || t->size() < 3) {
        return 5'000;
    }
    return static_cast<Millis>(std::stoi(t->substr(1, t->size() - 2))) * 1'000;
}

/// 128-NEA/NIA n is bit n of the 16-bit map, counted from the most significant (TS 38.413 §9.3.1.86).
bool supports(std::uint16_t map, std::uint8_t alg) { return alg == 0 || (map & (0x8000U >> (alg - 1))) != 0; }

} // namespace

CuCp::CuCp(Executor& ex, IEventSink& events, CuCpConfig cfg, IAssoc& ngap, IAssoc& f1)
    : ex_(ex), events_(events), cfg_(std::move(cfg)), ng_(ngap), f1_(f1), alive_(std::make_shared<bool>(true)) {
    ng_.set_handlers([this](ByteView msg, SctpMeta) { on_ngap(msg); }, [this](LinkEvent e) { on_ng_event(e); });
    f1_.set_handlers([this](ByteView msg, SctpMeta) { on_f1(msg); }, [this](LinkEvent e) { on_f1_event(e); });
}

CuCp::~CuCp() {
    *alive_ = false;
    if (ng_retry_) {
        ex_.stop_timer(*ng_retry_);
    }
}

ngap::NrCgi CuCp::nr_cgi() const { return du_ ? ngap::NrCgi{du_->cgi.plmn, du_->cgi.nci} : ngap::NrCgi{}; }
ngap::Tai CuCp::tai() const {
    return {ngap::plmn_id(cfg_.plmn.mcc, cfg_.plmn.mnc), du_ ? du_->tac : 0};
}

std::uint8_t CuCp::next_tid(Ue& ue) {
    const std::uint8_t t = ue.tid;
    ue.tid = static_cast<std::uint8_t>((ue.tid + 1) % 4);
    return t;
}

CuCp::Ue* CuCp::by_cu(std::uint32_t id) {
    auto it = ues_.find(id);
    return it != ues_.end() ? &it->second : nullptr;
}

CuCp::Ue* CuCp::by_ran(std::uint32_t id) {
    for (auto& [cu, ue] : ues_) {
        if (ue.ran_ue == id) {
            return &ue;
        }
    }
    return nullptr;
}

// ---- sending ---------------------------------------------------------------------------

void CuCp::send_ngap(const ngap::Pdu& p, std::optional<std::uint32_t> ran_ue) {
    auto wire = ngap::encode(p);
    if (!wire) {
        events_.emit("ran.encode_error", cfg_.id, {{"what", wire.error().what}});
        return;
    }
    // TS 38.412 §7: stream 0 for non-UE-associated signalling, the others for UEs.
    std::uint16_t stream = 0;
    if (ran_ue && ng_.out_streams() > 1) {
        stream = static_cast<std::uint16_t>(1 + *ran_ue % (ng_.out_streams() - 1U));
    }
    (void)ng_.send(*wire, SctpMeta{kNgapPpid, stream});
}

void CuCp::send_f1(const f1ap::Pdu& p, bool ue_associated) {
    auto wire = f1ap::encode(p);
    if (!wire) {
        events_.emit("ran.encode_error", cfg_.id, {{"what", wire.error().what}});
        return;
    }
    (void)f1_.send(*wire, SctpMeta{kF1apPpid, static_cast<std::uint16_t>(ue_associated && f1_.out_streams() > 1 ? 1 : 0)});
}

void CuCp::error_indication(ngap::UeIds ids, const char* group, const char* value) {
    ++stats_.ngap_errors;
    events_.emit("ran.ngap.error_indication", cfg_.id, {{"direction", "tx"}, {"cause", std::string(group) + "/" + value}});
    send_ngap(ngap::ErrorIndication{ids, ngap::Cause{group, value}}, ids.ran);
}

// ---- associations ------------------------------------------------------------------------

void CuCp::on_ng_event(LinkEvent e) {
    if (e == LinkEvent::up || e == LinkEvent::restart) {
        ng_setup();
        return;
    }
    ng_ready_ = false;
    // The UEs' NG contexts are gone with the association (TS 38.413 §8.7.1.1 does it explicitly; L10).
    std::vector<std::uint32_t> gone;
    for (auto& [cu, ue] : ues_) {
        if (ue.amf_ue) {
            gone.push_back(cu);
        }
    }
    for (std::uint32_t cu : gone) {
        if (Ue* ue = by_cu(cu)) {
            release_locally(*ue);
        }
    }
}

void CuCp::on_f1_event(LinkEvent e) {
    if (e != LinkEvent::up && e != LinkEvent::restart) {
        du_.reset();
        ues_.clear();
    }
}

void CuCp::ng_setup() {
    if (!du_) {
        return;   // the TAs come from the DU's cell
    }
    ngap::NgSetupRequest r;
    r.plmn = ngap::plmn_id(cfg_.plmn.mcc, cfg_.plmn.mnc);
    r.gnb_id = cfg_.gnb_id;
    r.gnb_id_bits = cfg_.gnb_id_bits;
    r.name = cfg_.name;
    r.tas = {{du_->tac, {{r.plmn, cfg_.slices}}}};
    r.paging_drx = cfg_.paging_drx;
    send_ngap(r, std::nullopt);
}

// ---- F1 ------------------------------------------------------------------------------------

void CuCp::on_f1(ByteView msg) {
    auto p = f1ap::decode(msg);
    if (!p) {
        ++stats_.f1_errors;
        events_.emit("ran.f1.error", cfg_.id, {{"what", p.error().what}});
        return;
    }
    std::visit(Overload{
                   [this](const f1ap::F1SetupRequest& m) { handle(m); },
                   [this](const f1ap::InitialUlRrcMessageTransfer& m) { handle(m); },
                   [this](const f1ap::UlRrcMessageTransfer& m) { handle(m); },
                   [this](const f1ap::UeContextSetupResponse& m) { handle(m); },
                   [this](const f1ap::UeContextSetupFailure& m) { handle(m); },
                   [this](const f1ap::UeContextReleaseRequest& m) { handle(m); },
                   [this](const f1ap::UeContextReleaseComplete& m) { handle(m); },
                   [](const f1ap::UeContextModificationResponse&) {},
                   [this](const f1ap::ErrorIndication& m) {
                       events_.emit("ran.f1.error_indication", cfg_.id,
                                    {{"cause", m.cause ? m.cause->group + "/" + m.cause->value : ""}});
                   },
                   [this](const auto&) { ++stats_.f1_errors; },
               },
               *p);
}

void CuCp::handle(const f1ap::F1SetupRequest& m) {
    if (m.cells.empty()) {
        send_f1(f1ap::F1SetupFailure{m.transaction, f1ap::Cause{"misc", "unspecified"}, std::nullopt}, false);
        return;
    }
    const f1ap::ServedCell& cell = m.cells.front();
    du_ = DuInfo{m.du_id, cell.cgi, cell.tac};
    send_f1(f1ap::F1SetupResponse{m.transaction, cfg_.name, {cell.cgi}}, false);
    events_.emit("ran.f1.setup", cfg_.id, {{"du", m.du_name}, {"tac", str(cell.tac)}});
    if (ng_.up() && !ng_ready_) {
        ng_setup();
    }
}

std::unique_ptr<entity::Pdcp> CuCp::make_srb(std::uint32_t cu_ue, std::uint8_t srb) {
    entity::PdcpConfig c;
    c.srb = true;
    c.rb_id = srb;
    c.side = entity::PdcpSide::gnb;
    auto p = std::make_unique<entity::Pdcp>(
        ex_, c,
        [this, cu_ue, srb](Bytes pdu) {
            Ue* ue = by_cu(cu_ue);
            if (ue == nullptr) {
                return;
            }
            if (srb == 1 && ue->capture) {
                ue->captured = std::move(pdu);
                ue->capture = false;
                return;
            }
            send_f1(f1ap::DlRrcMessageTransfer{cu_ue, ue->du_ue, srb, std::move(pdu)}, true);
        },
        [this, cu_ue](Bytes sdu) { on_dcch(cu_ue, std::move(sdu)); });
    p->on_integrity_failure([this, cu_ue](std::uint32_t) {
        ex_.post([this, cu_ue, alive = alive_] {
            if (*alive) {
                on_srb_integrity_failure(cu_ue);
            }
        });
    });
    return p;
}

void CuCp::handle(const f1ap::InitialUlRrcMessageTransfer& m) {
    auto req = rrc::decode_ul_ccch(m.rrc);
    if (!req) {
        events_.emit("ran.rrc.error", cfg_.id, {{"what", req.error().what}});
        return;
    }
    // IDs: [shard:4][gen:4][index:24] (architecture.md §7.1); P1 runs one shard, generation 0.
    const std::uint32_t id = next_ue_++ & 0x00FFFFFF;
    Ue ue;
    ue.cu_ue = id;
    ue.du_ue = m.du_ue;
    ue.ran_ue = id;
    ue.c_rnti = m.c_rnti;
    ue.cause = req->cause;
    if (req->s_tmsi_part1) {
        ue.s_tmsi_part1 = req->identity;
    }
    rrc::CellGroup cg{0, {rrc::RlcBearer{1, true, 1, true}}, {}};
    if (m.du_to_cu) {
        if (auto c = rrc::decode_cell_group(*m.du_to_cu)) {
            cg = std::move(*c);
        }
    }
    auto setup = rrc::encode(rrc::Setup{0, rrc::RadioBearers{{rrc::SrbAdd{1, false}}, {}, {}}, cg});
    if (!setup) {
        return;
    }
    ue.srb1 = make_srb(id, 1);
    ues_.emplace(id, std::move(ue));
    send_f1(f1ap::DlRrcMessageTransfer{id, m.du_ue, 0, std::move(*setup)}, true);
}

void CuCp::handle(const f1ap::UlRrcMessageTransfer& m) {
    Ue* ue = by_cu(m.cu_ue);
    if (ue == nullptr) {
        ++stats_.f1_errors;
        return;
    }
    if (m.srb == 1 && ue->srb1) {
        ue->srb1->on_pdu(m.rrc);
    } else if (m.srb == 2 && ue->srb2) {
        ue->srb2->on_pdu(m.rrc);
    }
}

void CuCp::handle(const f1ap::UeContextSetupResponse& m) {
    Ue* ue = by_cu(m.cu_ue);
    if (ue == nullptr || ue->phase != Phase::securing) {
        return;
    }
    auto cg = rrc::decode_cell_group(m.cell_group);
    if (!cg) {
        ics_failed(*ue, "radioNetwork", "unspecified");
        return;
    }
    ue->srb2_cell_group = std::move(*cg);
    start_security(*ue);
}

void CuCp::handle(const f1ap::UeContextSetupFailure& m) {
    if (Ue* ue = by_cu(m.cu_ue)) {
        ics_failed(*ue, "radioNetwork", "unspecified");
    }
}

void CuCp::handle(const f1ap::UeContextReleaseRequest& m) {
    Ue* ue = by_cu(m.cu_ue);
    if (ue == nullptr) {
        return;
    }
    if (!ue->amf_ue) {
        release_locally(*ue);
        return;
    }
    // TS 38.413 §8.3.2 (L1): the radio connection is gone.
    events_.emit("ran.ue.release_request", cfg_.id, {{"ran_ue", str(ue->ran_ue)}, {"cause", "radio-connection-with-ue-lost"}});
    send_ngap(ngap::UeContextReleaseRequest{*ue->amf_ue, ue->ran_ue, ngap::Cause{"radioNetwork", "radio-connection-with-ue-lost"}},
              ue->ran_ue);
}

void CuCp::handle(const f1ap::UeContextReleaseComplete& m) {
    Ue* ue = by_cu(m.cu_ue);
    if (ue == nullptr) {
        return;
    }
    if (ue->phase == Phase::releasing && ue->amf_ue) {
        send_ngap(ngap::UeContextReleaseComplete{*ue->amf_ue, ue->ran_ue}, ue->ran_ue);
        events_.emit("ran.ue.released", cfg_.id, {{"ran_ue", str(ue->ran_ue)}});
    }
    ues_.erase(m.cu_ue);
}

void CuCp::release_locally(Ue& ue) {
    send_f1(f1ap::UeContextReleaseCommand{ue.cu_ue, ue.du_ue, f1ap::Cause{"radioNetwork", "unspecified"}, std::nullopt,
                                          std::nullopt},
            true);
    ues_.erase(ue.cu_ue);
}

// ---- NG-C ----------------------------------------------------------------------------------

void CuCp::on_ngap(ByteView msg) {
    ++stats_.ngap_rx;
    auto p = ngap::decode(msg);
    if (!p) {
        auto h = ngap::peek(msg);
        if (!h) {
            error_indication({}, "protocol", "transfer-syntax-error");   // §10.2
            return;
        }
        if (p.error().code == Errc::unsupported) {
            // §10.3: a procedure P1 does not take; criticality reject asks for a report.
            events_.emit("ran.ngap.unsupported", cfg_.id, {{"procedure", str(h->procedure)}});
            if (h->reject && h->kind == ngap::Header::Kind::initiating) {
                error_indication(h->ids, "protocol", "abstract-syntax-error-reject");
            }
            return;
        }
        error_indication(h->ids, "protocol", "abstract-syntax-error-falsely-constructed-message");
        return;
    }
    std::visit(Overload{
                   [this](const ngap::NgSetupResponse& m) { handle(m); },
                   [this](const ngap::NgSetupFailure& m) { handle(m); },
                   [this](const ngap::DownlinkNasTransport& m) { handle(m); },
                   [this](ngap::InitialContextSetupRequest& m) { handle(m); },
                   [this](const ngap::UeContextReleaseCommand& m) { handle(m); },
                   [this](const ngap::UeContextModificationRequest& m) { handle(m); },
                   [this](const ngap::Paging& m) { handle(m); },
                   [this](const ngap::NgReset& m) { handle(m); },
                   [this](const ngap::ErrorIndication& m) {
                       ++stats_.error_indications_rx;
                       events_.emit("ran.ngap.error_indication", cfg_.id,
                                    {{"direction", "rx"}, {"cause", m.cause ? m.cause->group + "/" + m.cause->value : ""}});
                   },
                   [this](const ngap::AmfStatusIndication& m) {
                       events_.emit("ran.amf.status", cfg_.id, {{"unavailable_guamis", str(static_cast<std::int64_t>(m.unavailable.size()))}});
                   },
                   [this](const ngap::AmfConfigurationUpdate&) {
                       send_ngap(ngap::AmfConfigurationUpdateAcknowledge{}, std::nullopt);
                   },
                   [this](const auto&) {
                       events_.emit("ran.ngap.unexpected", cfg_.id, {});
                   },
               },
               *p);
}

void CuCp::handle(const ngap::NgSetupResponse& m) {
    ng_ready_ = true;
    amf_name_ = m.amf_name;
    if (ng_retry_) {
        ex_.stop_timer(*ng_retry_);
        ng_retry_.reset();
    }
    events_.emit("ran.ng.setup", cfg_.id, {{"amf", m.amf_name}, {"capacity", str(m.capacity)}});
}

const char* CuCp::phase_name(Phase p) noexcept {
    switch (p) {
    case Phase::setup: return "setup";
    case Phase::connected: return "connected";
    case Phase::securing: return "securing";
    case Phase::capability: return "capability";
    case Phase::reconfiguring: return "reconfiguring";
    case Phase::active: return "active";
    case Phase::releasing: return "releasing";
    }
    return "?";
}

std::vector<CuCpUeView> CuCp::ue_list() const {
    std::vector<CuCpUeView> out;
    out.reserve(ues_.size());
    for (const auto& [id, ue] : ues_) {
        out.push_back(CuCpUeView{ue.ran_ue, ue.amf_ue, ue.c_rnti, phase_name(ue.phase)});
    }
    return out;
}

void CuCp::handle(const ngap::NgSetupFailure& m) {
    const Millis wait = wait_of(m.time_to_wait);
    events_.emit("ran.ng.setup.failure", cfg_.id, {{"cause", m.cause.group + "/" + m.cause.value}, {"retry_ms", str(wait)}});
    ng_retry_ = ex_.start_timer(wait, [this, alive = alive_] {
        if (*alive) {
            ng_retry_.reset();
            if (ng_.up()) {
                ng_setup();
            }
        }
    });
}

void CuCp::handle(const ngap::DownlinkNasTransport& m) {
    Ue* ue = by_ran(m.ran);
    if (ue == nullptr) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "unknown-local-UE-NGAP-ID");   // §10.6
        return;
    }
    if (ue->amf_ue && *ue->amf_ue != m.amf) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "inconsistent-remote-UE-NGAP-ID");
        return;
    }
    ue->amf_ue = m.amf;
    dl_dcch(*ue, rrc::encode(rrc::DlInformationTransfer{next_tid(*ue), m.nas}), ue->srb2 ? 2 : 1);
}

void CuCp::handle(ngap::InitialContextSetupRequest& m) {
    Ue* ue = by_ran(m.ran);
    // The key moves into SecretBytes at once; the codec's copy is wiped (row KS-NGAP-B2).
    SecretBytes kgnb = SecretBytes::copy_of(m.security_key);
    secure_zero(m.security_key);
    if (ue == nullptr) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "unknown-local-UE-NGAP-ID");
        return;
    }
    ue->amf_ue = m.amf;
    ue->kgnb = std::move(kgnb);
    ue->ics_nas = m.nas;
    if (m.ue_radio_capability) {
        if (auto nr = rrc::nr_capability_of(*m.ue_radio_capability)) {
            ue->nr_capability = std::move(*nr);
        }
    }
    ue->nea.reset();
    ue->nia.reset();
    for (std::uint8_t a : cfg_.nea_preference) {
        if ((a != 0 || cfg_.allow_null) && supports(m.nr_enc, a)) {
            ue->nea = a;
            break;
        }
    }
    for (std::uint8_t a : cfg_.nia_preference) {
        if ((a != 0 || cfg_.allow_null) && supports(m.nr_int, a)) {
            ue->nia = a;
            break;
        }
    }
    if (!ue->nea || !ue->nia || !du_) {
        ics_failed(*ue, "radioNetwork", "encryption-and-or-integrity-protection-algorithms-not-supported");
        return;
    }
    ue->phase = Phase::securing;
    f1ap::UeContextSetupRequest r;
    r.cu_ue = ue->cu_ue;
    r.du_ue = ue->du_ue;
    r.spcell = du_->cgi;
    r.srbs = {2};
    send_f1(r, true);
}

void CuCp::handle(const ngap::UeContextReleaseCommand& m) {
    Ue* ue = m.ran ? by_ran(*m.ran) : nullptr;
    if (ue == nullptr && !m.ran) {
        for (auto& [cu, u] : ues_) {
            if (u.amf_ue == m.amf) {
                ue = &u;
                break;
            }
        }
    }
    if (ue == nullptr) {
        // §8.3.3.2: nothing to release; still report the IDs as unknown.
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "unknown-local-UE-NGAP-ID");
        return;
    }
    ue->amf_ue = m.amf;
    ue->phase = Phase::releasing;
    std::optional<Bytes> rrc_release;
    if (ue->srb1) {
        ue->capture = true;
        ue->srb1->write_sdu(rrc::encode(rrc::Release{next_tid(*ue)}).value_or(Bytes{}));
        rrc_release = std::move(ue->captured);
        ue->captured.reset();
    }
    std::optional<std::uint8_t> srb;
    if (rrc_release) {
        srb = 1;
    }
    send_f1(f1ap::UeContextReleaseCommand{ue->cu_ue, ue->du_ue, f1ap::Cause{"radioNetwork", "normal-release"},
                                          std::move(rrc_release), srb},
            true);
}

void CuCp::handle(const ngap::UeContextModificationRequest& m) {
    if (by_ran(m.ran) == nullptr) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "unknown-local-UE-NGAP-ID");
        return;
    }
    // A key change (Security Key) is P3 with handover; P1 acknowledges the rest.
    send_ngap(ngap::UeContextModificationResponse{m.amf, m.ran}, m.ran);
}

void CuCp::handle(const ngap::Paging& m) {
    events_.emit("ran.ngap.paging", cfg_.id, {{"s_tmsi", str(static_cast<std::int64_t>(m.s_tmsi.value()))}});
    if (!du_ || std::find(m.tais.begin(), m.tais.end(), tai()) == m.tais.end()) {
        return;
    }
    const std::uint64_t s = m.s_tmsi.value();
    send_f1(f1ap::Paging{static_cast<std::uint16_t>(s % 1024), s, {du_->cgi}, m.drx}, false);
}

void CuCp::handle(const ngap::NgReset& m) {
    std::vector<std::uint32_t> gone;
    for (auto& [cu, ue] : ues_) {
        bool hit = m.all;
        for (const auto& c : m.connections) {
            hit = hit || (c.ran && *c.ran == ue.ran_ue) || (c.amf && ue.amf_ue && *c.amf == *ue.amf_ue);
        }
        if (hit) {
            gone.push_back(cu);
        }
    }
    for (std::uint32_t cu : gone) {
        if (Ue* ue = by_cu(cu)) {
            release_locally(*ue);
        }
    }
    events_.emit("ran.ng.reset", cfg_.id, {{"all", m.all ? "1" : "0"}, {"released", str(static_cast<std::int64_t>(gone.size()))}});
    send_ngap(ngap::NgResetAcknowledge{m.all ? std::vector<ngap::UeIds>{} : m.connections}, std::nullopt);
}

// ---- RRC ---------------------------------------------------------------------------------

void CuCp::dl_dcch(Ue& ue, Result<Bytes> msg, std::uint8_t srb) {
    if (!msg) {
        events_.emit("ran.encode_error", cfg_.id, {{"what", msg.error().what}});
        return;
    }
    entity::Pdcp* p = srb == 2 && ue.srb2 ? ue.srb2.get() : ue.srb1.get();
    if (p != nullptr) {
        p->write_sdu(std::move(*msg));
    }
}

void CuCp::on_dcch(std::uint32_t cu_ue, Bytes sdu) {
    Ue* ue = by_cu(cu_ue);
    if (ue == nullptr) {
        return;
    }
    auto d = rrc::decode_ul_dcch(sdu);
    if (!d) {
        events_.emit("ran.rrc.error", cfg_.id, {{"what", d.error().what}});
        return;
    }
    std::visit(Overload{
                   [&](const rrc::SetupComplete& m) {
                       ue->phase = Phase::connected;
                       ngap::InitialUeMessage i;
                       i.ran = ue->ran_ue;
                       i.nas = m.nas;
                       i.cgi = nr_cgi();
                       i.tai = tai();
                       i.cause = rrc::cause_name(ue->cause);
                       if (ue->s_tmsi_part1 && m.s_tmsi_part2) {
                           i.s_tmsi = ngap::FiveGSTmsi::of(std::uint64_t{*m.s_tmsi_part2} << 39 |
                                                           (*ue->s_tmsi_part1 & kPart1Mask));
                       }
                       events_.emit("ran.ue.connected", cfg_.id, {{"ran_ue", str(ue->ran_ue)}, {"c_rnti", str(ue->c_rnti)}});
                       send_ngap(i, ue->ran_ue);
                   },
                   [&](const rrc::UlInformationTransfer& m) {
                       if (!ue->amf_ue) {
                           events_.emit("ran.rrc.error", cfg_.id, {{"what", "uplink NAS before the AMF knows the UE"}});
                           return;
                       }
                       send_ngap(ngap::UplinkNasTransport{*ue->amf_ue, ue->ran_ue, m.nas, nr_cgi(), tai()}, ue->ran_ue);
                   },
                   [&](const rrc::SecurityModeComplete&) {
                       if (ue->phase != Phase::securing) {
                           return;
                       }
                       ue->srb1->set_ciphering(true, true);   // TS 38.331 §5.3.4: from now on
                       events_.emit("ran.as.smc", cfg_.id, {{"ran_ue", str(ue->ran_ue)},
                                                            {"alg", "nia" + str(ue->nia.value_or(0)) + "/nea" +
                                                                        str(ue->nea.value_or(0))}});
                       after_security(*ue);
                   },
                   [&](const rrc::SecurityModeFailure&) { ics_failed(*ue, "radioNetwork", "failure-in-radio-interface-procedure"); },
                   [&](const rrc::CapabilityInformation& m) {
                       if (ue->phase != Phase::capability) {
                           return;
                       }
                       ue->nr_capability = m.nr_capability;
                       if (auto cap = rrc::radio_access_capability(m.nr_capability); cap && ue->amf_ue) {
                           send_ngap(ngap::UeRadioCapabilityInfoIndication{*ue->amf_ue, ue->ran_ue, std::move(*cap)}, ue->ran_ue);
                       }
                       reconfigure(*ue);
                   },
                   [&](const rrc::ReconfigurationComplete&) {
                       if (ue->phase != Phase::reconfiguring || !ue->amf_ue) {
                           return;
                       }
                       ue->phase = Phase::active;
                       ++stats_.ics_ok;
                       events_.emit("ran.ics.complete", cfg_.id, {{"ran_ue", str(ue->ran_ue)}});
                       send_ngap(ngap::InitialContextSetupResponse{*ue->amf_ue, ue->ran_ue}, ue->ran_ue);
                   },
               },
               *d);
}

void CuCp::start_security(Ue& ue) {
    if (!ue.nia || !ue.nea || !ue.srb1) {
        ics_failed(ue, "radioNetwork", "unspecified");
        return;
    }
    const std::uint8_t nia = *ue.nia;
    const std::uint8_t nea = *ue.nea;
    auto ki = crypto::keys5g::algorithm_key(ue.kgnb, AlgType::rrc_int, nia);
    auto ke = crypto::keys5g::algorithm_key(ue.kgnb, AlgType::rrc_enc, nea);
    if (!ki || !ke ||
        !ue.srb1->set_keys(static_cast<crypto::Nia>(nia), ki->clone(), static_cast<crypto::Nea>(nea), ke->clone())) {
        ics_failed(ue, "radioNetwork", "unspecified");
        return;
    }
    ue.k_rrc_int = std::move(*ki);
    ue.k_rrc_enc = std::move(*ke);
    ue.srb1->set_integrity(true, true);   // the command goes integrity protected, not ciphered
    dl_dcch(ue, rrc::encode(rrc::SecurityModeCommand{next_tid(ue), nea, nia}));
}

void CuCp::after_security(Ue& ue) {
    if (ue.nr_capability) {
        reconfigure(ue);
        return;
    }
    ue.phase = Phase::capability;
    dl_dcch(ue, rrc::encode(rrc::CapabilityEnquiry{next_tid(ue)}));
}

void CuCp::reconfigure(Ue& ue) {
    if (!ue.nia || !ue.nea) {
        ics_failed(ue, "radioNetwork", "unspecified");
        return;
    }
    const auto nia = static_cast<crypto::Nia>(*ue.nia);
    const auto nea = static_cast<crypto::Nea>(*ue.nea);
    ue.srb2 = make_srb(ue.cu_ue, 2);
    (void)ue.srb2->set_keys(nia, ue.k_rrc_int.clone(), nea, ue.k_rrc_enc.clone());
    ue.srb2->set_integrity(true, true);
    ue.srb2->set_ciphering(true, true);
    rrc::Reconfiguration r;
    r.tid = next_tid(ue);
    r.bearers = rrc::RadioBearers{{rrc::SrbAdd{2, false}}, {}, {}};
    r.cell_group = ue.srb2_cell_group;
    if (ue.ics_nas) {
        r.nas.push_back(*ue.ics_nas);
    }
    ue.phase = Phase::reconfiguring;
    dl_dcch(ue, rrc::encode(r));
}

void CuCp::ics_failed(Ue& ue, const char* group, const char* value) {
    ++stats_.ics_failed;
    events_.emit("ran.ics.failure", cfg_.id, {{"ran_ue", str(ue.ran_ue)}, {"cause", std::string(group) + "/" + value}});
    ue.phase = Phase::connected;
    if (ue.amf_ue) {
        send_ngap(ngap::InitialContextSetupFailure{*ue.amf_ue, ue.ran_ue, ngap::Cause{group, value}}, ue.ran_ue);
    }
}

void CuCp::on_srb_integrity_failure(std::uint32_t cu_ue) {
    Ue* ue = by_cu(cu_ue);
    if (ue == nullptr) {
        return;
    }
    events_.emit("ran.rrc.integrity_failure", cfg_.id, {{"ran_ue", str(ue->ran_ue)}});
    if (ue->phase == Phase::securing) {
        // The UE could not verify the command (a K_gNB mismatch): its unprotected
        // SecurityModeFailure fails here (TS 38.331 §5.3.4.3).
        ics_failed(*ue, "radioNetwork", "failure-in-radio-interface-procedure");
    }
}

} // namespace ksim::proc::ran
