// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ran/cucp.hpp"

#include "platform/mutation.hpp"

#include <algorithm>
#include <utility>

#include "crypto/keys5g.hpp"
#include "proc/ran/cuup.hpp"   // kE1apPpid

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

CuCp::CuCp(Executor& ex, IEventSink& events, CuCpConfig cfg, IAssoc& ngap, IAssoc& f1, IAssoc* e1)
    : ex_(ex), events_(events), cfg_(std::move(cfg)), ng_(ngap), f1_(f1), alive_(std::make_shared<bool>(true)), e1_(e1) {
    // P2 Q2: a message under another protocol's PPID is dropped and counted (TS 38.412, 38.472, 37.482 §7).
    ng_.set_handlers(
        [this](ByteView msg, SctpMeta m) {
            if (ppid_ok(m, kNgapPpid, "ngap")) {
                on_ngap(msg);
            }
        },
        [this](LinkEvent e) { on_ng_event(e); });
    f1_.set_handlers(
        [this](ByteView msg, SctpMeta m) {
            if (ppid_ok(m, kF1apPpid, "f1ap")) {
                f1_rx_stream_ = m.stream;
                on_f1(msg);
            }
        },
        [this](LinkEvent e) { on_f1_event(e); });
    if (e1_ != nullptr) {
        e1_->set_handlers(
            [this](ByteView msg, SctpMeta m) {
                if (ppid_ok(m, kE1apPpid, "e1ap")) {
                    on_e1(msg);
                }
            },
            [this](LinkEvent e) { on_e1_event(e); });
    }
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

bool CuCp::ppid_ok(const SctpMeta& m, std::uint32_t want, const char* link) {
    if (m.ppid == want || m.ppid == 0) {
        return true;   // 0: a transport with no PPIDs (memlink in tests)
    }
    ++stats_.wrong_ppid;
    events_.emit("ran.link.wrong_ppid", cfg_.id, {{"link", link}, {"ppid", std::to_string(m.ppid)}});
    return false;
}

Result<void> CuCp::cu_configuration_update(std::vector<f1ap::NrCgi> activate, std::vector<f1ap::NrCgi> deactivate) {
    if (!du_) {
        return make_error(Errc::closed, 0, "no F1 with a DU");
    }
    f1_transaction_ = static_cast<std::uint8_t>(f1_transaction_ + 1);
    send_f1(f1ap::GnbCuConfigurationUpdate{f1_transaction_, std::move(activate), std::move(deactivate)}, false);
    return {};
}

void CuCp::send_f1(const f1ap::Pdu& p, bool ue_associated) {
    auto wire = f1ap::encode(p);
    if (!wire) {
        events_.emit("ran.encode_error", cfg_.id, {{"what", wire.error().what}});
        return;
    }
    const auto ue = ue_associated ? f1ap::cu_ue_of(p) : std::nullopt;
    (void)f1_.send(*wire, SctpMeta{kF1apPpid, ue ? ue_stream(f1_.out_streams(), *ue) : static_cast<std::uint16_t>(0)});
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
    if (e == LinkEvent::up || e == LinkEvent::restart || e == LinkEvent::refused) {
        return;
    }
    // P2 Q2 (row ksim-p2.f1-loss-release): with F1 gone the UEs' radio connections are gone too.
    // A UE the AMF knows is asked to be released (TS 38.413 §8.3.2); the others go at once.
    du_.reset();
    events_.emit("ran.f1.lost", cfg_.id, {{"link", link_event_name(e)}, {"ues", std::to_string(ues_.size())}});
    std::vector<std::uint32_t> local;
    for (auto& [cu, ue] : ues_) {
        if (!ue.amf_ue || KSIM_MUTANT("f1_loss_silent")) {
            local.push_back(cu);
            continue;
        }
        ue.du_gone = true;
        if (ue.phase != Phase::releasing) {
            events_.emit("ran.ue.release_request", cfg_.id, {{"ran_ue", str(ue.ran_ue)}, {"cause", "radio-connection-with-ue-lost"}});
            send_ngap(ngap::UeContextReleaseRequest{*ue.amf_ue, ue.ran_ue, ngap::Cause{"radioNetwork", "radio-connection-with-ue-lost"}},
                      ue.ran_ue);
        }
    }
    for (std::uint32_t cu : local) {
        ues_.erase(cu);
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
    // P2 Q2: which streams the DU's UE-associated messages come on (row ksim-p2.per-ue-stream).
    if (f1ap::du_ue_of(*p)) {
        if (f1_rx_stream_ == 0) {
            ++stats_.f1_ue_on_stream0;
        } else {
            f1_ue_streams_.insert(f1_rx_stream_);
        }
    }
    std::visit(Overload{
                   [this](const f1ap::F1SetupRequest& m) { handle(m); },
                   [this](const f1ap::InitialUlRrcMessageTransfer& m) { handle(m); },
                   [this](const f1ap::UlRrcMessageTransfer& m) { handle(m); },
                   [this](const f1ap::UeContextSetupResponse& m) { handle(m); },
                   [this](const f1ap::UeContextSetupFailure& m) { handle(m); },
                   [this](const f1ap::UeContextReleaseRequest& m) { handle(m); },
                   [this](const f1ap::UeContextReleaseComplete& m) { handle(m); },
                   [this](const f1ap::UeContextModificationResponse& m) { handle(m); },
                   [this](const f1ap::UeContextModificationFailure& m) {
                       // P2 Q4 (TS 38.473 8.3.4.3): the DU made none of it. The sessions fail
                       // towards the AMF, a transport cause as one (TS 38.413 9.3.1.2).
                       Ue* ue = by_cu(m.cu_ue);
                       if (ue != nullptr && !ue->jobs.empty() && ue->jobs.front().stage == Ue::Job::Stage::f1) {
                           if (m.cause.group == "transport") {
                               job_failed(*ue, "transport", "transport-resource-unavailable");
                           } else {
                               job_failed(*ue, "radioNetwork", "unspecified");
                           }
                       }
                   },
                   [this](const f1ap::GnbCuConfigurationUpdateAcknowledge& m) {
                       events_.emit("ran.f1.cu_config_update", cfg_.id,
                                    {{"transaction", str(m.transaction)}, {"failed", str(static_cast<std::int64_t>(m.failed.size()))}});
                   },
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

Result<void> CuCp::request_release(std::uint32_t ran_ue, const std::string& cause) {
    Ue* ue = by_ran(ran_ue);
    if (ue == nullptr || !ue->amf_ue) {
        return make_error(Errc::invalid_argument, ran_ue, "CU-CP: no UE with that RAN UE NGAP ID known to the AMF");
    }
    if (cause == "user-inactivity" && !ue->jobs.empty()) {
        // A UE whose context or sessions are being set up is not inactive.
        return make_error(Errc::invalid_argument, ran_ue, "CU-CP: a UE procedure is in progress");
    }
    events_.emit("ran.ue.release_request", cfg_.id, {{"ran_ue", str(ue->ran_ue)}, {"cause", cause}});
    send_ngap(ngap::UeContextReleaseRequest{*ue->amf_ue, ue->ran_ue, ngap::Cause{"radioNetwork", cause}}, ue->ran_ue);
    return {};
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
    if (ue.cu_up_ue && e1_ != nullptr) {
        send_e1(e1ap::BearerContextReleaseCommand{ue.cu_ue, *ue.cu_up_ue, e1ap::Cause{"radioNetwork", "unspecified"}}, true);
    }
    // The Uu side goes too (TS 38.413 8.7.4.2.2; TS 38.473 8.3.3.2): an RRCRelease
    // on SRB1 when the UE has one, so it does not stay on bearers nobody serves.
    std::optional<Bytes> rrc_release;
    if (ue.srb1) {
        ue.capture = true;
        ue.srb1->write_sdu(rrc::encode(rrc::Release{next_tid(ue)}).value_or(Bytes{}));
        rrc_release = std::move(ue.captured);
        ue.captured.reset();
    }
    std::optional<std::uint8_t> srb;
    if (rrc_release) {
        srb = 1;
    }
    send_f1(f1ap::UeContextReleaseCommand{ue.cu_ue, ue.du_ue, f1ap::Cause{"radioNetwork", "unspecified"},
                                          std::move(rrc_release), srb},
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
                   [this](const ngap::PduSessionResourceSetupRequest& m) { handle(m); },
                   [this](const ngap::PduSessionResourceReleaseCommand& m) { handle(m); },
                   [this](const ngap::PduSessionResourceModifyRequest& m) { handle(m); },
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
    if (m.ue_ambr) {
        ue->ue_ambr = m.ue_ambr;
    }
    if (!m.sessions.empty()) {
        Ue::Job j;
        j.ics = true;
        j.items = m.sessions;
        ue->jobs.push_back(std::move(j));
    }
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
    if (ue->cu_up_ue && e1_ != nullptr) {
        send_e1(e1ap::BearerContextReleaseCommand{ue->cu_ue, *ue->cu_up_ue, e1ap::Cause{"radioNetwork", "normal-release"}}, true);
        ue->cu_up_ue.reset();
    }
    if (ue->du_gone || !f1_.up()) {
        // No DU to release it on (F1 lost): the release completes here.
        send_ngap(ngap::UeContextReleaseComplete{*ue->amf_ue, ue->ran_ue}, ue->ran_ue);
        events_.emit("ran.ue.released", cfg_.id, {{"ran_ue", str(ue->ran_ue)}});
        ues_.erase(ue->cu_ue);
        return;
    }
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
                       if (ue->phase == Phase::active && !ue->jobs.empty() && ue->jobs.front().stage == Ue::Job::Stage::rrc) {
                           job_done(*ue);
                           return;
                       }
                       if (ue->phase != Phase::reconfiguring || !ue->amf_ue) {
                           return;
                       }
                       ue->phase = Phase::active;
                       if (!ue->jobs.empty() && ue->jobs.front().ics) {
                           start_job(*ue);   // the ICS response waits for its sessions
                           return;
                       }
                       finish_ics(*ue, {}, {});
                       start_job(*ue);
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

// ---- E1 and PDU sessions (P1 N10) ------------------------------------------------------------

namespace {

e1ap::GtpTunnel e1_tunnel(const ngap::GtpTunnel& t) { return {t.addr, t.teid}; }
ngap::GtpTunnel ng_tunnel(const e1ap::GtpTunnel& t) { return {t.addr, t.teid}; }
f1ap::GtpTunnel f1_tunnel(const e1ap::GtpTunnel& t) { return {t.addr, t.teid}; }
e1ap::GtpTunnel e1_from_f1(const f1ap::GtpTunnel& t) { return {t.addr, t.teid}; }
bool is_in(const std::vector<std::uint8_t>& v, std::uint8_t x) { return std::find(v.begin(), v.end(), x) != v.end(); }

} // namespace

CuCp::Ue* CuCp::by_cu_up(std::uint32_t id) {
    for (auto& [cu, ue] : ues_) {
        if (ue.cu_up_ue == id) {
            return &ue;
        }
    }
    return nullptr;
}

std::vector<std::uint8_t> CuCp::sessions_of(std::uint32_t ran_ue) const {
    std::vector<std::uint8_t> out;
    for (const auto& [cu, ue] : ues_) {
        if (ue.ran_ue == ran_ue) {
            for (const auto& [psi, s] : ue.sessions) {
                out.push_back(psi);
            }
        }
    }
    return out;
}

void CuCp::send_e1(const e1ap::Pdu& p, bool ue_associated) {
    if (e1_ == nullptr) {
        return;
    }
    auto wire = e1ap::encode(p);
    if (!wire) {
        events_.emit("ran.encode_error", cfg_.id, {{"what", wire.error().what}});
        return;
    }
    const auto ue = ue_associated ? e1ap::cu_cp_ue_of(p) : std::nullopt;
    (void)e1_->send(*wire, SctpMeta{kE1apPpid, ue ? ue_stream(e1_->out_streams(), *ue) : static_cast<std::uint16_t>(0)});
}

void CuCp::on_e1_event(LinkEvent e) {
    if (e == LinkEvent::up || e == LinkEvent::restart || e == LinkEvent::refused) {
        return;
    }
    // P2 Q2: the bearer contexts went with the association, and with them the UEs' user plane. A UE
    // that had one is asked to be released (TS 38.413 §8.3.2), so the core does not keep sessions
    // that carry nothing.
    e1_ready_ = false;
    events_.emit("ran.e1.lost", cfg_.id, {{"link", link_event_name(e)}});
    for (auto& [cu, ue] : ues_) {
        const bool had = ue.cu_up_ue.has_value();
        ue.cu_up_ue.reset();
        if (had && ue.amf_ue && ue.phase != Phase::releasing) {
            events_.emit("ran.ue.release_request", cfg_.id,
                         {{"ran_ue", str(ue.ran_ue)}, {"cause", "release-due-to-ngran-generated-reason"}});
            send_ngap(ngap::UeContextReleaseRequest{*ue.amf_ue, ue.ran_ue,
                                                    ngap::Cause{"radioNetwork", "release-due-to-ngran-generated-reason"}},
                      ue.ran_ue);
        }
    }
}

void CuCp::on_e1(ByteView msg) {
    auto p = e1ap::decode(msg);
    if (!p) {
        events_.emit("ran.e1.error", cfg_.id, {{"what", p.error().what}});
        return;
    }
    std::visit(Overload{
                   [this](const e1ap::E1SetupRequest& m) {
                       e1_ready_ = true;
                       send_e1(e1ap::E1SetupResponse{m.transaction, cfg_.name}, false);
                       events_.emit("ran.e1.setup", cfg_.id, {{"cu_up", m.name}});
                   },
                   [this](const e1ap::BearerContextSetupResponse& m) { handle(m); },
                   [this](const e1ap::BearerContextModificationResponse& m) { handle(m); },
                   [this](const e1ap::BearerContextInactivityNotification& m) {
                       // P2 Q5 (TS 37.483 8.6.3; architecture.md 7.2): the UE did nothing for the
                       // UE Inactivity Timer, so the CU-CP asks the AMF to release it.
                       Ue* ue = by_cu(m.cu_cp_ue);
                       events_.emit("ran.e1.inactivity", cfg_.id,
                                    {{"cu_cp_ue", str(m.cu_cp_ue)}, {"active", m.active ? "1" : "0"}});
                       if (ue != nullptr && !m.active) {
                           (void)request_release(ue->ran_ue, "user-inactivity");
                       }
                   },
                   [this](const e1ap::BearerContextSetupFailure& m) {
                       if (Ue* ue = by_cu(m.cu_cp_ue)) {
                           job_failed(*ue, "radioNetwork", "unspecified");
                       }
                   },
                   [this](const e1ap::BearerContextModificationFailure& m) {
                       if (Ue* ue = by_cu(m.cu_cp_ue)) {
                           job_failed(*ue, "radioNetwork", "unspecified");
                       }
                   },
                   [](const e1ap::BearerContextReleaseComplete&) {},
                   [this](const e1ap::ErrorIndication& m) {
                       events_.emit("ran.e1.error", cfg_.id, {{"what", "ERROR INDICATION " + (m.cause ? m.cause->value : std::string("-"))}});
                   },
                   [this](const auto&) { events_.emit("ran.e1.error", cfg_.id, {{"what", "an E1AP message the CU-CP does not take"}}); },
               },
               *p);
}

void CuCp::handle(const ngap::PduSessionResourceSetupRequest& m) {
    Ue* ue = by_ran(m.ran);
    if (ue == nullptr) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "unknown-local-UE-NGAP-ID");
        return;
    }
    if (ue->amf_ue && *ue->amf_ue != m.amf) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "inconsistent-remote-UE-NGAP-ID");
        return;
    }
    if (m.ue_ambr) {
        ue->ue_ambr = m.ue_ambr;
    }
    Ue::Job j;
    j.items = m.sessions;
    j.nas = m.nas;
    ue->jobs.push_back(std::move(j));
    start_job(*ue);
}

void CuCp::handle(const ngap::PduSessionResourceReleaseCommand& m) {
    Ue* ue = by_ran(m.ran);
    if (ue == nullptr) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "unknown-local-UE-NGAP-ID");
        return;
    }
    Ue::Job j;
    j.kind = Ue::Job::Kind::release;
    j.nas = m.nas;
    j.release = m.sessions;
    ue->jobs.push_back(std::move(j));
    start_job(*ue);
}

void CuCp::handle(const ngap::PduSessionResourceModifyRequest& m) {
    Ue* ue = by_ran(m.ran);
    if (ue == nullptr) {
        error_indication(ngap::UeIds{m.amf, m.ran}, "radioNetwork", "unknown-local-UE-NGAP-ID");
        return;
    }
    if (KSIM_MUTANT("modify_ack_only")) {
        // The mutant (row ksim-p2.modify-add-flow): P1's way, no QoS change to the DRBs;
        // the NAS PDU goes to the UE and the flows are acknowledged as asked.
        ngap::PduSessionResourceModifyResponse r{m.amf, m.ran, {}, {}};
        for (const auto& s : m.sessions) {
            if (ue->sessions.count(s.psi) == 0) {
                r.failed.push_back(ngap::SessionCause{s.psi, ngap::Cause{"radioNetwork", "unknown-PDU-session-ID"}});
                continue;
            }
            ngap::ModifyResponseTransfer t;
            for (const auto& f : s.transfer.add_or_modify) {
                t.added_or_modified.push_back(f.qfi);
            }
            r.sessions.push_back(ngap::SessionModifyOk{s.psi, t});
            if (const auto& nas = s.nas) {
                dl_dcch(*ue, rrc::encode(rrc::DlInformationTransfer{next_tid(*ue), *nas}), ue->srb2 ? 2 : 1);
            }
        }
        send_ngap(r, ue->ran_ue);
        return;
    }
    // P2 Q10 (TS 38.413 8.2.3.2): a job of its own, after any procedure the UE has running.
    Ue::Job j;
    j.kind = Ue::Job::Kind::modify;
    // Copy-constructed and moved in: GCC's -Wnull-dereference misreads the vector's copy-assignment.
    j.modify = std::vector<ngap::SessionModifyItem>(m.sessions.begin(), m.sessions.end());
    ue->jobs.push_back(std::move(j));
    start_job(*ue);
}

Result<void> CuCp::release_flow(std::uint32_t ran_ue, std::uint8_t psi, std::uint8_t qfi) {
    Ue* ue = by_ran(ran_ue);
    if (ue == nullptr || !ue->amf_ue) {
        return make_error(Errc::invalid_argument, ran_ue, "CU-CP: no such UE known to the AMF");
    }
    auto s = ue->sessions.find(psi);
    if (s == ue->sessions.end()) {
        return make_error(Errc::invalid_argument, psi, "CU-CP: no such PDU session");
    }
    const auto& flows = s->second.item.transfer.flows;
    if (std::none_of(flows.begin(), flows.end(), [qfi](const auto& f) { return f.qfi == qfi; })) {
        return make_error(Errc::invalid_argument, qfi, "CU-CP: no such QoS flow in the session");
    }
    Ue::Job j;
    j.kind = Ue::Job::Kind::modify;
    j.notify = true;
    ngap::SessionModifyItem item;
    item.psi = psi;
    item.transfer.release = {qfi};
    j.modify.push_back(std::move(item));
    ue->jobs.push_back(std::move(j));
    start_job(*ue);
    return {};
}

// ---- QoS flows to DRBs (P2 Q10) ---------------------------------------------------------------

const char* drb_map_name(DrbMap m) noexcept { return m == DrbMap::per_session ? "per-session" : "per-5qi"; }

namespace {

// The DU gives DRB n LCID n+3, so DRBs 1..29 (TS 38.321 Table 6.2.1-1: LCIDs 4..32).
constexpr std::uint8_t kMaxDrbId = 29;

e1ap::QosFlow e1_flow(const ngap::QosFlowRequest& f) {
    std::optional<e1ap::Gbr> gbr;
    if (f.gbr) {   // P2 Q11: the bit rates go on to the CU-UP as NGAP gave them
        gbr = e1ap::Gbr{f.gbr->mfbr_dl, f.gbr->mfbr_ul, f.gbr->gfbr_dl, f.gbr->gfbr_ul};
    }
    return {f.qfi, f.five_qi, f.arp.priority, f.arp.may_preempt, f.arp.preemptable, gbr, f.reflective};
}
f1ap::Flow f1_flow(const ngap::QosFlowRequest& f) {
    std::optional<f1ap::Gbr> gbr;
    if (f.gbr) {   // and to the DU, which schedules them (P2 Q11)
        gbr = f1ap::Gbr{f.gbr->mfbr_dl, f.gbr->mfbr_ul, f.gbr->gfbr_dl, f.gbr->gfbr_ul};
    }
    return {f.qfi, f.five_qi, f.arp.priority, f.arp.may_preempt, f.arp.preemptable, gbr, f.reflective};
}

std::string qfi_list(const std::vector<std::uint8_t>& v) {
    std::string out;
    for (std::uint8_t q : v) {
        out += (out.empty() ? "" : ",") + std::to_string(q);
    }
    return out.empty() ? "-" : out;
}

template <typename D>
std::string drb_list(const std::vector<D>& drbs) {
    std::string out;
    for (const auto& d : drbs) {
        out += (out.empty() ? "" : ",") + std::to_string(d.id);
    }
    return out.empty() ? "-" : out;
}

} // namespace

bool CuCp::one_drb() const {
    // The mutant single_drb (row ksim-p2.multi-drb): every flow on the session's first DRB.
    return cfg_.drb_map == DrbMap::per_session || KSIM_MUTANT("single_drb");
}

std::set<std::uint8_t> CuCp::drbs_in_use(const Ue& ue) const {
    std::set<std::uint8_t> used;
    for (const auto& [psi, s] : ue.sessions) {
        for (const auto& d : s.drbs) {
            used.insert(d.id);
        }
    }
    if (!ue.jobs.empty()) {
        for (const auto& [psi, s] : ue.jobs.front().pending) {
            for (const auto& d : s.drbs) {
                used.insert(d.id);
            }
        }
    }
    return used;
}

std::optional<std::uint8_t> CuCp::take_drb(std::set<std::uint8_t>& used) {
    for (std::uint8_t d = 1; d <= kMaxDrbId; ++d) {
        if (used.insert(d).second) {
            return d;
        }
    }
    return std::nullopt;
}

CuCp::Ue::Drb* CuCp::drb_for(Ue::Session& s, std::uint16_t five_qi) const {
    // Per 5QI: the DRB that carries that 5QI. On one DRB: the default DRB (or the first).
    // A GBR flow's DRB is its own (P2 Q11): no other flow joins it.
    for (auto& d : s.drbs) {
        if (!d.gbr && (one_drb() ? d.default_drb : d.five_qi == five_qi)) {
            return &d;
        }
    }
    if (one_drb()) {
        for (auto& d : s.drbs) {
            if (!d.gbr) {
                return &d;
            }
        }
    }
    return nullptr;
}

// ---- GBR admission (P2 Q11; ledger A-07) ----------------------------------------------------

std::uint64_t CuCp::gbr_need(const ngap::QosFlowRequest& f) { return f.gbr ? f.gbr->gfbr_dl + f.gbr->gfbr_ul : 0; }

bool CuCp::admit(std::uint64_t used, const ngap::QosFlowRequest& f) const {
    // The mutant gbr_no_admission (row ksim-p2.gbr-refused): every GBR flow admitted.
    return KSIM_MUTANT("gbr_no_admission") || used + gbr_need(f) <= cfg_.gbr_budget_bps;
}

std::uint64_t CuCp::gbr_used() const {
    std::uint64_t n = 0;
    for (const auto& [cu, ue] : ues_) {
        for (const auto& [psi, s] : ue.sessions) {
            for (const auto& f : s.item.transfer.flows) {
                n += gbr_need(f);
            }
        }
        if (!ue.jobs.empty()) {   // sessions being set up hold theirs already
            for (const auto& [psi, s] : ue.jobs.front().pending) {
                for (const auto& f : s.item.transfer.flows) {
                    n += gbr_need(f);
                }
            }
        }
    }
    return n;
}

void CuCp::set_gbr_budget(std::uint64_t bps) {
    cfg_.gbr_budget_bps = bps;
    events_.emit("ran.gbr.budget", cfg_.id, {{"bps", std::to_string(bps)}, {"used", std::to_string(gbr_used())}});
    reassess_gbr();
}

void CuCp::reassess_gbr() {
    // The GBR flows in the cell, in the order the CU-CP holds them, each fulfilled while the
    // budget covers its GFBR beside those before it (TS 23.501 5.7.2.4, notification control).
    std::uint64_t load = 0;
    std::set<std::tuple<std::uint32_t, std::uint8_t, std::uint8_t>> now;
    std::map<std::uint32_t, std::map<std::uint8_t, ngap::NotifyTransfer>> notes;
    for (const auto& [cu, ue] : ues_) {
        for (const auto& [psi, s] : ue.sessions) {
            for (const auto& f : s.item.transfer.flows) {
                if (!f.gbr) {
                    continue;
                }
                const bool ok = load + gbr_need(f) <= cfg_.gbr_budget_bps;
                if (ok) {
                    load += gbr_need(f);
                }
                const auto key = std::tuple{cu, psi, f.qfi};
                if (!ok) {
                    now.insert(key);
                }
                if (ok == (not_fulfilled_.count(key) == 0)) {
                    continue;
                }
                events_.emit("ran.gbr.fulfilment", cfg_.id,
                             {{"ran_ue", str(ue.ran_ue)}, {"psi", str(psi)}, {"qfi", str(f.qfi)}, {"fulfilled", ok ? "1" : "0"},
                              {"notification_control", f.gbr->notification_control ? "1" : "0"}});
                if (f.gbr->notification_control) {
                    notes[cu][psi].notify.push_back(ngap::NotifyTransfer::Notify{f.qfi, ok});
                }
            }
        }
    }
    not_fulfilled_ = std::move(now);
    // TS 38.413 8.2.4.2: PDU SESSION RESOURCE NOTIFY with the flows not fulfilled or fulfilled
    // again (mutant notify_missing, row ksim-p2.gbr-notify).
    if (KSIM_MUTANT("notify_missing")) {
        return;
    }
    for (const auto& [cu, sessions] : notes) {
        auto it = ues_.find(cu);
        if (it == ues_.end()) {
            continue;
        }
        const auto amf_ue = it->second.amf_ue;
        if (!amf_ue) {
            continue;
        }
        ngap::PduSessionResourceNotify n{*amf_ue, it->second.ran_ue, {}, {}};
        for (const auto& [psi, t] : sessions) {
            n.sessions.push_back(ngap::SessionNotify{psi, t});
        }
        send_ngap(n, it->second.ran_ue);
    }
}

std::vector<CuCp::DrbView> CuCp::drbs_of(std::uint32_t ran_ue, std::uint8_t psi) const {
    std::vector<DrbView> out;
    for (const auto& [cu, ue] : ues_) {
        if (ue.ran_ue != ran_ue) {
            continue;
        }
        auto s = ue.sessions.find(psi);
        if (s == ue.sessions.end()) {
            break;
        }
        for (const auto& d : s->second.drbs) {
            DrbView v{d.id, d.default_drb, d.five_qi, {}, 0, 0, {}};
            for (const auto& f : d.flows) {
                v.qfis.push_back(f.qfi);
                if (f.gbr) {
                    v.gfbr_dl += f.gbr->gfbr_dl;
                    v.gfbr_ul += f.gbr->gfbr_ul;
                    if (not_fulfilled_.count(std::tuple{ue.cu_ue, psi, f.qfi}) != 0) {
                        v.not_fulfilled.push_back(f.qfi);
                    }
                }
            }
            out.push_back(std::move(v));
        }
    }
    return out;
}

// ---- the session jobs ------------------------------------------------------------------------

void CuCp::start_job(Ue& ue) {
    if (ue.jobs.empty() || ue.jobs.front().stage != Ue::Job::Stage::waiting || ue.phase != Phase::active) {
        return;
    }
    Ue::Job& j = ue.jobs.front();
    if (j.kind == Ue::Job::Kind::release) {
        rrc::RadioBearers b;
        rrc::CellGroup cg;
        for (const auto& s : j.release) {
            auto it = ue.sessions.find(s.psi);
            if (it == ue.sessions.end()) {
                continue;
            }
            for (const auto& d : it->second.drbs) {
                b.drb_release.push_back(d.id);
                if (d.du && d.du->lcid) {
                    cg.release_lcids.push_back(*d.du->lcid);
                }
            }
        }
        rrc::Reconfiguration r;
        r.tid = next_tid(ue);
        r.bearers = b;
        if (!cg.release_lcids.empty()) {
            r.cell_group = cg;
        }
        if (j.nas) {
            r.nas.push_back(*j.nas);
        }
        j.stage = Ue::Job::Stage::rrc;
        dl_dcch(ue, rrc::encode(r), ue.srb2 ? 2 : 1);
        return;
    }
    if (j.kind == Ue::Job::Kind::modify) {
        start_modify(ue);
        return;
    }
    // Setup: the session's flows on DRBs by the mapping (P2 Q10), the first DRB the default.
    if (e1_ == nullptr || !e1_ready_ || !ue.nea || !ue.nia) {
        job_failed(ue, "radioNetwork", "unspecified");
        return;
    }
    std::set<std::uint8_t> used = drbs_in_use(ue);
    std::uint64_t gbr_load = gbr_used();   // P2 Q11
    std::vector<e1ap::SessionToSetup> up;
    for (const auto& item : j.items) {
        if (ue.sessions.count(item.psi) != 0 || j.pending.count(item.psi) != 0) {
            j.failed.push_back(ngap::SessionCause{item.psi, ngap::Cause{"radioNetwork", "multiple-PDU-session-ID-instances"}});
            continue;
        }
        // P2 Q9: the UP security decision (TS 33.501 6.6.1, TS 38.413 8.2.1.2; up_security.hpp).
        const UpDecision upd = decide_up_security(item.transfer.security, cfg_.up_policy);
        if (upd.indicated || !KSIM_MUTANT("up_absent_silent")) {   // the mutant: silent when there was none
            const auto& si = item.transfer.security;
            events_.emit("ran.up.security", cfg_.id,
                         {{"ran_ue", str(ue.ran_ue)}, {"psi", str(item.psi)}, {"indication", upd.indicated ? "present" : "absent"},
                          {"asked", si ? si->integrity + "/" + si->confidentiality : std::string("-")},
                          {"integrity", upd.integrity ? "1" : "0"}, {"confidentiality", upd.confidentiality ? "1" : "0"},
                          {"result", upd.refuse ? upd.refuse->value : "set-up"}});
        }
        if (upd.refuse) {
            j.failed.push_back(ngap::SessionCause{item.psi, *upd.refuse});
            continue;
        }
        Ue::Session s;
        s.item = item;
        s.integrity = upd.integrity;
        s.confidentiality = upd.confidentiality;
        s.report = upd.report;
        std::set<std::uint8_t> mine;
        // P2 Q11: a GBR flow is admitted against the cell's budget; one refused goes in the
        // session's QoS Flow Failed to Setup List (TS 38.413 8.2.1.2), none left fails the session.
        std::vector<ngap::QosFlowRequest> flows;
        std::uint64_t mine_gbr = 0;
        for (auto f : item.transfer.flows) {
            if (KSIM_MUTANT("gbr_as_nongbr")) {
                f.gbr.reset();   // the mutant (row ksim-p2.gbr-setup): a GBR flow taken as non-GBR
            }
            if (f.gbr && !admit(gbr_load + mine_gbr, f)) {
                s.refused.push_back(ngap::QosFlowCause{f.qfi, ngap::Cause{"radioNetwork", "radio-resources-not-available"}});
                events_.emit("ran.gbr.refused", cfg_.id,
                             {{"ran_ue", str(ue.ran_ue)}, {"psi", str(item.psi)}, {"qfi", str(f.qfi)},
                              {"need", std::to_string(gbr_need(f))}, {"budget", std::to_string(cfg_.gbr_budget_bps)}});
                continue;
            }
            mine_gbr += gbr_need(f);
            flows.push_back(f);
        }
        s.item.transfer.flows = flows;
        bool fit = !flows.empty();
        for (const auto& f : flows) {
            Ue::Drb* d = f.gbr ? nullptr : drb_for(s, f.five_qi);
            if (d == nullptr) {
                const auto id = take_drb(used);
                if (!id) {
                    fit = false;
                    break;
                }
                mine.insert(*id);
                Ue::Drb fresh;
                fresh.id = *id;
                fresh.five_qi = f.five_qi;
                fresh.gbr = f.gbr.has_value();
                fresh.default_drb = s.drbs.empty();
                s.drbs.push_back(std::move(fresh));
                d = &s.drbs.back();
            }
            d->flows.push_back(f);
        }
        if (fit) {
            gbr_load += mine_gbr;
        }
        if (!fit) {
            for (std::uint8_t id : mine) {
                used.erase(id);
            }
            j.failed.push_back(ngap::SessionCause{item.psi, ngap::Cause{"radioNetwork", "radio-resources-not-available"}});
            continue;
        }
        e1ap::SessionToSetup t;
        t.psi = item.psi;
        t.type = item.transfer.type;
        t.snssai = e1ap::Snssai{item.snssai.sst, item.snssai.sd};
        t.security = e1ap::SecurityIndication{s.integrity ? "required" : "not-needed",
                                              s.confidentiality ? "required" : "not-needed"};
        t.ng_ul = e1_tunnel(item.transfer.ul);
        for (const auto& drb : s.drbs) {
            e1ap::DrbToSetup d;
            d.drb_id = drb.id;
            d.default_drb = drb.default_drb;
            // The PDCP timers of the PDCP-Config the UE gets (rrc::PdcpSettings): the CU-UP's
            // entity runs with the same (P2 Q5); t-Reordering the topology's (P2 Q8).
            d.t_reordering_ms = cfg_.t_reordering_ms;
            for (const auto& f : drb.flows) {
                d.flows.push_back(e1_flow(f));
            }
            t.drbs.push_back(std::move(d));
        }
        up.push_back(std::move(t));
        j.pending.emplace(item.psi, std::move(s));
    }
    if (j.pending.empty()) {
        job_failed(ue, "radioNetwork", "unspecified");
        return;
    }
    j.stage = Ue::Job::Stage::e1;
    if (ue.cu_up_ue) {
        send_e1(e1ap::BearerContextModificationRequest{ue.cu_ue, *ue.cu_up_ue, std::move(up), {}, {}}, true);
        return;
    }
    const std::uint8_t nea = ue.nea.value_or(0);
    const std::uint8_t nia = ue.nia.value_or(0);
    auto ke = crypto::keys5g::algorithm_key(ue.kgnb, AlgType::up_enc, nea);
    auto ki = crypto::keys5g::algorithm_key(ue.kgnb, AlgType::up_int, nia);
    if (!ke || !ki) {
        job_failed(ue, "radioNetwork", "unspecified");
        return;
    }
    e1ap::BearerContextSetupRequest r;
    r.cu_cp_ue = ue.cu_ue;
    // The UP keys cross the E1AP codec as octets (rule R3), wiped once encoded.
    r.security = e1ap::Security{nea, nia, Bytes(ke->expose().begin(), ke->expose().end()),
                                Bytes(ki->expose().begin(), ki->expose().end())};
    r.ue_dl_ambr = ue.ue_ambr ? ue.ue_ambr->dl : 1'000'000'000;
    r.serving_plmn = e1ap::plmn_id(cfg_.plmn.mcc, cfg_.plmn.mnc);
    r.activity_level = "ue";
    r.ue_inactivity_s = cfg_.ue_inactivity_s;
    r.sessions = std::move(up);
    send_e1(r, true);
    secure_zero(r.security.enc_key);
    if (r.security.int_key) {
        secure_zero(*r.security.int_key);
    }
}

void CuCp::handle(const e1ap::BearerContextSetupResponse& m) {
    Ue* ue = by_cu(m.cu_cp_ue);
    if (ue == nullptr || ue->jobs.empty() || ue->jobs.front().stage != Ue::Job::Stage::e1) {
        return;
    }
    ue->cu_up_ue = m.cu_up_ue;
    e1ap::BearerContextModificationResponse as_mod{m.cu_cp_ue, m.cu_up_ue, m.sessions, {}};
    handle(as_mod);
}

void CuCp::handle(const e1ap::BearerContextModificationResponse& m) {
    Ue* ue = by_cu(m.cu_cp_ue);
    if (ue == nullptr || ue->jobs.empty()) {
        return;
    }
    Ue::Job& j = ue->jobs.front();
    if (j.stage == Ue::Job::Stage::e1_mod) {
        job_rrc(*ue);
        return;
    }
    if (j.stage != Ue::Job::Stage::e1) {
        return;
    }
    if (j.kind == Ue::Job::Kind::modify) {
        modify_e1_done(*ue, m);
        return;
    }
    for (const auto& s : m.added) {
        auto it = j.pending.find(s.psi);
        if (it == j.pending.end()) {
            continue;
        }
        it->second.ng_dl = s.ng_dl;
        for (auto& d : it->second.drbs) {
            for (const auto& u : s.drbs) {
                if (u.drb_id == d.id) {
                    d.f1u_ul = u.f1u_ul;
                }
            }
        }
    }
    f1ap::UeContextModificationRequest r;
    r.cu_ue = ue->cu_ue;
    r.du_ue = ue->du_ue;
    const rrc::PdcpSettings pdcp;   // the DRBs' PDCP-Config towards the UE
    for (auto it = j.pending.begin(); it != j.pending.end();) {
        const auto& item = it->second.item;
        const bool complete = it->second.ng_dl && std::all_of(it->second.drbs.begin(), it->second.drbs.end(),
                                                              [](const Ue::Drb& d) { return d.f1u_ul.has_value(); });
        if (!complete) {
            j.failed.push_back(ngap::SessionCause{it->first, ngap::Cause{"radioNetwork", "unspecified"}});
            it = j.pending.erase(it);
            continue;
        }
        for (const auto& drb : it->second.drbs) {
            f1ap::DrbToSetup d;
            d.drb_id = drb.id;
            d.snssai = f1ap::Snssai{item.snssai.sst, item.snssai.sd};
            for (const auto& f : drb.flows) {
                d.flows.push_back(f1_flow(f));
            }
            d.ul = f1_tunnel(drb.f1u_ul.value_or(e1ap::GtpTunnel{}));   // set: the session is complete
            d.dl_pdcp_sn_bits = pdcp.sn18_dl ? 18 : 12;
            d.ul_pdcp_sn_bits = static_cast<std::uint8_t>(pdcp.sn18_ul ? 18 : 12);
            r.drbs.push_back(std::move(d));
        }
        ++it;
    }
    if (r.drbs.empty()) {
        job_failed(*ue, "radioNetwork", "unspecified");
        return;
    }
    j.stage = Ue::Job::Stage::f1;
    send_f1(r, true);
}

void CuCp::handle(const f1ap::UeContextModificationResponse& m) {
    Ue* ue = by_cu(m.cu_ue);
    if (ue == nullptr || ue->jobs.empty() || ue->jobs.front().stage != Ue::Job::Stage::f1) {
        return;
    }
    Ue::Job& j = ue->jobs.front();
    if (m.cell_group) {
        if (auto cg = rrc::decode_cell_group(*m.cell_group)) {
            j.cell_group = std::move(*cg);
        }
    }
    e1ap::BearerContextModificationRequest r;
    r.cu_cp_ue = ue->cu_ue;
    r.cu_up_ue = ue->cu_up_ue.value_or(0);
    if (j.kind == Ue::Job::Kind::modify) {
        // P2 Q10: the DU's F1-U ends of the DRBs the modification added go to the CU-UP.
        for (auto& [psi, c] : j.changes) {
            e1ap::SessionToModify sm;
            sm.psi = psi;
            for (auto& d : c.after.drbs) {
                if (std::find(c.added.begin(), c.added.end(), d.id) == c.added.end()) {
                    continue;
                }
                for (const auto& x : m.drbs) {
                    if (x.drb_id == d.id) {
                        d.du = x;
                        sm.drbs.push_back(e1ap::DrbToModify{d.id, e1_from_f1(x.dl), std::nullopt});
                    }
                }
            }
            if (!sm.drbs.empty()) {
                r.modify.push_back(std::move(sm));
            }
        }
        if (r.modify.empty()) {
            job_rrc(*ue);
            return;
        }
        j.stage = Ue::Job::Stage::e1_mod;
        send_e1(r, true);
        return;
    }
    for (auto& [psi, s] : j.pending) {
        e1ap::SessionToModify sm;
        sm.psi = psi;
        for (auto& drb : s.drbs) {
            for (const auto& d : m.drbs) {
                if (d.drb_id == drb.id) {
                    drb.du = d;
                    sm.drbs.push_back(e1ap::DrbToModify{d.drb_id, e1_from_f1(d.dl), std::nullopt});
                }
            }
        }
        if (!sm.drbs.empty()) {
            r.modify.push_back(std::move(sm));
        }
    }
    if (r.modify.empty() || !ue->cu_up_ue) {
        job_failed(*ue, "radioNetwork", "unspecified");
        return;
    }
    j.stage = Ue::Job::Stage::e1_mod;
    send_e1(r, true);
}

// ---- PDU SESSION RESOURCE MODIFY (P2 Q10) ----------------------------------------------------

void CuCp::start_modify(Ue& ue) {
    Ue::Job& j = ue.jobs.front();
    std::set<std::uint8_t> used = drbs_in_use(ue);
    std::uint64_t gbr_load = gbr_used();   // P2 Q11
    for (const auto& item : j.modify) {
        auto it = ue.sessions.find(item.psi);
        if (it == ue.sessions.end()) {
            j.failed.push_back(ngap::SessionCause{item.psi, ngap::Cause{"radioNetwork", "unknown-PDU-session-ID"}});
            continue;
        }
        Ue::Job::Change c;
        c.after = it->second;
        c.nas = item.nas;
        if (const auto& a = item.transfer.session_ambr) {
            c.dl_ambr = a->dl;
            c.after.item.transfer.session_ambr = a;
        }
        auto& flows = c.after.item.transfer.flows;
        auto find_drb = [&c](std::uint8_t id) -> Ue::Drb* {
            for (auto& d : c.after.drbs) {
                if (d.id == id) {
                    return &d;
                }
            }
            return nullptr;
        };
        auto drb_of = [&c](std::uint8_t qfi) -> Ue::Drb* {
            for (auto& d : c.after.drbs) {
                for (const auto& f : d.flows) {
                    if (f.qfi == qfi) {
                        return &d;
                    }
                }
            }
            return nullptr;
        };
        auto is_new = [&c](std::uint8_t id) { return std::find(c.added.begin(), c.added.end(), id) != c.added.end(); };
        // A flow off its DRB; noted for the UE unless the DRB is new.
        auto unmap = [&](std::uint8_t qfi) {
            Ue::Drb* d = drb_of(qfi);
            if (d == nullptr) {
                return;
            }
            d->flows.erase(std::remove_if(d->flows.begin(), d->flows.end(), [qfi](const auto& f) { return f.qfi == qfi; }),
                           d->flows.end());
            if (!is_new(d->id)) {
                c.remapped[d->id].second.push_back(qfi);
            }
        };
        for (std::uint8_t q : item.transfer.release) {
            for (const auto& f : flows) {
                if (f.qfi == q) {
                    gbr_load -= std::min(gbr_load, gbr_need(f));   // P2 Q11: its GFBR is free again
                }
            }
            flows.erase(std::remove_if(flows.begin(), flows.end(), [q](const auto& f) { return f.qfi == q; }), flows.end());
            unmap(q);
        }
        for (auto f : item.transfer.add_or_modify) {
            if (KSIM_MUTANT("gbr_as_nongbr")) {
                f.gbr.reset();
            }
            auto fl = std::find_if(flows.begin(), flows.end(), [&f](const auto& x) { return x.qfi == f.qfi; });
            const std::uint64_t before = fl != flows.end() ? gbr_need(*fl) : 0;
            // P2 Q11: a GBR flow added, or one asking a higher GFBR, is admitted against the budget.
            if (gbr_need(f) > before && !admit(gbr_load - std::min(gbr_load, before), f)) {
                c.failed.push_back(ngap::QosFlowCause{f.qfi, ngap::Cause{"radioNetwork", "radio-resources-not-available"}});
                events_.emit("ran.gbr.refused", cfg_.id,
                             {{"ran_ue", str(ue.ran_ue)}, {"psi", str(item.psi)}, {"qfi", str(f.qfi)},
                              {"need", std::to_string(gbr_need(f))}, {"budget", std::to_string(cfg_.gbr_budget_bps)}});
                continue;
            }
            Ue::Drb* cur = drb_of(f.qfi);
            const bool stays = fl != flows.end() && cur != nullptr && cur->gbr == f.gbr.has_value() &&
                               (cur->gbr || one_drb() || cur->five_qi == f.five_qi);
            if (stays) {
                // Modified where it is: its QoS parameters change, its DRB stays.
                *fl = f;
                for (auto& x : cur->flows) {
                    if (x.qfi == f.qfi) {
                        x = f;
                    }
                }
                if (!is_new(cur->id)) {
                    (void)c.remapped[cur->id];
                }
                gbr_load = gbr_load - std::min(gbr_load, before) + gbr_need(f);
                c.ok.push_back(f.qfi);
                continue;
            }
            // Where it goes: its 5QI's DRB, or a new one (a GBR flow's always its own). The
            // DRB ID is found first, so a flow that cannot move stays where it was.
            Ue::Drb* d = f.gbr ? nullptr : drb_for(c.after, f.five_qi);
            std::optional<std::uint8_t> fresh_id;
            if (d == nullptr) {
                fresh_id = take_drb(used);
                if (!fresh_id) {
                    c.failed.push_back(ngap::QosFlowCause{f.qfi, ngap::Cause{"radioNetwork", "radio-resources-not-available"}});
                    continue;
                }
            }
            if (fl != flows.end()) {
                flows.erase(fl);   // a new 5QI: the flow moves to that 5QI's DRB
            }
            unmap(f.qfi);
            if (fresh_id) {
                Ue::Drb fresh;
                fresh.id = *fresh_id;
                fresh.five_qi = f.five_qi;
                fresh.gbr = f.gbr.has_value();
                fresh.default_drb = c.after.drbs.empty();
                c.after.drbs.push_back(std::move(fresh));
                c.added.push_back(*fresh_id);
                d = find_drb(*fresh_id);
            }
            d->flows.push_back(f);
            flows.push_back(f);
            if (!is_new(d->id)) {
                c.remapped[d->id].first.push_back(f.qfi);
            }
            gbr_load = gbr_load - std::min(gbr_load, before) + gbr_need(f);
            c.ok.push_back(f.qfi);
        }
        // A DRB left with no flow goes (TS 37.324 5.3: a DRB carries at least one).
        for (auto d = c.after.drbs.begin(); d != c.after.drbs.end();) {
            if (!d->flows.empty()) {
                ++d;
                continue;
            }
            if (is_new(d->id)) {
                c.added.erase(std::find(c.added.begin(), c.added.end(), d->id));
            } else {
                c.removed.push_back(d->id);
                c.remapped.erase(d->id);
            }
            d = c.after.drbs.erase(d);
        }
        j.changes.emplace(item.psi, std::move(c));
    }
    // E1 first: the CU-UP's DRBs set up, remapped and removed, and the session-AMBR.
    e1ap::BearerContextModificationRequest r;
    r.cu_cp_ue = ue.cu_ue;
    r.cu_up_ue = ue.cu_up_ue.value_or(0);
    for (auto& [psi, c] : j.changes) {
        e1ap::SessionToModify sm;
        sm.psi = psi;
        sm.dl_ambr = c.dl_ambr;
        for (const auto& d : c.after.drbs) {
            std::vector<e1ap::QosFlow> fl;
            fl.reserve(d.flows.size());
            for (const auto& f : d.flows) {
                fl.push_back(e1_flow(f));
            }
            if (is_in(c.added, d.id)) {
                e1ap::DrbToSetup x;
                x.drb_id = d.id;
                x.default_drb = d.default_drb;
                x.t_reordering_ms = cfg_.t_reordering_ms;
                x.flows = std::move(fl);
                sm.drbs_setup.push_back(std::move(x));
            } else if (c.remapped.count(d.id) != 0) {
                sm.drbs.push_back(e1ap::DrbToModify{d.id, std::nullopt, std::move(fl)});
            }
        }
        sm.drbs_remove = c.removed;
        if (sm.dl_ambr || !sm.drbs_setup.empty() || !sm.drbs.empty() || !sm.drbs_remove.empty()) {
            r.modify.push_back(std::move(sm));
        }
    }
    if (r.modify.empty()) {
        modify_f1(ue);   // nothing for the CU-UP
        return;
    }
    if (!ue.cu_up_ue || e1_ == nullptr || !e1_ready_) {
        job_failed(ue, "radioNetwork", "unspecified");
        return;
    }
    j.stage = Ue::Job::Stage::e1;
    send_e1(r, true);
}

void CuCp::modify_e1_done(Ue& ue, const e1ap::BearerContextModificationResponse& m) {
    Ue::Job& j = ue.jobs.front();
    for (const auto& s : m.modified) {
        auto c = j.changes.find(s.psi);
        if (c == j.changes.end()) {
            continue;
        }
        for (auto& d : c->second.after.drbs) {
            for (const auto& u : s.drbs_setup) {
                if (u.drb_id == d.id) {
                    d.f1u_ul = u.f1u_ul;
                }
            }
        }
    }
    for (const auto& [psi, c] : j.changes) {
        for (const auto& d : c.after.drbs) {
            if (is_in(c.added, d.id) && !d.f1u_ul) {
                job_failed(ue, "radioNetwork", "unspecified");   // the CU-UP set up no F1-U end for it
                return;
            }
        }
    }
    modify_f1(ue);
}

void CuCp::modify_f1(Ue& ue) {
    Ue::Job& j = ue.jobs.front();
    f1ap::UeContextModificationRequest r;
    r.cu_ue = ue.cu_ue;
    r.du_ue = ue.du_ue;
    const rrc::PdcpSettings pdcp;
    for (const auto& [psi, c] : j.changes) {
        const auto& item = c.after.item;
        for (const auto& drb : c.after.drbs) {
            const bool fresh = is_in(c.added, drb.id);
            if (!fresh && c.remapped.count(drb.id) == 0) {
                continue;
            }
            f1ap::DrbToSetup d;
            d.drb_id = drb.id;
            d.snssai = f1ap::Snssai{item.snssai.sst, item.snssai.sd};
            for (const auto& f : drb.flows) {
                d.flows.push_back(f1_flow(f));
            }
            d.ul = f1_tunnel(drb.f1u_ul.value_or(e1ap::GtpTunnel{}));   // none: the DU keeps the end it has
            if (fresh) {
                d.dl_pdcp_sn_bits = pdcp.sn18_dl ? 18 : 12;
                d.ul_pdcp_sn_bits = static_cast<std::uint8_t>(pdcp.sn18_ul ? 18 : 12);
                r.drbs.push_back(std::move(d));
            } else {
                d.ul_pdcp_sn_bits.reset();
                r.modify_drbs.push_back(std::move(d));
            }
        }
        r.release_drbs.insert(r.release_drbs.end(), c.removed.begin(), c.removed.end());
    }
    if (r.drbs.empty() && r.modify_drbs.empty() && r.release_drbs.empty()) {
        job_rrc(ue);   // the AMBR alone, or nothing: the UE gets its NAS
        return;
    }
    j.stage = Ue::Job::Stage::f1;
    send_f1(r, true);
}

void CuCp::job_rrc(Ue& ue) {
    Ue::Job& j = ue.jobs.front();
    rrc::Reconfiguration r;
    rrc::RadioBearers b;
    const auto drb_add = [this](const Ue::Session& s, const Ue::Drb& drb, std::uint8_t psi) {
        rrc::DrbAdd d;
        d.drb_id = drb.id;
        d.pdu_session = psi;
        d.sdap_header_dl = true;
        d.sdap_header_ul = true;
        d.default_drb = drb.default_drb;
        for (const auto& f : drb.flows) {
            d.qfis.push_back(f.qfi);
        }
        d.pdcp.integrity = s.integrity;
        d.pdcp.ciphering_disabled = !s.confidentiality;   // P2 Q9: TS 38.331 cipheringDisabled
        d.pdcp.t_reordering_ms = cfg_.t_reordering_ms;   // P2 Q8: as the CU-UP's entity runs it (E1)
        return d;
    };
    if (j.kind == Ue::Job::Kind::modify) {
        // P2 Q10: the new DRBs, the mappings that changed, the DRBs that go; the sessions' NAS.
        for (const auto& [psi, c] : j.changes) {
            for (const auto& drb : c.after.drbs) {
                if (is_in(c.added, drb.id)) {
                    b.drbs.push_back(drb_add(c.after, drb, psi));
                    continue;
                }
                auto m = c.remapped.find(drb.id);
                if (m == c.remapped.end() || (m->second.first.empty() && m->second.second.empty())) {
                    continue;   // its flows' QoS changed, not the mapping: nothing for the UE
                }
                rrc::DrbAdd d;
                d.drb_id = drb.id;
                d.pdu_session = psi;
                d.sdap_header_dl = true;
                d.sdap_header_ul = true;
                d.default_drb = drb.default_drb;
                d.qfis = m->second.first;
                // A flow moved to another DRB of the session is the new DRB's (TS 37.324 5.3.1).
                for (std::uint8_t q : m->second.second) {
                    const bool moved = std::any_of(c.after.drbs.begin(), c.after.drbs.end(), [q](const Ue::Drb& o) {
                        return std::any_of(o.flows.begin(), o.flows.end(), [q](const auto& f) { return f.qfi == q; });
                    });
                    if (!moved) {
                        d.qfis_release.push_back(q);
                    }
                }
                d.setup = false;
                if (!d.qfis.empty() || !d.qfis_release.empty()) {
                    b.drbs.push_back(std::move(d));
                }
            }
            b.drb_release.insert(b.drb_release.end(), c.removed.begin(), c.removed.end());
        }
        std::vector<Bytes> nas;
        for (const auto& [psi, c] : j.changes) {
            if (c.nas) {
                nas.push_back(*c.nas);
            }
        }
        if (b.drbs.empty() && b.drb_release.empty() && !j.cell_group) {
            // Nothing for the radio (the AMBR, a flow's QoS): the NAS goes on its own.
            for (const auto& n : nas) {
                dl_dcch(ue, rrc::encode(rrc::DlInformationTransfer{next_tid(ue), n}), ue.srb2 ? 2 : 1);
            }
            job_done(ue);
            return;
        }
        r.tid = next_tid(ue);
        r.nas = std::move(nas);
        r.bearers = b;
        r.cell_group = j.cell_group;
        j.stage = Ue::Job::Stage::rrc;
        dl_dcch(ue, rrc::encode(r), ue.srb2 ? 2 : 1);
        return;
    }
    r.tid = next_tid(ue);
    for (const auto& [psi, s] : j.pending) {
        for (const auto& drb : s.drbs) {
            b.drbs.push_back(drb_add(s, drb, psi));
        }
        if (s.item.nas) {
            r.nas.push_back(*s.item.nas);
        }
    }
    if (j.nas) {
        r.nas.push_back(*j.nas);
    }
    r.bearers = b;
    r.cell_group = j.cell_group;
    j.stage = Ue::Job::Stage::rrc;
    dl_dcch(ue, rrc::encode(r), ue.srb2 ? 2 : 1);
}

void CuCp::modify_done(Ue& ue, Ue::Job j) {
    ngap::PduSessionResourceModifyResponse resp{ue.amf_ue.value_or(0), ue.ran_ue, {}, std::move(j.failed)};
    ngap::PduSessionResourceNotify notify{ue.amf_ue.value_or(0), ue.ran_ue, {}, {}};
    for (auto& [psi, c] : j.changes) {
        std::vector<std::uint8_t> released;
        for (const auto& item : j.modify) {
            if (item.psi == psi) {
                released = item.transfer.release;
            }
        }
        events_.emit("ran.session.modify", cfg_.id,
                     {{"ran_ue", str(ue.ran_ue)}, {"psi", str(psi)}, {"drbs", drb_list(c.after.drbs)},
                      {"added", qfi_list(c.ok)}, {"released", qfi_list(released)},
                      {"drbs_added", qfi_list(c.added)}, {"drbs_removed", qfi_list(c.removed)},
                      {"failed", str(static_cast<std::int64_t>(c.failed.size()))}, {"by", j.notify ? "gnb" : "amf"}});
        if (j.notify) {
            ngap::NotifyTransfer t;
            for (std::uint8_t q : released) {
                t.released.push_back(ngap::QosFlowCause{q, ngap::Cause{"radioNetwork", "release-due-to-ngran-generated-reason"}});
            }
            notify.sessions.push_back(ngap::SessionNotify{psi, std::move(t)});
        } else {
            resp.sessions.push_back(ngap::SessionModifyOk{psi, ngap::ModifyResponseTransfer{c.ok, c.failed}});
        }
        ue.sessions[psi] = std::move(c.after);
    }
    if (!ue.amf_ue) {
        return;
    }
    if (j.notify) {
        if (!notify.sessions.empty()) {
            send_ngap(notify, ue.ran_ue);
        }
        return;
    }
    send_ngap(resp, ue.ran_ue);
}

void CuCp::job_done(Ue& ue) {
    Ue::Job j = std::move(ue.jobs.front());
    ue.jobs.pop_front();
    if (j.kind == Ue::Job::Kind::modify) {
        modify_done(ue, std::move(j));
        reassess_gbr();   // P2 Q11: GFBR freed or taken may change what others get
        start_job(ue);
        return;
    }
    if (j.kind == Ue::Job::Kind::release) {
        std::vector<std::uint8_t> released;
        f1ap::UeContextModificationRequest f1;
        f1.cu_ue = ue.cu_ue;
        f1.du_ue = ue.du_ue;
        std::vector<std::uint8_t> remove;
        for (const auto& s : j.release) {
            auto it = ue.sessions.find(s.psi);
            if (it == ue.sessions.end()) {
                continue;
            }
            for (const auto& d : it->second.drbs) {
                f1.release_drbs.push_back(d.id);
            }
            remove.push_back(s.psi);
            released.push_back(s.psi);
            ue.sessions.erase(it);
            events_.emit("ran.session.release", cfg_.id, {{"ran_ue", str(ue.ran_ue)}, {"psi", str(s.psi)}});
        }
        if (!f1.release_drbs.empty()) {
            send_f1(f1, true);
        }
        if (ue.cu_up_ue) {
            if (ue.sessions.empty()) {
                send_e1(e1ap::BearerContextReleaseCommand{ue.cu_ue, *ue.cu_up_ue, e1ap::Cause{"radioNetwork", "normal-release"}}, true);
                ue.cu_up_ue.reset();
            } else if (!remove.empty()) {
                send_e1(e1ap::BearerContextModificationRequest{ue.cu_ue, *ue.cu_up_ue, {}, {}, remove}, true);
            }
        }
        if (ue.amf_ue) {
            if (released.empty()) {
                released.push_back(j.release.empty() ? 1 : j.release.front().psi);   // nothing held: answered as released
            }
            send_ngap(ngap::PduSessionResourceReleaseResponse{*ue.amf_ue, ue.ran_ue, released}, ue.ran_ue);
        }
        reassess_gbr();   // P2 Q11
        start_job(ue);
        return;
    }
    std::vector<ngap::SessionSetupOk> ok;
    for (auto& [psi, s] : j.pending) {
        ngap::SetupResponseTransfer t;
        if (s.ng_dl) {
            t.dl = ng_tunnel(*s.ng_dl);
        }
        for (const auto& f : s.item.transfer.flows) {
            t.qfis.push_back(f.qfi);
        }
        if (s.report) {
            // TS 38.413 8.2.1.2: what was done with a "preferred" (9.3.1.59).
            t.security = ngap::SecurityResult{s.integrity != KSIM_MUTANT("up_result_misreported"), s.confidentiality};
        }
        t.failed = s.refused;   // P2 Q11: GBR flows not admitted
        ok.push_back(ngap::SessionSetupOk{psi, std::move(t)});
        events_.emit("ran.session.setup", cfg_.id,
                     {{"ran_ue", str(ue.ran_ue)}, {"psi", str(psi)}, {"drb", str(s.drbs.empty() ? 0 : s.drbs.front().id)},
                      {"drbs", drb_list(s.drbs)}, {"integrity", s.integrity ? "1" : "0"},
                      {"confidentiality", s.confidentiality ? "1" : "0"}});
        ue.sessions.emplace(psi, std::move(s));
    }
    if (j.ics) {
        finish_ics(ue, std::move(ok), std::move(j.failed));
    } else if (ue.amf_ue) {
        send_ngap(ngap::PduSessionResourceSetupResponse{*ue.amf_ue, ue.ran_ue, std::move(ok), std::move(j.failed)}, ue.ran_ue);
    }
    start_job(ue);
}

void CuCp::job_failed(Ue& ue, const char* group, const char* value) {
    if (ue.jobs.empty()) {
        return;
    }
    Ue::Job j = std::move(ue.jobs.front());
    ue.jobs.pop_front();
    if (j.kind == Ue::Job::Kind::setup) {
        for (const auto& item : j.items) {
            const bool listed = std::any_of(j.failed.begin(), j.failed.end(), [&](const auto& f) { return f.psi == item.psi; });
            if (!listed) {
                j.failed.push_back(ngap::SessionCause{item.psi, ngap::Cause{group, value}});
            }
        }
        events_.emit("ran.session.failure", cfg_.id, {{"ran_ue", str(ue.ran_ue)}, {"cause", std::string(group) + "/" + value}});
        if (j.ics) {
            finish_ics(ue, {}, std::move(j.failed));
        } else if (ue.amf_ue) {
            send_ngap(ngap::PduSessionResourceSetupResponse{*ue.amf_ue, ue.ran_ue, {}, std::move(j.failed)}, ue.ran_ue);
        }
    } else if (j.kind == Ue::Job::Kind::modify) {
        // P2 Q10: the sessions stay as they were set up (TS 38.413 8.2.3.2: Failed to Modify List).
        events_.emit("ran.session.modify_failure", cfg_.id,
                     {{"ran_ue", str(ue.ran_ue)}, {"cause", std::string(group) + "/" + value}});
        if (ue.amf_ue && !j.notify) {
            for (const auto& item : j.modify) {
                const bool listed = std::any_of(j.failed.begin(), j.failed.end(), [&](const auto& f) { return f.psi == item.psi; });
                if (!listed) {
                    j.failed.push_back(ngap::SessionCause{item.psi, ngap::Cause{group, value}});
                }
            }
            send_ngap(ngap::PduSessionResourceModifyResponse{*ue.amf_ue, ue.ran_ue, {}, std::move(j.failed)}, ue.ran_ue);
        }
    }
    start_job(ue);
}

void CuCp::finish_ics(Ue& ue, std::vector<ngap::SessionSetupOk> ok, std::vector<ngap::SessionCause> failed) {
    if (!ue.amf_ue) {
        return;
    }
    ++stats_.ics_ok;
    events_.emit("ran.ics.complete", cfg_.id, {{"ran_ue", str(ue.ran_ue)}});
    send_ngap(ngap::InitialContextSetupResponse{*ue.amf_ue, ue.ran_ue, std::move(ok), std::move(failed)}, ue.ran_ue);
}

} // namespace ksim::proc::ran
