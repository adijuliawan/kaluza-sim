// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "ngap_amf.hpp"

#include <algorithm>
#include <utility>

#include "codec/nas/build.hpp"
#include "uicc/image/image.hpp"

namespace ksim::corestub {

namespace {

constexpr std::uint32_t kNgapPpid = 60;

template <class... F>
struct Overload : F... {
    using F::operator()...;
};
template <class... F>
Overload(F...) -> Overload<F...>;

/// The NR algorithm maps of TS 38.413 §9.3.1.86 from a NAS UE security
/// capability: 128-NEA1/NIA1 in the top bit, then 2 and 3.
std::uint16_t nr_map(std::uint8_t nas_bits) {
    std::uint16_t out = 0;
    for (unsigned n = 1; n <= 3; ++n) {
        if ((nas_bits & (0x80U >> n)) != 0) {
            out = static_cast<std::uint16_t>(out | (0x8000U >> (n - 1)));
        }
    }
    return out;
}

const char* name_of(const ngap::Pdu& p) {
    return std::visit(Overload{
                          [](const ngap::NgSetupRequest&) { return "NGSetupRequest"; },
                          [](const ngap::InitialUeMessage&) { return "InitialUEMessage"; },
                          [](const ngap::UplinkNasTransport&) { return "UplinkNASTransport"; },
                          [](const ngap::InitialContextSetupResponse&) { return "InitialContextSetupResponse"; },
                          [](const ngap::InitialContextSetupFailure&) { return "InitialContextSetupFailure"; },
                          [](const ngap::UeContextReleaseComplete&) { return "UEContextReleaseComplete"; },
                          [](const ngap::UeContextReleaseRequest&) { return "UEContextReleaseRequest"; },
                          [](const ngap::UeRadioCapabilityInfoIndication&) { return "UERadioCapabilityInfoIndication"; },
                          [](const ngap::ErrorIndication&) { return "ErrorIndication"; },
                          [](const ngap::NgResetAcknowledge&) { return "NGResetAcknowledge"; },
                          [](const ngap::NasNonDeliveryIndication&) { return "NASNonDeliveryIndication"; },
                          [](const ngap::UeContextModificationResponse&) { return "UEContextModificationResponse"; },
                          [](const ngap::AmfConfigurationUpdateAcknowledge&) { return "AMFConfigurationUpdateAcknowledge"; },
                          [](const ngap::PduSessionResourceSetupResponse&) { return "PDUSessionResourceSetupResponse"; },
                          [](const ngap::PduSessionResourceReleaseResponse&) { return "PDUSessionResourceReleaseResponse"; },
                          [](const ngap::PduSessionResourceModifyResponse&) { return "PDUSessionResourceModifyResponse"; },
                          [](const ngap::PduSessionResourceNotify&) { return "PDUSessionResourceNotify"; },
                          [](const ngap::RanConfigurationUpdate&) { return "RANConfigurationUpdate"; },
                          [](const auto&) { return "other"; },
                      },
                      p);
}

} // namespace

NgapAmf::NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, IAssoc& ng, IDatagram* n3,
                 std::array<std::uint8_t, 4> n3_addr)
    : NgapAmf(ex, home, std::move(plmn), std::move(p), std::make_unique<SingleAssocPool>(ng), nullptr, n3, n3_addr) {}

NgapAmf::NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, IAssocPool& ng, IDatagram* n3,
                 std::array<std::uint8_t, 4> n3_addr)
    : NgapAmf(ex, home, std::move(plmn), std::move(p), nullptr, &ng, n3, n3_addr) {}

NgapAmf::NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, std::unique_ptr<IAssocPool> own, IAssocPool* ng,
                 IDatagram* n3, std::array<std::uint8_t, 4> n3_addr)
    : ex_(ex), home_(home), plmn_(std::move(plmn)), p_(std::move(p)), own_ng_(std::move(own)),
      ng_(ng != nullptr ? ng : own_ng_.get()),
      upf_(n3 != nullptr ? std::make_unique<Upf>(*n3, n3_addr) : nullptr), smf_(p_.session, upf_.get()),
      smsf_(Smsf::Link{
                [this](const std::string& msisdn) {
                    // The sim range's MSISDN is 999 and the MSIN's last eight digits (image.hpp).
                    for (const auto& s : home_.supis()) {
                        if (auto r = uicc::image::range_subscriber(s); r && r->msisdn == msisdn) {
                            return s;
                        }
                    }
                    return std::string();
                },
                [](const std::string& supi) {
                    auto r = uicc::image::range_subscriber(supi);
                    return r ? r->msisdn : std::string();
                },
                [this](const std::string& supi, Bytes cp) {
                    Amf* a = nas_by_supi(supi);
                    return a != nullptr && a->send_sms(std::move(cp));
                },
                [this](const std::string& supi) { page(supi); },
                [this] { return static_cast<std::uint64_t>(ex_.now()); }},
            p_.sms_sc) {
    wire_ng();
    smf_.on_page([this](const std::string& supi, std::uint8_t) { page(supi); });
}

void NgapAmf::wire_ng() {
    ng_->set_handlers(
        [this](LinkId link, ByteView msg, SctpMeta) {
            rx_link_ = link;
            on_message(msg);
        },
        [this](LinkId link, LinkEvent e) { on_ng_event(link, e); });
}

bool NgapAmf::serves(std::uint32_t tac) const {
    return p_.tacs.empty() ? tac == 1 : std::find(p_.tacs.begin(), p_.tacs.end(), tac) != p_.tacs.end();
}

std::vector<std::uint32_t> NgapAmf::gnb_tacs(std::uint32_t gnb_id) const {
    for (const auto& [link, g] : gnbs_) {
        if (g.gnb_id == gnb_id) {
            return g.tacs;
        }
    }
    return {};
}

std::vector<std::pair<std::uint32_t, std::vector<std::uint32_t>>> NgapAmf::gnb_list() const {
    std::vector<std::pair<std::uint32_t, std::vector<std::uint32_t>>> out;
    out.reserve(gnbs_.size());
    for (const auto& [link, g] : gnbs_) {
        out.emplace_back(g.gnb_id, g.tacs);
    }
    return out;
}

void NgapAmf::set_sms_subscribed(const std::string& supi, bool on) { sms_sub_[supi] = on; }

void NgapAmf::on_ng_event(LinkId link, LinkEvent e) {
    if (e == LinkEvent::shutdown) {
        ng_end_ = "shutdown";
    } else if (e == LinkEvent::lost) {
        ng_end_ = "lost";
    }
    if ((e == LinkEvent::shutdown || e == LinkEvent::lost) && own_ng_ == nullptr) {
        // P3 R2: with several gNBs, the one that went takes its UEs' N2 connections with it
        // (one gNB's go at its next association, rebind()).
        for (auto& [id, ue] : ues_) {
            if (ue.link == link && ue.connected) {
                drop_n2(ue);
            }
        }
        gnbs_.erase(link);
    }
}

void NgapAmf::command_release(std::uint64_t amf_ue, const ngap::Cause& cause) {
    const Ue* now = by_amf(amf_ue);
    const std::uint32_t ran = now != nullptr ? now->ran_ue : 0;
    // Late, the command is for the NG connection it was meant for: not one released meanwhile
    // (by the other command) or a new one.
    const auto send_it = [this, amf_ue, ran, cause] {
        if (Ue* u = by_amf(amf_ue); u != nullptr && u->connected && !u->releasing && u->ran_ue == ran) {
            u->releasing = true;
            send_ue(*u, ngap::UeContextReleaseCommand{u->amf_ue, u->ran_ue, cause});
        }
    };
    if (release_delay_ <= 0) {
        send_it();
        return;
    }
    (void)ex_.start_timer(release_delay_, send_it);
}

std::optional<Bytes> NgapAmf::radio_capability(std::uint64_t amf_ue) {
    Ue* u = by_amf(amf_ue);
    return u != nullptr ? u->radio_capability : std::nullopt;
}

void NgapAmf::rebind(IAssoc& ng) {
    own_ng_ = std::make_unique<SingleAssocPool>(ng);
    ng_ = own_ng_.get();
    wire_ng();
    gnbs_.clear();
    ng_setup_ = false;
    for (auto& [id, ue] : ues_) {
        drop_n2(ue);
    }
}

void NgapAmf::drop_n2(Ue& ue) {
    if (!ue.connected) {
        return;
    }
    ue.connected = false;
    ue.releasing = false;
    ue.asked = false;
    ue.setups.clear();
    ue.releases.clear();
    ue.nas->on_ue_released();
    smf_.deactivate(ue.nas->supi());
}

void NgapAmf::status_indication() {
    const ngap::PlmnId plmn = ngap::plmn_id(plmn_.mcc, plmn_.mnc);
    for (const auto& [link, g] : gnbs_) {
        send_to(link, ngap::AmfStatusIndication{{ngap::Guami{plmn, p_.amf_region, p_.amf_set, p_.amf_pointer}}}, 0);
    }
}

bool NgapAmf::deregister(const std::string& supi, bool reregistration_required) {
    Amf* a = nas_by_supi(supi);
    return a != nullptr && a->network_deregister(reregistration_required);
}

void NgapAmf::set_t3512(std::optional<int> seconds) {
    p_.t3512_s = seconds;
    for (auto& [id, ue] : ues_) {
        ue.nas->profile().t3512_s = seconds;
    }
}

void NgapAmf::set_nas_algorithms(std::uint8_t ea, std::uint8_t ia) {
    p_.ea = ea;
    p_.ia = ia;
    for (auto& [id, ue] : ues_) {
        ue.nas->profile().ea = ea;
        ue.nas->profile().ia = ia;
    }
}

void NgapAmf::page(const std::string& supi) {
    Ue* ue = nullptr;
    for (auto it = order_.rbegin(); it != order_.rend(); ++it) {
        Ue* u = by_amf(*it);
        if (u != nullptr && u->nas->supi() == supi) {
            ue = u;
            break;
        }
    }
    if (ue == nullptr || ue->connected) {
        return;   // a connected UE gets its downlink once the gNB's end is back
    }
    const auto s = ue->nas->s_tmsi();
    if (!s || (ue->paged_at && ex_.now() - *ue->paged_at < 2'000)) {
        return;
    }
    ue->paged_at = ex_.now();
    ++pagings_;
    // TS 23.502 4.2.3.3: downlink waits for an idle UE: PAGING with its 5G-S-TMSI to the TAs it registered in.
    std::vector<ngap::Tai> tais;
    tais.reserve(p_.tacs.size());
    for (std::uint32_t tac : p_.tacs) {
        tais.push_back(ngap::Tai{ngap::plmn_id(plmn_.mcc, plmn_.mnc), tac});
    }
    // TS 38.413 §8.5.1: to every gNB serving one of those TAs.
    for (const auto& [link, g] : gnbs_) {
        if (std::any_of(g.tacs.begin(), g.tacs.end(), [&](std::uint32_t t) { return serves(t); })) {
            send_to(link, ngap::Paging{ngap::FiveGSTmsi::of(*s), tais, std::nullopt}, 0);
        }
    }
}

NgapAmf::Ue* NgapAmf::returning(const ngap::InitialUeMessage& m) {
    std::optional<std::uint64_t> s;
    if (m.s_tmsi) {
        s = m.s_tmsi->value();
    }
    std::optional<nas::ie::MobileIdentity> guti;
    Bytes plain;
    if (nas::is_protected(m.nas)) {
        if (auto p = nas::decode_protected(m.nas)) {
            plain = p->payload;   // an initial message is integrity protected only: its IEs are readable
        }
    } else {
        plain = m.nas;
    }
    if (auto msg = nas::decode(plain)) {
        if (const Bytes* id = nas::get(*msg, "5GS mobile identity")) {
            if (auto d = nas::ie::MobileIdentity::decode(*id); d && d->type == nas::ie::MobileIdentity::Type::guti) {
                guti = *d;
            }
        }
        if (const Bytes* id = nas::get(*msg, "5G-S-TMSI")) {
            if (auto d = nas::ie::MobileIdentity::decode(*id); d && d->type == nas::ie::MobileIdentity::Type::s_tmsi) {
                s = ngap::FiveGSTmsi{d->amf_set, d->amf_pointer, d->tmsi}.value();
            }
        }
    }
    for (auto it = order_.rbegin(); it != order_.rend(); ++it) {
        Ue* ue = by_amf(*it);
        if (ue != nullptr && ((s && ue->nas->owns_s_tmsi(*s)) || (guti && ue->nas->owns(*guti)))) {
            return ue;
        }
    }
    return nullptr;
}

void NgapAmf::check(bool ok, const char* clause, const char* what, std::string detail) {
    verdicts_.push_back(Verdict{clause, what, ok, std::move(detail)});
}

std::vector<Verdict> NgapAmf::failures() const {
    std::vector<Verdict> out;
    std::copy_if(verdicts_.begin(), verdicts_.end(), std::back_inserter(out), [](const Verdict& v) { return !v.ok; });
    std::copy_if(smf_.verdicts().begin(), smf_.verdicts().end(), std::back_inserter(out), [](const Verdict& v) { return !v.ok; });
    const auto sf = smsf_.failures();
    out.insert(out.end(), sf.begin(), sf.end());
    if (upf_) {
        std::copy_if(upf_->verdicts().begin(), upf_->verdicts().end(), std::back_inserter(out),
                     [](const Verdict& v) { return !v.ok; });
    }
    for (const auto& [id, ue] : ues_) {
        const auto f = ue.nas->failures();
        out.insert(out.end(), f.begin(), f.end());
    }
    return out;
}

std::size_t NgapAmf::count(std::string_view message) const {
    return static_cast<std::size_t>(std::count(received_.begin(), received_.end(), message));
}

Amf* NgapAmf::nas(std::size_t n) {
    if (n >= order_.size()) {
        return nullptr;
    }
    Ue* ue = by_amf(order_[n]);
    return ue != nullptr ? ue->nas.get() : nullptr;
}

Amf* NgapAmf::nas_by_supi(const std::string& supi) {
    for (auto it = order_.rbegin(); it != order_.rend(); ++it) {
        Ue* ue = by_amf(*it);
        if (ue != nullptr && ue->nas->supi() == supi) {
            return ue->nas.get();
        }
    }
    return nullptr;
}

std::optional<NgapAmf::UeIds> NgapAmf::ids(std::size_t n) const {
    if (n >= order_.size()) {
        return std::nullopt;
    }
    auto it = ues_.find(order_[n]);
    if (it == ues_.end()) {
        return std::nullopt;
    }
    return UeIds{it->second.amf_ue, it->second.ran_ue};
}

NgapAmf::Ue* NgapAmf::by_amf(std::uint64_t id) {
    auto it = ues_.find(id);
    return it != ues_.end() ? &it->second : nullptr;
}

std::uint16_t NgapAmf::stream_of(const Ue& ue) const {
    const std::uint16_t n = ng_->out_streams(ue.link);
    if (n <= 1) {
        return 0;
    }
    return static_cast<std::uint16_t>(1U + ue.ran_ue % (n - 1U));
}

void NgapAmf::send_raw(ByteView pdu, std::uint16_t stream) { (void)ng_->send(rx_link_, pdu, SctpMeta{kNgapPpid, stream}); }

void NgapAmf::send(const ngap::Pdu& p, std::uint16_t stream) { send_to(rx_link_, p, stream); }

void NgapAmf::send_to(LinkId link, const ngap::Pdu& p, std::uint16_t stream) {
    auto wire = ngap::encode(p);
    check(wire.has_value(), "9", "the stub encoded its NGAP message", wire ? "" : wire.error().what);
    if (wire) {
        (void)ng_->send(link, *wire, SctpMeta{kNgapPpid, stream});
    }
}

void NgapAmf::send_ue(const Ue& ue, const ngap::Pdu& p) { send_to(ue.link, p, stream_of(ue)); }

void NgapAmf::release(std::size_t n, ngap::Cause cause) {
    if (n >= order_.size()) {
        return;
    }
    Ue* ue = by_amf(order_[n]);
    if (ue == nullptr) {
        return;
    }
    ue->releasing = true;
    send_ue(*ue, ngap::UeContextReleaseCommand{ue->amf_ue, ue->ran_ue, std::move(cause)});
}

void NgapAmf::attach_nas(Ue& ue) {
    // One 5G-TMSI per UE: the profile's, then the next ones in arrival order.
    Profile p = p_;
    p.tmsi = p_.tmsi + static_cast<std::uint32_t>(order_.size() - 1);
    ue.nas = std::make_unique<Amf>(ex_, home_, plmn_, std::move(p));
    relink(ue);
}

// TS 38.413 8.2.1.2 (P2 Q4): "The UE Aggregate Maximum Bit Rate IE should be sent to the
// NG-RAN node if the AMF has not sent it previously." P1 sent it only in an Initial
// Context Setup with sessions; OCUDU's CU-CP passes 0 to its CU-UP, which refuses it.
std::optional<ngap::Ambr> NgapAmf::first_ambr(Ue& u) {
    if (u.ambr_sent) {
        return std::nullopt;
    }
    u.ambr_sent = true;
    return kUeAmbr;
}

void NgapAmf::send_ics(Ue& u, Bytes nas, SecretBytes kgnb, std::vector<ngap::SessionSetupItem> sessions) {
    const auto& caps = u.nas->ue_capabilities();
    ngap::InitialContextSetupRequest r;
    r.amf = u.amf_ue;
    r.ran = u.ran_ue;
    const ngap::PlmnId plmn = ngap::plmn_id(plmn_.mcc, plmn_.mnc);
    r.guami = ngap::Guami{plmn, p_.amf_region, p_.amf_set, p_.amf_pointer};
    for (std::uint8_t sst : p_.allowed_sst) {
        r.allowed_nssai.push_back(ngap::Snssai{sst, std::nullopt});
    }
    r.nr_enc = caps ? nr_map(caps->ea) : 0;
    r.nr_int = caps ? nr_map(caps->ia) : 0;
    r.security_key.assign(kgnb.expose().begin(), kgnb.expose().end());
    if (u.radio_capability) {
        r.ue_radio_capability = u.radio_capability;
    }
    u.ambr_sent = !sessions.empty();   // a new context at the gNB
    if (!sessions.empty()) {
        r.ue_ambr = kUeAmbr;   // mandatory with sessions (9.2.2.1)
        for (const auto& item : sessions) {
            u.setups.push_back(item.psi);
        }
        r.sessions = std::move(sessions);
    }
    r.nas = std::move(nas);
    u.ics_sent = true;
    u.ics_answered = false;
    send_ue(u, r);
    secure_zero(r.security_key);
}

void NgapAmf::relink(Ue& ue) {
    const std::uint64_t id = ue.amf_ue;
    Amf::Link link;
    link.to_ue = [this, id](Bytes nas) {
        if (Ue* u = by_amf(id)) {
            send_ue(*u, ngap::DownlinkNasTransport{u->amf_ue, u->ran_ue, std::move(nas)});
        }
    };
    link.release = [this, id] { command_release(id, ngap::Cause{"nas", "normal-release"}); };
    link.initial_context = [this, id](Bytes accept, SecretBytes kgnb) {
        if (Ue* u = by_amf(id)) {
            send_ics(*u, std::move(accept), std::move(kgnb), {});
        }
    };
    link.service_accept = [this, id](Bytes accept, SecretBytes kgnb, std::uint16_t psis) {
        if (Ue* u = by_amf(id)) {
            send_ics(*u, std::move(accept), std::move(kgnb), smf_.reactivate(u->nas->supi(), psis));
        }
    };
    link.connected_service_accept = [this, id](Bytes accept, std::uint16_t psis) {
        Ue* u = by_amf(id);
        if (u == nullptr) {
            return;
        }
        auto items = smf_.reactivate(u->nas->supi(), psis);
        for (const auto& it : items) {
            u->setups.push_back(it.psi);
        }
        ngap::PduSessionResourceSetupRequest r{u->amf_ue, u->ran_ue, std::move(accept), std::move(items), first_ambr(*u)};
        send_ue(*u, r);
    };
    link.session_setup = [this, id](Bytes nas, ngap::SessionSetupItem item) {
        Ue* u = by_amf(id);
        if (u == nullptr) {
            return;
        }
        // TS 38.413 9.2.1.1: the 5GSM accept as the session's NAS-PDU.
        item.nas = std::move(nas);
        u->setups.push_back(item.psi);
        ngap::PduSessionResourceSetupRequest r{u->amf_ue, u->ran_ue, std::nullopt, {std::move(item)}, first_ambr(*u)};
        send_ue(*u, r);
    };
    link.session_release = [this, id](Bytes nas, std::uint8_t psi) {
        Ue* u = by_amf(id);
        if (u == nullptr) {
            return;
        }
        u->releases.push_back(psi);
        send_ue(*u, ngap::PduSessionResourceReleaseCommand{u->amf_ue, u->ran_ue, std::move(nas),
                                                           {ngap::SessionCause{psi, ngap::Cause{"nas", "normal-release"}}}});
    };
    link.session_modify = [this, id](Bytes nas, ngap::SessionModifyItem item) {
        Ue* u = by_amf(id);
        if (u == nullptr) {
            return;
        }
        // P2 Q10 (TS 38.413 9.2.1.5): the 5GSM command as the session's NAS-PDU.
        item.nas = std::move(nas);
        u->modifies.push_back(item.psi);
        send_ue(*u, ngap::PduSessionResourceModifyRequest{u->amf_ue, u->ran_ue, {std::move(item)}});
    };
    link.sms_uplink = [this, id](Bytes cp) {
        if (Ue* u = by_amf(id)) {
            smsf_.on_uplink(u->nas->supi(), cp);
        }
    };
    link.sms_subscribed = [this, id] {
        Ue* u = by_amf(id);
        if (u == nullptr) {
            return false;
        }
        auto it = sms_sub_.find(u->nas->supi());
        return it != sms_sub_.end() ? it->second : p_.sms_subscribed;
    };
    ue.nas->attach(std::move(link));
    ue.nas->attach_smf(&smf_);
}

void NgapAmf::on_message(ByteView msg) {
    auto p = ngap::decode(msg);
    check(p.has_value(), "TS 38.413 9", "the gNB's NGAP message decodes", p ? "" : p.error().what);
    if (!p) {
        return;
    }
    received_.emplace_back(name_of(*p));
    const ngap::PlmnId our_plmn = ngap::plmn_id(plmn_.mcc, plmn_.mnc);
    // P3 R2: a TAI is the AMF's when it is a TA of its own that this gNB serves.
    const auto our_tai = [&](const ngap::Tai& t) {
        auto g = gnbs_.find(rx_link_);
        return t.plmn == our_plmn && serves(t.tac) &&
               (g == gnbs_.end() || std::find(g->second.tacs.begin(), g->second.tacs.end(), t.tac) != g->second.tacs.end());
    };
    const auto tas_ok = [&](const std::vector<ngap::NgSetupRequest::Ta>& tas) {
        return std::any_of(tas.begin(), tas.end(), [&](const auto& t) {
            return serves(t.tac) && std::any_of(t.plmns.begin(), t.plmns.end(),
                                                [&](const ngap::PlmnSlices& ps) { return ps.plmn == our_plmn; });
        });
    };
    const auto tacs_of = [](const std::vector<ngap::NgSetupRequest::Ta>& tas) {
        std::vector<std::uint32_t> out;
        out.reserve(tas.size());
        for (const auto& t : tas) {
            out.push_back(t.tac);
        }
        return out;
    };
    std::visit(Overload{
                   [&](const ngap::NgSetupRequest& m) {
                       check(m.gnb_id_bits >= 22 && m.gnb_id_bits <= 32, "TS 38.413 9.3.1.6", "a 22..32-bit gNB ID");
                       check(tas_ok(m.tas), "TS 38.413 8.7.1.2", "the supported TAs include a TA and PLMN of the AMF's");
                       ngap::NgSetupResponse r;
                       r.amf_name = "ksim-stub-amf";
                       r.guamis = {ngap::Guami{our_plmn, p_.amf_region, p_.amf_set, p_.amf_pointer}};
                       r.capacity = 255;
                       std::vector<ngap::Snssai> slices;
                       slices.reserve(p_.allowed_sst.size());
                       for (std::uint8_t sst : p_.allowed_sst) {
                           slices.push_back(ngap::Snssai{sst, std::nullopt});
                       }
                       r.plmns = {{our_plmn, slices}};
                       ng_setup_ = true;
                       gnbs_[rx_link_] = Gnb{m.gnb_id, tacs_of(m.tas)};
                       for (auto& [uid, ue] : ues_) {
                           if (ue.link == rx_link_) {
                               drop_n2(ue);   // TS 38.413 8.7.1.2: the NG-RAN node's UE contexts are gone
                           }
                       }
                       send(r, 0);
                   },
                   [&](const ngap::RanConfigurationUpdate& m) {
                       // TS 38.413 §8.7.2.2: the gNB's served TAs as they are now.
                       auto g = gnbs_.find(rx_link_);
                       check(g != gnbs_.end(), "TS 38.413 8.7.2.1", "a RAN CONFIGURATION UPDATE after NG Setup");
                       if (!m.tas.empty()) {
                           check(tas_ok(m.tas), "TS 38.413 8.7.2.2", "the supported TAs still include one of the AMF's");
                           if (g != gnbs_.end()) {
                               g->second.tacs = tacs_of(m.tas);
                           }
                       }
                       send(ngap::RanConfigurationUpdateAcknowledge{}, 0);
                   },
                   [&](const ngap::InitialUeMessage& m) {
                       check(our_tai(m.tai), "TS 38.413 9.2.5.1", "the user location's TAI is one the gNB serves for this AMF",
                             "");
                       check(!m.cause.empty(), "TS 38.413 9.2.5.1", "an RRC establishment cause");
                       if (Ue* old = returning(m)) {
                           // A returning UE: its NAS context under a new N2 connection (N12).
                           const std::uint64_t old_id = old->amf_ue;
                           Ue moved = std::move(*old);
                           ues_.erase(old_id);
                           if (moved.connected) {
                               moved.nas->on_ue_released();   // the old connection is stale
                           }
                           moved.amf_ue = next_amf_ue_++;
                           moved.ran_ue = m.ran;
                           moved.link = rx_link_;
                           moved.connected = true;
                           moved.ics_sent = moved.ics_answered = moved.releasing = moved.asked = false;
                           moved.setups.clear();
                           moved.releases.clear();
                           moved.paged_at.reset();
                           const std::uint64_t nid = moved.amf_ue;
                           ues_.emplace(nid, std::move(moved));
                           std::replace(order_.begin(), order_.end(), old_id, nid);
                           Ue& u = ues_.at(nid);
                           relink(u);
                           u.nas->on_uplink(m.nas, true);
                           return;
                       }
                       Ue ue;
                       ue.amf_ue = next_amf_ue_++;
                       ue.ran_ue = m.ran;
                       ue.link = rx_link_;
                       const std::uint64_t id = ue.amf_ue;
                       ues_.emplace(id, std::move(ue));
                       order_.push_back(id);
                       Ue& u = ues_.at(id);
                       attach_nas(u);
                       u.nas->on_uplink(m.nas, true);
                   },
                   [&](const ngap::UplinkNasTransport& m) {
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->ran_ue == m.ran, "TS 38.413 10.6", "the UE NGAP IDs are a known pair");
                       check(our_tai(m.tai), "TS 38.413 9.2.5.3", "the user location's TAI is one the gNB serves for this AMF");
                       if (ue != nullptr) {
                           ue->nas->on_uplink(m.nas, false);
                       }
                   },
                   [&](const ngap::InitialContextSetupResponse& m) {
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->ics_sent, "TS 38.413 8.3.1.2", "the response answers a setup request");
                       if (ue != nullptr) {
                           ue->ics_answered = true;
                           const std::string supi = ue->nas->supi();
                           ex_.post([this, supi] { smsf_.on_connected(supi); });   // N13: MT SMS that waited
                           for (const auto& s : m.sessions) {
                               ue->setups.erase(std::remove(ue->setups.begin(), ue->setups.end(), s.psi), ue->setups.end());
                               smf_.on_setup_response(ue->nas->supi(), s.psi, s.transfer.dl);   // the user plane is back
                           }
                           for (const auto& f : m.failed) {
                               check(false, "TS 38.413 8.3.1.2", "the gNB brought the session back",
                                     std::to_string(f.psi) + " " + f.cause.group + "/" + f.cause.value);
                           }
                       }
                   },
                   [&](const ngap::InitialContextSetupFailure& m) {
                       check(false, "TS 38.413 8.3.1.3", "the gNB set up the UE context", m.cause.group + "/" + m.cause.value);
                   },
                   [&](const ngap::UeContextReleaseComplete& m) {
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->releasing, "TS 38.413 8.3.3.2", "the complete answers a release command");
                       if (ue != nullptr) {
                           drop_n2(*ue);   // the NAS context stays; the user plane is deactivated
                       }
                   },
                   [&](const ngap::UeContextReleaseRequest& m) {
                       last_release_cause_ = m.cause.value;
                       if (Ue* ue = by_amf(m.amf)) {
                           if (ue->asked || ue->releasing) {
                               ++repeated_requests_;   // one is enough: the command answers it
                               return;
                           }
                           ue->asked = true;
                           command_release(ue->amf_ue, m.cause);
                       }
                   },
                   [&](const ngap::UeRadioCapabilityInfoIndication& m) {
                       if (Ue* ue = by_amf(m.amf)) {
                           ue->radio_capability = m.capability;
                       }
                   },
                   [&](const ngap::ErrorIndication& m) {
                       ++error_indications_;
                       last_error_ = m.cause;
                   },
                   [&](const ngap::PduSessionResourceSetupResponse& m) {
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->ran_ue == m.ran, "TS 38.413 10.6", "the UE NGAP IDs are a known pair");
                       if (ue == nullptr) {
                           return;
                       }
                       const std::string supi = ue->nas->supi();
                       for (const auto& s : m.sessions) {
                           auto it = std::find(ue->setups.begin(), ue->setups.end(), s.psi);
                           check(it != ue->setups.end(), "TS 38.413 8.2.1.2", "the response answers a session setup request",
                                 std::to_string(s.psi));
                           if (it != ue->setups.end()) {
                               ue->setups.erase(it);
                           }
                           check(!s.transfer.qfis.empty(), "TS 38.413 9.3.4.2", "the gNB set up the session's QoS flow");
                           smf_.on_setup_response(supi, s.psi, s.transfer.dl);
                           if (!s.transfer.failed.empty()) {
                               // P2 Q11 (TS 23.502 4.3.2.2.1): flows the gNB could not admit; the SMF has
                               // the UE delete their rules. A GBR admission refusal is the only one expected.
                               std::vector<std::uint8_t> qfis;
                               qfis.reserve(s.transfer.failed.size());
                               for (const auto& f : s.transfer.failed) {
                                   check(f.cause.value == "radio-resources-not-available", "TS 38.413 8.2.1.2",
                                         "a flow not set up is refused for radio resources", f.cause.group + "/" + f.cause.value);
                                   qfis.push_back(f.qfi);
                               }
                               ++refused_flows_;
                               ue->nas->qos_released(s.psi, qfis);
                           }
                       }
                       for (const auto& f : m.failed) {
                           // P2 Q9: TS 38.413 8.2.1.2, a "required" UP security the gNB cannot
                           // meet is refused with its cause; any other refusal is the gNB's fault.
                           const bool up_security = f.cause.group == "radioNetwork" &&
                                                    (f.cause.value == "up-integrity-protection-not-possible" ||
                                                     f.cause.value == "up-confidentiality-protection-not-possible");
                           check(up_security, "TS 38.413 8.2.1.2", "the gNB set up the session or refused it for UP security",
                                 std::to_string(f.psi) + " " + f.cause.group + "/" + f.cause.value);
                           ue->setups.erase(std::remove(ue->setups.begin(), ue->setups.end(), f.psi), ue->setups.end());
                           smf_.on_setup_failed(supi, f.psi);
                       }
                   },
                   [&](const ngap::PduSessionResourceModifyResponse& m) {
                       // P2 Q10 (TS 38.413 8.2.3.2): the answer to a modification the SMF asked for.
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->ran_ue == m.ran, "TS 38.413 10.6", "the UE NGAP IDs are a known pair");
                       if (ue == nullptr) {
                           return;
                       }
                       const std::string supi = ue->nas->supi();
                       for (const auto& s : m.sessions) {
                           auto it = std::find(ue->modifies.begin(), ue->modifies.end(), s.psi);
                           check(it != ue->modifies.end(), "TS 38.413 8.2.3.2", "the response answers a modify request",
                                 std::to_string(s.psi));
                           if (it != ue->modifies.end()) {
                               ue->modifies.erase(it);
                           }
                           smf_.on_modify_response(supi, s.psi, s.transfer);
                       }
                       for (const auto& f : m.failed) {
                           check(false, "TS 38.413 8.2.3.2", "the gNB modified the session",
                                 std::to_string(f.psi) + " " + f.cause.group + "/" + f.cause.value);
                           ue->modifies.erase(std::remove(ue->modifies.begin(), ue->modifies.end(), f.psi), ue->modifies.end());
                           smf_.on_modify_failed(supi, f.psi);
                       }
                   },
                   [&](const ngap::PduSessionResourceNotify& m) {
                       // P2 Q10 (TS 38.413 8.2.4): flows the gNB released itself; the SMF has the UE delete their rules.
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->ran_ue == m.ran, "TS 38.413 10.6", "the UE NGAP IDs are a known pair");
                       if (ue == nullptr) {
                           return;
                       }
                       ++notifies_;
                       for (const auto& s : m.sessions) {
                           for (const auto& n : s.transfer.notify) {   // P2 Q11: GFBR not fulfilled / fulfilled again
                               ++(n.fulfilled ? notify_fulfilled_ : notify_not_fulfilled_);
                           }
                           std::vector<std::uint8_t> qfis;
                           qfis.reserve(s.transfer.released.size());
                           for (const auto& f : s.transfer.released) {
                               qfis.push_back(f.qfi);
                           }
                           ue->nas->qos_released(s.psi, qfis);
                       }
                   },
                   [&](const ngap::PduSessionResourceReleaseResponse& m) {
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->ran_ue == m.ran, "TS 38.413 10.6", "the UE NGAP IDs are a known pair");
                       if (ue == nullptr) {
                           return;
                       }
                       for (std::uint8_t psi : m.released) {
                           auto it = std::find(ue->releases.begin(), ue->releases.end(), psi);
                           check(it != ue->releases.end(), "TS 38.413 8.2.2.2", "the response answers a release command",
                                 std::to_string(psi));
                           if (it != ue->releases.end()) {
                               ue->releases.erase(it);
                           }
                       }
                   },
                   [&](const auto&) {},
               },
               *p);
}

} // namespace ksim::corestub
