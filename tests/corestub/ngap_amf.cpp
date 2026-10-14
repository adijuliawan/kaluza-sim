// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "ngap_amf.hpp"

#include <algorithm>
#include <utility>

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
                          [](const auto&) { return "other"; },
                      },
                      p);
}

} // namespace

NgapAmf::NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, IAssoc& ng)
    : ex_(ex), home_(home), plmn_(std::move(plmn)), p_(std::move(p)), ng_(ng) {
    ng_.set_handlers([this](ByteView msg, SctpMeta) { on_message(msg); }, [](LinkEvent) {});
}

void NgapAmf::check(bool ok, const char* clause, const char* what, std::string detail) {
    verdicts_.push_back(Verdict{clause, what, ok, std::move(detail)});
}

std::vector<Verdict> NgapAmf::failures() const {
    std::vector<Verdict> out;
    std::copy_if(verdicts_.begin(), verdicts_.end(), std::back_inserter(out), [](const Verdict& v) { return !v.ok; });
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
    if (ng_.out_streams() <= 1) {
        return 0;
    }
    return static_cast<std::uint16_t>(1U + ue.ran_ue % (ng_.out_streams() - 1U));
}

void NgapAmf::send_raw(ByteView pdu, std::uint16_t stream) { (void)ng_.send(pdu, SctpMeta{kNgapPpid, stream}); }

void NgapAmf::send(const ngap::Pdu& p, std::uint16_t stream) {
    auto wire = ngap::encode(p);
    check(wire.has_value(), "9", "the stub encoded its NGAP message", wire ? "" : wire.error().what);
    if (wire) {
        send_raw(*wire, stream);
    }
}

void NgapAmf::release(std::size_t n, ngap::Cause cause) {
    if (n >= order_.size()) {
        return;
    }
    Ue* ue = by_amf(order_[n]);
    if (ue == nullptr) {
        return;
    }
    ue->releasing = true;
    send(ngap::UeContextReleaseCommand{ue->amf_ue, ue->ran_ue, std::move(cause)}, stream_of(*ue));
}

void NgapAmf::attach_nas(Ue& ue) {
    const std::uint64_t id = ue.amf_ue;
    // One 5G-TMSI per UE: the profile's, then the next ones in arrival order.
    Profile p = p_;
    p.tmsi = p_.tmsi + static_cast<std::uint32_t>(order_.size() - 1);
    ue.nas = std::make_unique<Amf>(ex_, home_, plmn_, std::move(p));
    Amf::Link link;
    link.to_ue = [this, id](Bytes nas) {
        if (Ue* u = by_amf(id)) {
            send(ngap::DownlinkNasTransport{u->amf_ue, u->ran_ue, std::move(nas)}, stream_of(*u));
        }
    };
    link.release = [this, id] {
        if (Ue* u = by_amf(id)) {
            u->releasing = true;
            send(ngap::UeContextReleaseCommand{u->amf_ue, u->ran_ue, ngap::Cause{"nas", "normal-release"}}, stream_of(*u));
        }
    };
    link.initial_context = [this, id](Bytes accept, SecretBytes kgnb) {
        Ue* u = by_amf(id);
        if (u == nullptr) {
            return;
        }
        const auto& caps = u->nas->ue_capabilities();
        ngap::InitialContextSetupRequest r;
        r.amf = u->amf_ue;
        r.ran = u->ran_ue;
        const ngap::PlmnId plmn = ngap::plmn_id(plmn_.mcc, plmn_.mnc);
        r.guami = ngap::Guami{plmn, p_.amf_region, p_.amf_set, p_.amf_pointer};
        for (std::uint8_t sst : p_.allowed_sst) {
            r.allowed_nssai.push_back(ngap::Snssai{sst, std::nullopt});
        }
        r.nr_enc = caps ? nr_map(caps->ea) : 0;
        r.nr_int = caps ? nr_map(caps->ia) : 0;
        r.security_key.assign(kgnb.expose().begin(), kgnb.expose().end());
        if (u->radio_capability) {
            r.ue_radio_capability = u->radio_capability;
        }
        r.nas = std::move(accept);
        u->ics_sent = true;
        send(r, stream_of(*u));
        secure_zero(r.security_key);
    };
    ue.nas->attach(std::move(link));
}

void NgapAmf::on_message(ByteView msg) {
    auto p = ngap::decode(msg);
    check(p.has_value(), "TS 38.413 9", "the gNB's NGAP message decodes", p ? "" : p.error().what);
    if (!p) {
        return;
    }
    received_.emplace_back(name_of(*p));
    const ngap::Tai our_tai{ngap::plmn_id(plmn_.mcc, plmn_.mnc), p_.tacs.empty() ? 1U : p_.tacs.front()};
    std::visit(Overload{
                   [&](const ngap::NgSetupRequest& m) {
                       check(m.gnb_id_bits >= 22 && m.gnb_id_bits <= 32, "TS 38.413 9.3.1.6", "a 22..32-bit gNB ID");
                       const bool ta = std::any_of(m.tas.begin(), m.tas.end(), [&](const auto& t) {
                           return t.tac == our_tai.tac &&
                                  std::any_of(t.plmns.begin(), t.plmns.end(),
                                              [&](const ngap::PlmnSlices& s) { return s.plmn == our_tai.plmn; });
                       });
                       check(ta, "TS 38.413 8.7.1.2", "the supported TAs include the AMF's TA and PLMN");
                       ngap::NgSetupResponse r;
                       r.amf_name = "ksim-stub-amf";
                       r.guamis = {ngap::Guami{our_tai.plmn, p_.amf_region, p_.amf_set, p_.amf_pointer}};
                       r.capacity = 255;
                       std::vector<ngap::Snssai> slices;
                       slices.reserve(p_.allowed_sst.size());
                       for (std::uint8_t sst : p_.allowed_sst) {
                           slices.push_back(ngap::Snssai{sst, std::nullopt});
                       }
                       r.plmns = {{our_tai.plmn, slices}};
                       ng_setup_ = true;
                       send(r, 0);
                   },
                   [&](const ngap::InitialUeMessage& m) {
                       check(m.tai == our_tai, "TS 38.413 9.2.5.1", "the user location's TAI is the cell's", "");
                       check(!m.cause.empty(), "TS 38.413 9.2.5.1", "an RRC establishment cause");
                       Ue ue;
                       ue.amf_ue = next_amf_ue_++;
                       ue.ran_ue = m.ran;
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
                       check(m.tai == our_tai, "TS 38.413 9.2.5.3", "the user location's TAI is the cell's");
                       if (ue != nullptr) {
                           ue->nas->on_uplink(m.nas, false);
                       }
                   },
                   [&](const ngap::InitialContextSetupResponse& m) {
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->ics_sent, "TS 38.413 8.3.1.2", "the response answers a setup request");
                       if (ue != nullptr) {
                           ue->ics_answered = true;
                       }
                   },
                   [&](const ngap::InitialContextSetupFailure& m) {
                       check(false, "TS 38.413 8.3.1.3", "the gNB set up the UE context", m.cause.group + "/" + m.cause.value);
                   },
                   [&](const ngap::UeContextReleaseComplete& m) {
                       Ue* ue = by_amf(m.amf);
                       check(ue != nullptr && ue->releasing, "TS 38.413 8.3.3.2", "the complete answers a release command");
                       if (ue != nullptr) {
                           ue->nas->on_ue_released();
                       }
                   },
                   [&](const ngap::UeContextReleaseRequest& m) {
                       if (Ue* ue = by_amf(m.amf)) {
                           ue->releasing = true;
                           send(ngap::UeContextReleaseCommand{ue->amf_ue, ue->ran_ue, m.cause}, stream_of(*ue));
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
                   [&](const auto&) {},
               },
               *p);
}

} // namespace ksim::corestub
