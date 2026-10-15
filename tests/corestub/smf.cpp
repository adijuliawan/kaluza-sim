// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "smf.hpp"

#include <algorithm>

#include "verdict.hpp"
#include "codec/nas/build.hpp"
#include "upf.hpp"

namespace ksim::corestub {

namespace ie = nas::ie;

namespace {

// TS 24.501 Table 9.7.2
constexpr std::uint8_t kEstablishmentRequest = 0xC1;
constexpr std::uint8_t kEstablishmentAccept = 0xC2;
constexpr std::uint8_t kEstablishmentReject = 0xC3;
constexpr std::uint8_t kModificationCommand = 0xCB;
constexpr std::uint8_t kModificationComplete = 0xCC;
constexpr std::uint8_t kReleaseRequest = 0xD1;
constexpr std::uint8_t kReleaseCommand = 0xD3;
constexpr std::uint8_t kReleaseComplete = 0xD4;
constexpr std::uint8_t kStatus = 0xD6;

constexpr std::uint8_t kRegularDeactivation = 36;
constexpr std::uint8_t kUnknownDnn = 27;

nas::Message make(std::uint8_t type, std::uint8_t psi, std::uint8_t pti) {
    auto m = nas::make(nas::Epd::sm, type);
    if (!m) {
        return {};
    }
    (void)nas::set(*m, "PDU session ID", Bytes{psi});
    (void)nas::set(*m, "PTI", Bytes{pti});
    return std::move(*m);
}

ip::Addr addr_of(const Yaml& y, const char* key, ip::Addr fallback) {
    if (!y.has(key)) {
        return fallback;
    }
    auto e = Endpoint::parse(y.at(key).as<std::string>(), 0);
    if (!e || e->family != Endpoint::Family::v4) {
        throw YamlError(y.at(key).where(), y.at(key).path(), "an IPv4 address");
    }
    return {e->addr[0], e->addr[1], e->addr[2], e->addr[3]};
}

/// §9.11.2.5: the coarsest unit that holds `s` exactly in five bits, else 10-minute units.
ie::GprsTimer3 timer3(int s) {
    if (s % 2 == 0 && s / 2 <= 31) {
        return {3, static_cast<std::uint8_t>(s / 2)};
    }
    if (s % 30 == 0 && s / 30 <= 31) {
        return {4, static_cast<std::uint8_t>(s / 30)};
    }
    if (s % 60 == 0 && s / 60 <= 31) {
        return {5, static_cast<std::uint8_t>(s / 60)};
    }
    return {0, static_cast<std::uint8_t>(std::min(31, (s + 599) / 600))};
}

std::vector<SmAction> one(std::uint8_t psi, Result<Bytes> wire, bool release) {
    std::vector<SmAction> out;
    if (wire) {
        out.push_back(SmAction{psi, std::move(*wire), std::nullopt, release});
    }
    return out;
}

ie::SessionAmbr ambr(std::uint32_t mbps) {
    ie::SessionAmbr a;
    a.dl_unit = 6;   // 1 Mbps
    a.dl_value = static_cast<std::uint16_t>(std::min<std::uint32_t>(mbps, 0xFFFF));
    a.ul_unit = 6;
    a.ul_value = a.dl_value;
    return a;
}

} // namespace

SessionProfile SessionProfile::from_yaml(const Yaml& y) {
    y.only({"establishment", "reject_cause", "backoff_s", "rejects", "dnns", "pool", "dns", "dn", "mtu", "qfi", "five_qi",
            "ambr_mbps", "default_rule", "up_integrity", "backoff_dnn", "backoff_dnn_s", "backoff_dnn_rejects"});
    SessionProfile p;
    const std::string e = y.get<std::string>("establishment", "accept");
    if (e == "accept") {
        p.establishment = Establishment::accept;
    } else if (e == "reject") {
        p.establishment = Establishment::reject;
    } else if (e == "silent") {
        p.establishment = Establishment::silent;
    } else {
        throw YamlError(y.at("establishment").where(), y.at("establishment").path(), "unknown establishment '" + e + "'");
    }
    p.reject_cause = static_cast<std::uint8_t>(y.get<int>("reject_cause", p.reject_cause));
    if (y.has("backoff_s")) {
        p.backoff_s = y.at("backoff_s").is_null() ? std::nullopt : std::optional<int>(y.at("backoff_s").as<int>());
    }
    p.rejects = y.get<int>("rejects", p.rejects);
    if (y.has("dnns")) {
        p.dnns.clear();
        for (std::size_t i = 0; i < y.at("dnns").size(); ++i) {
            p.dnns.push_back(y.at("dnns").at(i).as<std::string>());
        }
    }
    p.pool = addr_of(y, "pool", p.pool);
    p.dns = addr_of(y, "dns", p.dns);
    p.dn = addr_of(y, "dn", p.dn);
    p.mtu = static_cast<std::uint16_t>(y.get<int>("mtu", p.mtu));
    p.qfi = static_cast<std::uint8_t>(y.get<int>("qfi", p.qfi));
    p.five_qi = static_cast<std::uint16_t>(y.get<int>("five_qi", p.five_qi));
    p.ambr_mbps = y.get<std::uint32_t>("ambr_mbps", p.ambr_mbps);
    p.default_rule = y.get<bool>("default_rule", p.default_rule);
    p.up_integrity = y.get<std::string>("up_integrity", p.up_integrity);
    p.backoff_dnn = y.get<std::string>("backoff_dnn", p.backoff_dnn);
    p.backoff_dnn_s = y.get<int>("backoff_dnn_s", p.backoff_dnn_s);
    p.backoff_dnn_rejects = y.get<int>("backoff_dnn_rejects", p.backoff_dnn_rejects);
    return p;
}

Smf::Smf(SessionProfile p, Upf* upf) : p_(std::move(p)), upf_(upf) {}

void Smf::check(bool ok, const char* clause, const char* what, std::string detail) {
    verdicts_.push_back(Verdict{clause, what, ok, std::move(detail)});
}

const Smf::Session* Smf::session(const std::string& supi, std::uint8_t psi) const {
    auto it = sessions_.find({supi, psi});
    return it != sessions_.end() ? &it->second : nullptr;
}

bool Smf::known(const std::string& supi, std::uint8_t psi) const { return session(supi, psi) != nullptr; }

std::size_t Smf::sessions() const { return sessions_.size(); }

ip::Addr Smf::next_address() {
    std::uint32_t a = std::uint32_t{p_.pool[0]} << 24 | std::uint32_t{p_.pool[1]} << 16 | std::uint32_t{p_.pool[2]} << 8 |
                      p_.pool[3];
    a += next_host_++;
    return {static_cast<std::uint8_t>(a >> 24), static_cast<std::uint8_t>(a >> 16), static_cast<std::uint8_t>(a >> 8),
            static_cast<std::uint8_t>(a)};
}

std::vector<SmAction> Smf::on_uplink(const std::string& supi, std::uint8_t psi, ByteView sm,
                                     std::optional<std::uint8_t> request_type, const std::optional<std::string>& dnn,
                                     const std::optional<ie::Snssai>& snssai) {
    auto m = nas::decode(sm);
    check(m.has_value(), "8.3", "the 5GSM message decodes", m ? "" : m.error().what);
    if (!m) {
        return {};
    }
    const auto missing = nas::missing_mandatory(*m);
    check(missing.empty(), "8.3", "the 5GSM message's mandatory IEs are present",
          missing.empty() ? "" : std::string(missing.front()));
    const Bytes* hdr_psi = nas::get(*m, "PDU session ID");
    check(hdr_psi != nullptr && !hdr_psi->empty() && (*hdr_psi)[0] == psi, "5.4.5.2.2",
          "the 5GSM header's PDU session ID is the transport's");
    switch (m->desc->type) {
    case kEstablishmentRequest:
        return on_establishment(supi, psi, *m, request_type, dnn, snssai);
    case kReleaseRequest:
        return on_release_request(supi, psi, *m);
    case kReleaseComplete:
        on_release_complete(supi, psi, *m);
        return {};
    case kModificationComplete:
        ++completes_;
        return {};
    case kStatus:
        return {};
    default:
        check(false, "6", "a 5GSM message the stub expects", m->desc->name);
        return {};
    }
}

std::vector<SmAction> Smf::on_establishment(const std::string& supi, std::uint8_t psi, const nas::Message& m,
                                            std::optional<std::uint8_t> request_type,
                                            const std::optional<std::string>& dnn,
                                            const std::optional<ie::Snssai>& snssai) {
    ++requests_;
    const Bytes* pti_v = nas::get(m, "PTI");
    const std::uint8_t pti = pti_v != nullptr && !pti_v->empty() ? (*pti_v)[0] : 0;
    check(pti >= 1 && pti <= 254, "6.4.1.2", "the request carries an assigned PTI", std::to_string(pti));
    check(request_type == ie::RequestType::initial, "5.4.5.2.2", "the request type is initial request");
    check(psi >= 1 && psi <= 15, "6.4.1.2", "the PDU session identity is 1..15", std::to_string(psi));
    const Bytes* type = nas::get(m, "PDU session type");
    check(type != nullptr && !type->empty() && ((*type)[0] & 0x07) == ie::PduSessionType::ipv4, "6.4.1.2",
          "the UE asks for an IPv4 session");
    bool dns_req = false;
    bool mtu_req = false;
    if (const Bytes* e = nas::get(m, "Extended protocol configuration options")) {
        if (auto epco = nas::decode_epco(*e, nas::Direction::ul)) {
            for (const auto& u : epco->units) {
                dns_req = dns_req || u.id == 0x000D;
                mtu_req = mtu_req || u.id == 0x0010;
            }
        }
    }
    check(dns_req, "TS 24.008 10.5.6.3A", "the ePCO asks for the DNS server IPv4 address (000DH)");
    check(mtu_req, "TS 24.008 10.5.6.3A", "the ePCO asks for the IPv4 link MTU (0010H)");
    if (const Session* old = session(supi, psi); old != nullptr) {
        // TS 23.502 4.3.2.2.1: an initial request for a PSI in use: the old one goes locally.
        if (upf_ != nullptr) {
            upf_->close(old->ul_teid);
        }
        sessions_.erase({supi, psi});
    }
    const bool reject_now = p_.establishment == SessionProfile::Establishment::reject &&
                            (p_.rejects == 0 || rejected_ < p_.rejects);
    const std::string want = dnn.value_or(p_.dnns.empty() ? std::string() : p_.dnns.front());
    const bool backoff_dnn = !p_.backoff_dnn.empty() && want == p_.backoff_dnn;
    const bool dnn_ok = backoff_dnn || std::find(p_.dnns.begin(), p_.dnns.end(), want) != p_.dnns.end();
    if (p_.establishment == SessionProfile::Establishment::silent) {
        return {};
    }
    if (backoff_dnn && backoff_rejected_[supi] < p_.backoff_dnn_rejects) {
        ++backoff_rejected_[supi];
        nas::Message r = make(kEstablishmentReject, psi, pti);
        (void)nas::set(r, "5GSM cause", Bytes{29});   // user authentication or authorization failed
        (void)nas::set(r, "Back-off timer value", timer3(p_.backoff_dnn_s).encode());
        return one(psi, nas::encode(r), false);
    }
    if (reject_now || !dnn_ok) {
        ++rejected_;
        nas::Message r = make(kEstablishmentReject, psi, pti);
        (void)nas::set(r, "5GSM cause", Bytes{dnn_ok ? p_.reject_cause : kUnknownDnn});
        if (p_.backoff_s && reject_now) {
            (void)nas::set(r, "Back-off timer value", timer3(*p_.backoff_s).encode());
        }
        return one(psi, nas::encode(r), false);
    }
    Session s;
    s.psi = psi;
    s.dnn = want;
    s.ip = next_address();
    s.ul_teid = upf_ != nullptr ? upf_->open(s.ip, p_.qfi) : fake_teid_++;
    nas::Message a = make(kEstablishmentAccept, psi, pti);
    (void)nas::set(a, "Selected PDU session type", Bytes{ie::PduSessionType::ipv4});
    (void)nas::set(a, "Selected SSC mode", Bytes{1});
    ie::QosRules rules;
    ie::QosRules::Rule rule;
    rule.id = 1;
    rule.operation = 1;
    rule.default_rule = p_.default_rule;
    rule.filters = {ie::QosRules::PacketFilter{3, 1, {ie::QosRules::Component{0x01, {}}}}};
    rule.precedence = 255;
    rule.qfi = p_.qfi;
    rules.list.push_back(rule);
    if (auto r = rules.encode()) {
        (void)nas::set(a, "Authorized QoS rules", std::move(*r));
    }
    (void)nas::set(a, "Session AMBR", ambr(p_.ambr_mbps).encode());
    ie::PduAddress addr;
    addr.type = 1;
    addr.ipv4 = s.ip;
    (void)nas::set(a, "PDU address", addr.encode());
    if (snssai) {
        (void)nas::set(a, "S-NSSAI", snssai->encode());
    }
    ie::QosFlowDescriptions flows;
    flows.list.push_back(ie::QosFlowDescriptions::Description{
        p_.qfi, 1, true, {ie::QosFlowDescriptions::Parameter{1, Bytes{static_cast<std::uint8_t>(p_.five_qi)}}}});
    if (auto f = flows.encode()) {
        (void)nas::set(a, "Authorized QoS flow descriptions", std::move(*f));
    }
    nas::Epco epco;
    epco.units = {nas::EpcoUnit{0x000D, Bytes(p_.dns.begin(), p_.dns.end()), 0},
                  nas::EpcoUnit{0x0010, Bytes{static_cast<std::uint8_t>(p_.mtu >> 8), static_cast<std::uint8_t>(p_.mtu & 0xFF)}, 0}};
    if (auto e = nas::encode_epco(epco, nas::Direction::dl)) {
        (void)nas::set(a, "Extended protocol configuration options", std::move(*e));
    }
    (void)nas::set(a, "DNN", ie::Dnn{want}.encode().value_or(Bytes{}));
    auto wire = nas::encode(a);
    if (!wire) {
        check(false, "8.3.2", "the stub encoded its accept", wire.error().what);
        return {};
    }
    ngap::SessionSetupItem item;
    item.psi = psi;
    item.snssai = ngap::Snssai{snssai ? snssai->sst : std::uint8_t{1}, snssai ? snssai->sd : std::nullopt};
    item.transfer.session_ambr = ngap::Ambr{std::uint64_t{p_.ambr_mbps} * 1'000'000, std::uint64_t{p_.ambr_mbps} * 1'000'000};
    item.transfer.ul = upf_ != nullptr ? upf_->tunnel(s.ul_teid) : ngap::GtpTunnel{{127, 0, 0, 1}, s.ul_teid};
    item.transfer.type = "ipv4";
    item.transfer.security = ngap::SecurityIndication{p_.up_integrity, "required"};
    item.transfer.flows = {ngap::QosFlowRequest{p_.qfi, p_.five_qi, ngap::Arp{}}};
    sessions_[{supi, psi}] = s;
    std::vector<SmAction> out;
    out.push_back(SmAction{psi, std::move(*wire), std::move(item), false});
    return out;
}

void Smf::on_setup_response(const std::string& supi, std::uint8_t psi, const ngap::GtpTunnel& dl) {
    auto it = sessions_.find({supi, psi});
    check(it != sessions_.end(), "TS 38.413 8.2.1.2", "the setup response names a session the SMF set up");
    if (it == sessions_.end()) {
        return;
    }
    it->second.dl = dl;
    it->second.active = true;
    if (upf_ != nullptr) {
        upf_->set_dl(it->second.ul_teid, dl);
    }
}

void Smf::on_setup_failed(const std::string& supi, std::uint8_t psi) {
    auto it = sessions_.find({supi, psi});
    if (it == sessions_.end()) {
        return;
    }
    if (upf_ != nullptr) {
        upf_->close(it->second.ul_teid);
    }
    sessions_.erase(it);
}

std::vector<SmAction> Smf::on_release_request(const std::string& supi, std::uint8_t psi, const nas::Message& m) {
    const Bytes* pti_v = nas::get(m, "PTI");
    const std::uint8_t pti = pti_v != nullptr && !pti_v->empty() ? (*pti_v)[0] : 0;
    check(pti >= 1 && pti <= 254, "6.4.3.2", "the release request carries an assigned PTI", std::to_string(pti));
    auto it = sessions_.find({supi, psi});
    check(it != sessions_.end(), "6.4.3.2", "the UE releases a session it holds");
    if (it == sessions_.end()) {
        return {};
    }
    it->second.release_pti = pti;
    nas::Message c = make(kReleaseCommand, psi, pti);
    (void)nas::set(c, "5GSM cause", Bytes{kRegularDeactivation});
    return one(psi, nas::encode(c), true);
}

void Smf::on_release_complete(const std::string& supi, std::uint8_t psi, const nas::Message& m) {
    ++completes_;
    const Bytes* pti_v = nas::get(m, "PTI");
    const std::uint8_t pti = pti_v != nullptr && !pti_v->empty() ? (*pti_v)[0] : 0;
    auto it = sessions_.find({supi, psi});
    check(it != sessions_.end() && it->second.release_pti == pti, "6.3.3.3",
          "the RELEASE COMPLETE carries the RELEASE COMMAND's PTI", std::to_string(pti));
    if (it == sessions_.end()) {
        return;
    }
    if (upf_ != nullptr) {
        upf_->close(it->second.ul_teid);
    }
    sessions_.erase(it);
}

std::optional<SmAction> Smf::release(const std::string& supi, std::uint8_t psi, std::uint8_t cause) {
    auto it = sessions_.find({supi, psi});
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    it->second.release_pti = 0;
    nas::Message c = make(kReleaseCommand, psi, 0);
    (void)nas::set(c, "5GSM cause", Bytes{cause});
    auto wire = nas::encode(c);
    if (!wire) {
        return std::nullopt;
    }
    return SmAction{psi, std::move(*wire), std::nullopt, true};
}

std::optional<SmAction> Smf::modify(const std::string& supi, std::uint8_t psi, std::uint32_t ambr_mbps) {
    if (sessions_.count({supi, psi}) == 0) {
        return std::nullopt;
    }
    nas::Message c = make(kModificationCommand, psi, 0);
    (void)nas::set(c, "Session AMBR", ambr(ambr_mbps).encode());
    auto wire = nas::encode(c);
    if (!wire) {
        return std::nullopt;
    }
    return SmAction{psi, std::move(*wire), std::nullopt, false};
}

Result<void> Smf::ping_ue(const std::string& supi, std::uint8_t psi, std::uint16_t seq) {
    const Session* s = session(supi, psi);
    if (s == nullptr || upf_ == nullptr) {
        return make_error(Errc::invalid_argument, psi, "smf: no such session, or no UPF");
    }
    return upf_->ping_ue(s->ul_teid, p_.dn, seq);
}

} // namespace ksim::corestub
