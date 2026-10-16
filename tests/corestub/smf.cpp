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
        out.push_back(SmAction{psi, std::move(*wire), std::nullopt, release, std::nullopt});
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

// P2 Q10

std::optional<std::uint32_t> number(const std::string& t) {
    try {
        std::size_t used = 0;
        const unsigned long v = std::stoul(t, &used, 0);
        if (used != t.size() || v > 0xFFFFFFFFUL) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(v);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Bytes be(std::uint32_t v, std::size_t n) {
    Bytes out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[n - 1 - i] = static_cast<std::uint8_t>(v >> (8 * i));
    }
    return out;
}

ie::QosRules::Rule rule_of(std::uint8_t id, const FlowSpec& f) {
    ie::QosRules::Rule r;
    r.id = id;
    r.operation = 1;   // create new QoS rule
    r.default_rule = false;
    r.filters = {ie::QosRules::PacketFilter{f.direction, 1, f.components}};
    r.precedence = f.precedence;
    r.qfi = f.qfi;
    return r;
}

ie::QosFlowDescriptions::Description create_flow(std::uint8_t qfi, std::uint16_t five_qi) {
    return {qfi, 1, true, {ie::QosFlowDescriptions::Parameter{1, Bytes{static_cast<std::uint8_t>(five_qi)}}}};
}

} // namespace

SessionProfile SessionProfile::from_yaml(const Yaml& y) {
    y.only({"establishment", "reject_cause", "backoff_s", "rejects", "dnns", "pool", "dns", "dn", "mtu", "qfi", "five_qi",
            "ambr_mbps", "default_rule", "up_integrity", "up_confidentiality", "up_rate_ul", "up_rate_dl",
            "backoff_dnn", "backoff_dnn_s", "backoff_dnn_rejects", "flows"});
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
    p.up_confidentiality = y.get<std::string>("up_confidentiality", p.up_confidentiality);
    if (y.has("up_rate_ul")) {
        p.up_rate_ul = y.get<std::string>("up_rate_ul", "maximum-UE-rate");
    }
    if (y.has("up_rate_dl")) {
        p.up_rate_dl = y.get<std::string>("up_rate_dl", "maximum-UE-rate");
    }
    p.backoff_dnn = y.get<std::string>("backoff_dnn", p.backoff_dnn);
    p.backoff_dnn_s = y.get<int>("backoff_dnn_s", p.backoff_dnn_s);
    p.backoff_dnn_rejects = y.get<int>("backoff_dnn_rejects", p.backoff_dnn_rejects);
    if (y.has("flows")) {
        // P2 Q10: QoS flows beside the default one, with their rules.
        for (std::size_t i = 0; i < y.at("flows").size(); ++i) {
            const Yaml f = y.at("flows").at(i);
            f.only({"qfi", "five_qi", "precedence", "direction", "filter"});
            FlowSpec spec;
            spec.qfi = static_cast<std::uint8_t>(f.at("qfi").as<int>());
            spec.five_qi = static_cast<std::uint16_t>(f.get<int>("five_qi", spec.five_qi));
            spec.precedence = static_cast<std::uint8_t>(f.get<int>("precedence", spec.precedence));
            auto d = parse_direction(f.get<std::string>("direction", "bidirectional"));
            spec.filter = f.at("filter").as<std::string>();
            auto c = parse_filter(spec.filter);
            if (!d || !c || spec.qfi < 1 || spec.qfi > 63 || spec.qfi == p.qfi) {
                throw YamlError(f.where(), f.path(), "a flow: qfi 1..63 not the default's, a direction and a filter");
            }
            spec.direction = *d;
            spec.components = std::move(*c);
            p.flows.push_back(std::move(spec));
        }
    }
    return p;
}

Smf::Smf(SessionProfile p, Upf* upf) : p_(std::move(p)), upf_(upf) {
    if (upf_ != nullptr) {
        upf_->on_dl_pending([this](std::uint32_t teid) {
            for (auto& [key, s] : sessions_) {
                if (s.ul_teid == teid) {
                    s.pending = true;
                    if (on_page_) {
                        on_page_(key.first, key.second);
                    }
                    return;
                }
            }
        });
    }
}

void Smf::deactivate(const std::string& supi) {
    for (auto& [key, s] : sessions_) {
        if (key.first == supi) {
            s.active = false;
            s.dl.reset();
            if (upf_ != nullptr) {
                upf_->deactivate(s.ul_teid);
            }
        }
    }
}

std::vector<ngap::SessionSetupItem> Smf::reactivate(const std::string& supi, std::uint16_t psis) const {
    std::vector<ngap::SessionSetupItem> out;
    for (const auto& [key, s] : sessions_) {
        if (key.first == supi && (psis & (1U << key.second)) != 0 && s.setup) {
            ngap::SessionSetupItem item = *s.setup;
            item.nas.reset();   // no 5GSM message this time: only the resources
            out.push_back(std::move(item));
        }
    }
    return out;
}

std::uint16_t Smf::sessions_of(const std::string& supi) const {
    std::uint16_t out = 0;
    for (const auto& [key, s] : sessions_) {
        if (key.first == supi) {
            out = static_cast<std::uint16_t>(out | (1U << key.second));
        }
    }
    return out;
}

std::uint16_t Smf::pending_of(const std::string& supi) const {
    std::uint16_t out = 0;
    for (const auto& [key, s] : sessions_) {
        if (key.first == supi && s.pending) {
            out = static_cast<std::uint16_t>(out | (1U << key.second));
        }
    }
    return out;
}

void Smf::release_all(const std::string& supi) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->first.first == supi) {
            if (upf_ != nullptr) {
                upf_->close(it->second.ul_teid);
            }
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

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
    // P2 Q10: the profile's further flows, each with its rule (TS 24.501 6.2.5.1.1.2).
    for (const auto& f : p_.flows) {
        rules.list.push_back(rule_of(s.next_rule++, f));
    }
    s.rules = rules.list;
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
    flows.list.push_back(create_flow(p_.qfi, p_.five_qi));
    for (const auto& f : p_.flows) {
        flows.list.push_back(create_flow(f.qfi, f.five_qi));
    }
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
    if (p_.up_integrity != "absent" && p_.up_confidentiality != "absent") {
        ngap::SecurityIndication si;
        si.integrity = p_.up_integrity;
        si.confidentiality = p_.up_confidentiality;
        si.max_rate_ul = p_.up_rate_ul;
        si.max_rate_dl = p_.up_rate_dl;
        item.transfer.security = si;
    }
    item.transfer.flows = {ngap::QosFlowRequest{p_.qfi, p_.five_qi, ngap::Arp{}}};
    for (const auto& f : p_.flows) {
        item.transfer.flows.push_back(ngap::QosFlowRequest{f.qfi, f.five_qi, ngap::Arp{}});
    }
    s.setup = item;
    sessions_[{supi, psi}] = s;
    std::vector<SmAction> out;
    out.push_back(SmAction{psi, std::move(*wire), std::move(item), false, std::nullopt});
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
    it->second.pending = false;
    if (upf_ != nullptr) {
        upf_->set_rules(it->second.ul_teid, it->second.rules);   // P2 Q10: the UPF classifies with them
        upf_->set_dl(it->second.ul_teid, dl);   // what was held goes now
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
    return SmAction{psi, std::move(*wire), std::nullopt, true, std::nullopt};
}

std::optional<SmAction> Smf::modify(const std::string& supi, std::uint8_t psi, std::uint32_t ambr_mbps) {
    auto it = sessions_.find({supi, psi});
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    nas::Message c = make(kModificationCommand, psi, 0);
    (void)nas::set(c, "Session AMBR", ambr(ambr_mbps).encode());
    auto wire = nas::encode(c);
    if (!wire) {
        return std::nullopt;
    }
    Session& s = it->second;
    if (!s.active || !s.setup || s.modifying) {
        return SmAction{psi, std::move(*wire), std::nullopt, false, std::nullopt};   // the 5GSM command alone
    }
    // P2 Q10 (TS 23.502 4.3.3.2): the new session-AMBR goes to the gNB too.
    ngap::SessionModifyItem item;
    item.psi = psi;
    item.transfer.session_ambr = ngap::Ambr{std::uint64_t{ambr_mbps} * 1'000'000, std::uint64_t{ambr_mbps} * 1'000'000};
    s.modifying = Session::Pending{s.rules, s.setup->transfer.flows, {}, {}};
    return SmAction{psi, std::move(*wire), std::nullopt, false, std::move(item)};
}

// ---- P2 Q10: QoS flows beyond the default one ------------------------------------------------


Result<std::vector<ie::QosRules::Component>> parse_filter(const std::string& text) {
    std::vector<ie::QosRules::Component> out;
    std::size_t at = 0;
    while (at <= text.size()) {
        const std::size_t end = std::min(text.find(',', at), text.size());
        const std::string tok = text.substr(at, end - at);
        at = end + 1;
        if (tok.empty()) {
            continue;
        }
        const std::size_t eq = tok.find('=');
        const std::string key = tok.substr(0, eq);
        const std::string val = eq == std::string::npos ? std::string() : tok.substr(eq + 1);
        auto bad = [&at]() {
            return make_error(Errc::invalid_argument, static_cast<std::uint32_t>(at), "filter: a component it cannot read");
        };
        if (key == "all") {
            out.push_back({0x01, {}});
        } else if (key == "remote" || key == "local") {
            const std::size_t slash = val.find('/');
            auto e = Endpoint::parse(val.substr(0, slash), 0);
            const auto bits = slash == std::string::npos ? std::optional<std::uint32_t>(32) : number(val.substr(slash + 1));
            if (!e || e->family != Endpoint::Family::v4 || !bits || *bits > 32) {
                return bad();
            }
            const std::uint32_t mask = *bits == 0 ? 0 : ~std::uint32_t{0} << (32 - *bits);
            Bytes v{e->addr[0], e->addr[1], e->addr[2], e->addr[3]};
            const Bytes m = be(mask, 4);
            v.insert(v.end(), m.begin(), m.end());
            out.push_back({static_cast<std::uint8_t>(key == "remote" ? 0x10 : 0x11), std::move(v)});
        } else if (key == "proto") {
            const auto n = number(val);
            if (!n || *n > 255) {
                return bad();
            }
            out.push_back({0x30, be(*n, 1)});
        } else if (key == "lport" || key == "rport") {
            const auto n = number(val);
            if (!n || *n > 0xFFFF) {
                return bad();
            }
            out.push_back({static_cast<std::uint8_t>(key == "lport" ? 0x40 : 0x50), be(*n, 2)});
        } else if (key == "lports" || key == "rports") {
            const std::size_t dash = val.find('-');
            const auto lo = number(val.substr(0, dash));
            const auto hi = dash == std::string::npos ? std::nullopt : number(val.substr(dash + 1));
            if (!lo || !hi || *lo > *hi || *hi > 0xFFFF) {
                return bad();
            }
            Bytes v = be(*lo, 2);
            const Bytes h = be(*hi, 2);
            v.insert(v.end(), h.begin(), h.end());
            out.push_back({static_cast<std::uint8_t>(key == "lports" ? 0x41 : 0x51), std::move(v)});
        } else if (key == "spi") {
            const auto n = number(val);
            if (!n) {
                return bad();
            }
            out.push_back({0x60, be(*n, 4)});
        } else if (key == "tos") {
            const std::size_t slash = val.find('/');
            const auto v = number(val.substr(0, slash));
            const auto m = slash == std::string::npos ? std::optional<std::uint32_t>(0xFF) : number(val.substr(slash + 1));
            if (!v || !m || *v > 255 || *m > 255) {
                return bad();
            }
            out.push_back({0x70, Bytes{static_cast<std::uint8_t>(*v), static_cast<std::uint8_t>(*m)}});
        } else {
            return bad();
        }
    }
    if (out.empty()) {
        return make_error(Errc::invalid_argument, 0, "filter: no component");
    }
    return out;
}

Result<std::uint8_t> parse_direction(const std::string& text) {
    if (text == "downlink") {
        return std::uint8_t{1};
    }
    if (text == "uplink") {
        return std::uint8_t{2};
    }
    if (text == "bidirectional" || text.empty()) {
        return std::uint8_t{3};
    }
    return make_error(Errc::invalid_argument, 0, "direction: uplink, downlink or bidirectional");
}

Result<SmAction> Smf::modification(Session& s, Session::Pending p, ngap::ModifyRequestTransfer t, const ie::QosRules& rules,
                                   const ie::QosFlowDescriptions& flows) {
    nas::Message c = make(kModificationCommand, s.psi, 0);
    if (!rules.list.empty()) {
        auto r = rules.encode();
        if (!r) {
            return r.error();
        }
        (void)nas::set(c, "Authorized QoS rules", std::move(*r));
    }
    if (!flows.list.empty()) {
        auto f = flows.encode();
        if (!f) {
            return f.error();
        }
        (void)nas::set(c, "Authorized QoS flow descriptions", std::move(*f));
    }
    auto wire = nas::encode(c);
    if (!wire) {
        return wire.error();
    }
    ngap::SessionModifyItem item;
    item.psi = s.psi;
    item.transfer = std::move(t);
    s.modifying = std::move(p);
    return SmAction{s.psi, std::move(*wire), std::nullopt, false, std::move(item)};
}

Result<SmAction> Smf::qos_add(const std::string& supi, std::uint8_t psi, const FlowSpec& f) {
    auto it = sessions_.find({supi, psi});
    if (it == sessions_.end() || !it->second.active || !it->second.setup) {
        return make_error(Errc::invalid_argument, psi, "smf: no active session with that PSI");
    }
    Session& s = it->second;
    if (s.modifying) {
        return make_error(Errc::invalid_argument, psi, "smf: a modification of the session is on its way");
    }
    const auto& now = s.setup->transfer.flows;
    if (f.qfi < 1 || f.qfi > 63 || std::any_of(now.begin(), now.end(), [&f](const auto& x) { return x.qfi == f.qfi; })) {
        return make_error(Errc::invalid_argument, f.qfi, "smf: a QFI 1..63 the session does not have");
    }
    Session::Pending p;
    p.rules = s.rules;
    const ie::QosRules::Rule r = rule_of(s.next_rule++, f);
    p.rules.push_back(r);
    p.flows = now;
    const ngap::QosFlowRequest flow{f.qfi, f.five_qi, ngap::Arp{}};
    p.flows.push_back(flow);
    p.added = {f.qfi};
    ngap::ModifyRequestTransfer t;
    t.add_or_modify = {flow};
    ie::QosRules rules;
    rules.list = {r};
    ie::QosFlowDescriptions flows;
    flows.list = {create_flow(f.qfi, f.five_qi)};
    return modification(s, std::move(p), std::move(t), rules, flows);
}

Result<SmAction> Smf::qos_del(const std::string& supi, std::uint8_t psi, std::uint8_t qfi) {
    auto it = sessions_.find({supi, psi});
    if (it == sessions_.end() || !it->second.active || !it->second.setup) {
        return make_error(Errc::invalid_argument, psi, "smf: no active session with that PSI");
    }
    Session& s = it->second;
    if (s.modifying) {
        return make_error(Errc::invalid_argument, psi, "smf: a modification of the session is on its way");
    }
    if (qfi == p_.qfi) {
        return make_error(Errc::invalid_argument, qfi, "smf: the default QoS rule's flow goes with the session");
    }
    const auto& now = s.setup->transfer.flows;
    if (std::none_of(now.begin(), now.end(), [qfi](const auto& x) { return x.qfi == qfi; })) {
        return make_error(Errc::invalid_argument, qfi, "smf: no such QoS flow in the session");
    }
    Session::Pending p;
    ie::QosRules rules;
    for (const auto& r : s.rules) {
        if (r.qfi == qfi && !r.default_rule) {
            ie::QosRules::Rule d;   // delete existing QoS rule: the identifier alone (9.11.4.13)
            d.id = r.id;
            d.operation = 2;
            rules.list.push_back(d);
        } else {
            p.rules.push_back(r);
        }
    }
    for (const auto& x : now) {
        if (x.qfi != qfi) {
            p.flows.push_back(x);
        }
    }
    p.released = {qfi};
    ngap::ModifyRequestTransfer t;
    t.release = {qfi};
    ie::QosFlowDescriptions flows;
    flows.list = {ie::QosFlowDescriptions::Description{qfi, 2, false, {}}};   // delete existing QoS flow description
    return modification(s, std::move(p), std::move(t), rules, flows);
}

void Smf::on_modify_response(const std::string& supi, std::uint8_t psi, const ngap::ModifyResponseTransfer& t) {
    auto it = sessions_.find({supi, psi});
    check(it != sessions_.end() && it->second.modifying.has_value(), "TS 38.413 8.2.3.2",
          "the modify response answers a modification the SMF asked for", std::to_string(psi));
    if (it == sessions_.end() || !it->second.modifying) {
        return;
    }
    Session& s = it->second;
    Session::Pending p = std::move(*s.modifying);
    s.modifying.reset();
    ++s.modifications;
    for (std::uint8_t q : p.added) {
        const bool done = std::find(t.added_or_modified.begin(), t.added_or_modified.end(), q) != t.added_or_modified.end();
        const bool failed = std::any_of(t.failed.begin(), t.failed.end(), [q](const auto& f) { return f.qfi == q; });
        check(done || failed, "TS 38.413 9.3.4.4", "the gNB answers every QoS flow it was asked to add",
              std::to_string(q));
        if (!done) {
            // Not set up: the rule stays out of the UPF (the UE keeps it until the SMF deletes it).
            p.rules.erase(std::remove_if(p.rules.begin(), p.rules.end(), [q](const auto& r) { return r.qfi == q; }), p.rules.end());
            p.flows.erase(std::remove_if(p.flows.begin(), p.flows.end(), [q](const auto& f) { return f.qfi == q; }), p.flows.end());
        }
    }
    s.rules = std::move(p.rules);
    s.setup->transfer.flows = std::move(p.flows);   // a reactivation sets up these
    if (upf_ != nullptr) {
        upf_->set_rules(s.ul_teid, s.rules);
    }
}

void Smf::on_modify_failed(const std::string& supi, std::uint8_t psi) {
    auto it = sessions_.find({supi, psi});
    if (it != sessions_.end()) {
        it->second.modifying.reset();
        ++it->second.modifications;
    }
}

std::optional<SmAction> Smf::on_notify(const std::string& supi, std::uint8_t psi, const std::vector<std::uint8_t>& released) {
    auto it = sessions_.find({supi, psi});
    check(it != sessions_.end(), "TS 38.413 8.2.4.2", "the notify names a session the SMF holds", std::to_string(psi));
    if (it == sessions_.end() || released.empty()) {
        return std::nullopt;
    }
    Session& s = it->second;
    ie::QosRules rules;
    ie::QosFlowDescriptions flows;
    for (std::uint8_t q : released) {
        check(q != p_.qfi, "TS 23.501 5.7.1.3", "the gNB released a flow other than the default QoS rule's", std::to_string(q));
        for (const auto& r : s.rules) {
            if (r.qfi == q && !r.default_rule) {
                ie::QosRules::Rule d;
                d.id = r.id;
                d.operation = 2;
                rules.list.push_back(d);
            }
        }
        s.rules.erase(std::remove_if(s.rules.begin(), s.rules.end(), [q](const auto& r) { return r.qfi == q && !r.default_rule; }),
                      s.rules.end());
        if (s.setup) {
            auto& fl = s.setup->transfer.flows;
            fl.erase(std::remove_if(fl.begin(), fl.end(), [q](const auto& f) { return f.qfi == q; }), fl.end());
        }
        flows.list.push_back(ie::QosFlowDescriptions::Description{q, 2, false, {}});
    }
    if (upf_ != nullptr) {
        upf_->set_rules(s.ul_teid, s.rules);
    }
    nas::Message c = make(kModificationCommand, psi, 0);
    if (!rules.list.empty()) {
        if (auto r = rules.encode()) {
            (void)nas::set(c, "Authorized QoS rules", std::move(*r));
        }
    }
    if (auto f = flows.encode()) {
        (void)nas::set(c, "Authorized QoS flow descriptions", std::move(*f));
    }
    auto wire = nas::encode(c);
    if (!wire) {
        return std::nullopt;
    }
    return SmAction{psi, std::move(*wire), std::nullopt, false, std::nullopt};
}

Result<void> Smf::ping_ue(const std::string& supi, std::uint8_t psi, std::uint16_t seq) {
    const Session* s = session(supi, psi);
    if (s == nullptr || upf_ == nullptr) {
        return make_error(Errc::invalid_argument, psi, "smf: no such session, or no UPF");
    }
    return upf_->ping_ue(s->ul_teid, p_.dn, seq);
}

} // namespace ksim::corestub
