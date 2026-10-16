// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/nas_sm/sm.hpp"

#include <algorithm>
#include <utility>

#include <fmt/format.h>

#include "codec/nas/build.hpp"
#include "platform/mutation.hpp"

namespace ksim::proc::ue {

namespace ie = nas::ie;

namespace {

// TS 24.501 Table 9.7.2
constexpr std::uint8_t kEstablishmentRequest = 0xC1;
constexpr std::uint8_t kEstablishmentAccept = 0xC2;
constexpr std::uint8_t kEstablishmentReject = 0xC3;
constexpr std::uint8_t kModificationCommand = 0xCB;
constexpr std::uint8_t kModificationComplete = 0xCC;
constexpr std::uint8_t kReleaseRequest = 0xD1;
constexpr std::uint8_t kReleaseReject = 0xD2;
constexpr std::uint8_t kReleaseCommand = 0xD3;
constexpr std::uint8_t kReleaseComplete = 0xD4;
constexpr std::uint8_t kStatus = 0xD6;

// Annex B
constexpr std::uint8_t kOperatorBarring = 8;
constexpr std::uint8_t kInsufficientResources = 26;
constexpr std::uint8_t kUnknownDnn = 27;
constexpr std::uint8_t kServiceOptionNotSupported = 32;
constexpr std::uint8_t kNotSubscribed = 33;
constexpr std::uint8_t kReactivationRequested = 39;
constexpr std::uint8_t kInvalidPsi = 43;
constexpr std::uint8_t kPtiMismatch = 47;
constexpr std::uint8_t kSliceDnnResources = 67;
constexpr std::uint8_t kSliceResources = 69;
constexpr std::uint8_t kUnknownDnnInSlice = 70;
constexpr std::uint8_t kQosSemanticError = 83;
constexpr std::uint8_t kInvalidMandatory = 96;
constexpr std::uint8_t kTypeNotImplemented = 97;

constexpr int kRetransmissions = 4;   // §6.4.1.6 a, §6.4.3.5 a: the fifth expiry aborts

std::string str(std::int64_t v) { return std::to_string(v); }

std::string ipv4_text(const std::array<std::uint8_t, 4>& a) { return fmt::format("{}.{}.{}.{}", a[0], a[1], a[2], a[3]); }

nas::Message make(std::uint8_t type, std::uint8_t psi, std::uint8_t pti) {
    auto m = nas::make(nas::Epd::sm, type);
    if (!m) {
        return {};
    }
    (void)nas::set(*m, "PDU session ID", Bytes{psi});
    (void)nas::set(*m, "PTI", Bytes{pti});
    return std::move(*m);
}

std::uint8_t cause_of(const nas::Message& m) {
    const Bytes* c = nas::get(m, "5GSM cause");
    return c != nullptr && !c->empty() ? (*c)[0] : 0;
}

/// §6.4.1.4.3: the causes whose Back-off timer value IE that clause does not cover.
bool outside_6_4_1_4_3(std::uint8_t c) {
    switch (c) {
    case 26: case 28: case 39: case 46: case 50: case 51: case 54: case 57: case 58: case 61: case 67: case 68:
    case 69: case 86:
        return true;
    default:
        return false;
    }
}

std::string key_part(const std::optional<ie::Snssai>& s) { return s ? snssai_text(*s) : std::string("-"); }

} // namespace

std::string snssai_text(const ie::Snssai& s) {
    return s.sd ? fmt::format("{:02x}-{:06x}", s.sst, *s.sd) : fmt::format("{:02x}", s.sst);
}

const char* sm_state_name(SmState s) noexcept {
    switch (s) {
    case SmState::inactive: return "PDU-SESSION-INACTIVE";
    case SmState::active_pending: return "PDU-SESSION-ACTIVE-PENDING";
    case SmState::active: return "PDU-SESSION-ACTIVE";
    case SmState::inactive_pending: return "PDU-SESSION-INACTIVE-PENDING";
    case SmState::modification_pending: return "PDU-SESSION-MODIFICATION-PENDING";
    }
    return "?";
}

Sm::Sm(Executor& ex, IEventSink& events, SmConfig cfg, std::function<Result<void>(const SmUplink&)> lower, SmUpper upper)
    : ex_(ex), events_(events), cfg_(std::move(cfg)), lower_(std::move(lower)), upper_(std::move(upper)),
      alive_(std::make_shared<bool>(true)) {}

Sm::~Sm() {
    *alive_ = false;
    for (auto& [psi, s] : sessions_) {
        if (s.proc && s.proc->timer) {
            ex_.stop_timer(*s.proc->timer);
        }
    }
    for (auto& [k, b] : backoffs_) {
        if (b.id) {
            ex_.stop_timer(*b.id);
        }
    }
}

std::uint8_t Sm::next_pti() {
    // §9.6: 1..254 are assigned values; 0 is "no PTI", 255 reserved.
    pti_ = static_cast<std::uint8_t>(pti_ >= 254 ? 1 : pti_ + 1);
    return pti_;
}

std::vector<SessionInfo> Sm::sessions() const {
    std::vector<SessionInfo> out;
    out.reserve(sessions_.size());
    for (const auto& [psi, s] : sessions_) {
        if (s.info.state != SmState::inactive) {
            out.push_back(s.info);
        }
    }
    return out;
}

const SessionInfo* Sm::session(std::uint8_t psi) const {
    auto it = sessions_.find(psi);
    return it != sessions_.end() && it->second.info.state != SmState::inactive ? &it->second.info : nullptr;
}

bool Sm::running(std::uint8_t psi) const {
    auto it = sessions_.find(psi);
    return it != sessions_.end() && it->second.proc && it->second.proc->timer;
}

bool Sm::backed_off(const std::string& dnn, const std::optional<ie::Snssai>& snssai) const {
    const std::string d = dnn.empty() ? "-" : dnn;
    return backoffs_.count(d + "|" + key_part(snssai)) != 0 || backoffs_.count(d + "|*") != 0 ||
           (snssai && backoffs_.count("*|" + key_part(snssai)) != 0);
}

void Sm::set_state(Session& s, SmState to) {
    if (s.info.state == to) {
        return;
    }
    events_.emit("nas.sm.state", cfg_.id,
                 {{"psi", str(s.info.psi)}, {"from", sm_state_name(s.info.state)}, {"to", sm_state_name(to)}});
    s.info.state = to;
}

// ---- UE-requested establishment (§6.4.1) -------------------------------------------------------

Result<std::uint8_t> Sm::establish(const SessionRequest& r) {
    std::uint8_t psi = r.psi;
    if (psi == 0) {
        for (std::uint8_t p = 1; p <= 15; ++p) {
            if (session(p) == nullptr) {
                psi = p;
                break;
            }
        }
        if (psi == 0) {
            return make_error(Errc::invalid_argument, 0, "5GSM: no free PDU session identity");
        }
    } else if (psi > 15 || session(psi) != nullptr) {
        return make_error(Errc::invalid_argument, psi, "5GSM: the PDU session identity is in use or not 1..15");
    }
    if (backed_off(r.dnn, r.snssai) && !KSIM_MUTANT("ignore_backoff")) {
        events_.emit("nas.sm.backoff.blocked", cfg_.id, {{"psi", str(psi)}, {"dnn", r.dnn}, {"snssai", key_part(r.snssai)}});
        return make_error(Errc::invalid_argument, psi, "5GSM: a back-off timer runs for this DNN and S-NSSAI");
    }
    Session& s = sessions_[psi];
    s = Session{};
    s.info.psi = psi;
    s.info.dnn = r.dnn;
    s.info.snssai = r.snssai;
    const std::uint8_t pti = next_pti();
    nas::Message m = make(kEstablishmentRequest, psi, pti);
    (void)nas::set(m, "Integrity protection maximum data rate",
                   ie::IntegrityProtectionMaxDataRate{cfg_.ip_max_rate_ul, cfg_.ip_max_rate_dl}.encode());
    (void)nas::set(m, "PDU session type", Bytes{ie::PduSessionType::ipv4});
    (void)nas::set(m, "SSC mode", Bytes{1});
    nas::Epco epco;
    epco.units = {nas::EpcoUnit{0x000D, {}, 0}, nas::EpcoUnit{0x0010, {}, 0}};
    if (auto e = nas::encode_epco(epco, nas::Direction::ul)) {
        (void)nas::set(m, "Extended protocol configuration options", std::move(*e));
    }
    auto wire = nas::encode(m);
    if (!wire) {
        sessions_.erase(psi);
        return wire.error();
    }
    Proc p;
    p.kind = Proc::Kind::establish;
    p.pti = pti;
    p.uplink = SmUplink{psi, std::move(*wire), ie::RequestType::initial, r.snssai,
                        r.dnn.empty() ? std::nullopt : std::optional<std::string>(r.dnn)};
    if (auto sent = lower_(p.uplink); !sent) {
        sessions_.erase(psi);
        return sent.error();
    }
    s.proc = std::move(p);
    set_state(s, SmState::active_pending);
    start_proc_timer(s);
    events_.emit("nas.sm.est.request", cfg_.id,
                 {{"psi", str(psi)}, {"pti", str(pti)}, {"dnn", r.dnn}, {"snssai", key_part(r.snssai)}, {"type", "ipv4"}});
    return psi;
}

void Sm::apply_flows(Session& s, const ie::QosFlowDescriptions& d, bool initial) {
    // P2 Q10 (TS 24.501 6.2.5.1.4, 9.11.4.12): create, delete, modify; the 5QI is kept.
    if (initial) {
        s.info.flow_5qi.clear();
    }
    for (const auto& f : d.list) {
        switch (f.operation) {
        case 1:   // create new QoS flow description
        case 3:   // modify existing QoS flow description
            if (const auto q = f.five_qi()) {
                s.info.flow_5qi[f.qfi] = *q;
            } else if (f.operation == 1) {
                s.info.flow_5qi[f.qfi] = 0;
            }
            break;
        case 2:   // delete existing QoS flow description
            s.info.flow_5qi.erase(f.qfi);
            break;
        default:
            break;
        }
    }
}

bool Sm::apply_rules(Session& s, const ie::QosRules& r, bool initial) {
    if (initial) {
        s.rules.clear();
    }
    for (const auto& rule : r.list) {
        auto it = std::find_if(s.rules.begin(), s.rules.end(), [&](const auto& x) { return x.id == rule.id; });
        switch (rule.operation) {
        case 1:   // create new QoS rule
            if (it != s.rules.end()) {
                *it = rule;
            } else {
                s.rules.push_back(rule);
            }
            break;
        case 2:   // delete existing QoS rule
            if (it != s.rules.end()) {
                s.rules.erase(it);
            }
            break;
        case 3:   // modify existing QoS rule and add packet filters
            if (it != s.rules.end()) {
                it->filters.insert(it->filters.end(), rule.filters.begin(), rule.filters.end());
            }
            break;
        case 4:   // modify existing QoS rule and replace all packet filters
            if (it != s.rules.end()) {
                it->filters = rule.filters;
            }
            break;
        case 5:   // modify existing QoS rule and delete packet filters
            if (it != s.rules.end()) {
                for (const auto& f : rule.filters) {
                    auto& fl = it->filters;
                    fl.erase(std::remove_if(fl.begin(), fl.end(), [&](const auto& x) { return x.id == f.id; }), fl.end());
                }
            }
            break;
        case 6:   // modify existing QoS rule without modifying packet filters
            if (it != s.rules.end()) {
                it->precedence = rule.precedence;
                it->qfi = rule.qfi;
            }
            break;
        default:
            break;
        }
    }
    s.info.qfis.clear();
    s.info.rules = s.rules;   // P2 Q10: the UE's classifier works from them (proc/ue/qos_classifier)
    int defaults = 0;
    for (const auto& rule : s.rules) {
        if (rule.qfi) {
            s.info.qfis.push_back(*rule.qfi);
        }
        if (rule.default_rule) {
            ++defaults;
            s.info.default_qfi = rule.qfi.value_or(0);
        }
    }
    return defaults == 1;   // §6.4.1.3 a 1) and 2)
}

void Sm::on_accept(Session& s, const nas::Message& m, std::uint8_t pti) {
    if (s.info.state != SmState::active_pending || !s.proc || s.proc->kind != Proc::Kind::establish || s.proc->pti != pti) {
        send_status(s.info.psi, pti, kPtiMismatch);   // §7.3.1 c
        return;
    }
    stop_proc(s);   // §6.4.1.3: T3580 stopped, the PTI released
    bool rules_ok = false;
    if (const Bytes* r = nas::get(m, "Authorized QoS rules")) {
        if (auto rules = ie::QosRules::decode(*r)) {
            rules_ok = apply_rules(s, *rules, true);
        }
    }
    if (const Bytes* d = nas::get(m, "Authorized QoS flow descriptions")) {
        if (auto flows = ie::QosFlowDescriptions::decode(*d)) {
            apply_flows(s, *flows, true);
        }
    }
    if (const Bytes* a = nas::get(m, "Session AMBR")) {
        if (auto ambr = ie::SessionAmbr::decode(*a)) {
            s.info.ambr_dl_bps = ambr->dl_bps();
            s.info.ambr_ul_bps = ambr->ul_bps();
        }
    }
    if (const Bytes* a = nas::get(m, "PDU address")) {
        if (auto addr = ie::PduAddress::decode(*a)) {
            s.info.ipv4 = addr->ipv4;
        }
    }
    if (const Bytes* e = nas::get(m, "Extended protocol configuration options")) {
        if (auto epco = nas::decode_epco(*e, nas::Direction::dl)) {
            for (const auto& u : epco->units) {
                if (u.id == 0x000D && !s.info.dns) {
                    if (auto d = ie::EpcoIpv4Dns::decode(u.contents)) {
                        s.info.dns = d->address;
                    }
                } else if (u.id == 0x0010) {
                    if (auto mtu = ie::EpcoIpv4LinkMtu::decode(u.contents)) {
                        s.info.mtu = mtu->mtu;   // §6.4.1.3: passed to the upper layers
                    }
                }
            }
        }
    }
    if (const Bytes* sn = nas::get(m, "S-NSSAI")) {
        if (auto v = ie::Snssai::decode(*sn)) {
            s.info.snssai = *v;
        }
    }
    if (const Bytes* d = nas::get(m, "DNN")) {
        if (auto v = ie::Dnn::decode(*d)) {
            s.info.dnn = v->name;
        }
    }
    std::uint8_t type = 0;
    if (const Bytes* t = nas::get(m, "Selected PDU session type"); t != nullptr && !t->empty()) {
        type = static_cast<std::uint8_t>((*t)[0] & 0x07);
    }
    set_state(s, SmState::active);
    events_.emit("nas.sm.est.accept", cfg_.id,
                 {{"psi", str(s.info.psi)},
                  {"pti", str(pti)},
                  {"dnn", s.info.dnn},
                  {"snssai", key_part(s.info.snssai)},
                  {"type", str(type)},
                  {"ip", s.info.ipv4 ? ipv4_text(*s.info.ipv4) : ""},
                  {"dns", s.info.dns ? ipv4_text(*s.info.dns) : ""},
                  {"mtu", s.info.mtu ? str(*s.info.mtu) : ""},
                  {"qfi", str(s.info.default_qfi)},
                  {"ambr_dl", s.info.ambr_dl_bps ? str(static_cast<std::int64_t>(*s.info.ambr_dl_bps)) : ""},
                  {"ambr_ul", s.info.ambr_ul_bps ? str(static_cast<std::int64_t>(*s.info.ambr_ul_bps)) : ""}});
    if (!rules_ok) {
        // §6.4.1.3: no default QoS rule, or more than one: release with #83.
        events_.emit("core.anomaly", cfg_.id,
                     {{"clause", "24.501 6.4.1.3"}, {"what", "the authorized QoS rules hold no single default QoS rule"},
                      {"psi", str(s.info.psi)}});
        (void)release(s.info.psi, kQosSemanticError);
        return;
    }
    if (type != ie::PduSessionType::ipv4 || !s.info.ipv4) {
        events_.emit("core.anomaly", cfg_.id,
                     {{"clause", "24.501 6.4.1.3"}, {"what", "an IPv4 request accepted without an IPv4 session and address"},
                      {"psi", str(s.info.psi)}});
    }
    if (upper_.up) {
        upper_.up(s.info);
    }
}

void Sm::start_backoff(const Session& s, std::uint8_t cause, const std::optional<ie::GprsTimer3>& t) {
    std::string timer = "back-off";
    std::string dnn = s.info.dnn.empty() ? "-" : s.info.dnn;
    std::string key;
    std::optional<std::int64_t> ms;
    bool forever = false;
    if (cause == kInsufficientResources || cause == kSliceDnnResources || cause == kSliceResources) {
        // §6.4.1.4.2: congestion; only with the IE.
        if (!t) {
            return;
        }
        timer = cause == kInsufficientResources ? "T3396" : cause == kSliceDnnResources ? "T3584" : "T3585";
        key = cause == kInsufficientResources ? dnn + "|*"
              : cause == kSliceDnnResources   ? dnn + "|" + key_part(s.info.snssai)
                                              : "*|" + key_part(s.info.snssai);
    } else if (outside_6_4_1_4_3(cause)) {
        return;
    } else {
        key = cause == kUnknownDnn ? dnn + "|*" : dnn + "|" + key_part(s.info.snssai);
        if (!t) {
            // Without the IE: the 12-minute default for these causes only.
            if (cause != kOperatorBarring && cause != kServiceOptionNotSupported && cause != kNotSubscribed &&
                cause != kUnknownDnnInSlice && cause != kUnknownDnn) {
                return;
            }
            ms = cfg_.default_backoff;
        }
    }
    if (t) {
        ms = t->ms();
        if (!ms) {
            forever = true;   // deactivated: until switch-off or USIM removal
        } else if (*ms == 0) {
            return;           // zero: another request may be sent
        }
    }
    if (auto old = backoffs_.find(key); old != backoffs_.end()) {
        if (const auto& id = old->second.id) {
            ex_.stop_timer(*id);
        }
    }
    Backoff b;
    b.timer = timer;
    if (!forever) {
        b.id = ex_.start_timer(*ms, [this, alive = alive_, key] {
            if (!*alive) {
                return;
            }
            auto it = backoffs_.find(key);
            if (it == backoffs_.end()) {
                return;
            }
            events_.emit("nas.sm.backoff.expiry", cfg_.id, {{"timer", it->second.timer}, {"key", key}});
            backoffs_.erase(it);
        });
    }
    backoffs_[key] = b;
    events_.emit("nas.sm.backoff", cfg_.id,
                 {{"timer", timer},
                  {"cause", str(cause)},
                  {"key", key},
                  {"seconds", forever ? "deactivated" : str(*ms / 1000)}});
}

void Sm::on_reject(Session& s, const nas::Message& m, std::uint8_t pti) {
    if (s.info.state != SmState::active_pending || !s.proc || s.proc->kind != Proc::Kind::establish || s.proc->pti != pti) {
        send_status(s.info.psi, pti, kPtiMismatch);   // §7.3.1 c
        return;
    }
    stop_proc(s);
    const std::uint8_t cause = cause_of(m);
    std::optional<ie::GprsTimer3> backoff;
    if (const Bytes* b = nas::get(m, "Back-off timer value")) {
        if (auto t = ie::GprsTimer3::decode(*b)) {
            backoff = *t;
        }
    }
    events_.emit("nas.sm.est.reject", cfg_.id, {{"psi", str(s.info.psi)}, {"pti", str(pti)}, {"cause", str(cause)}});
    start_backoff(s, cause, backoff);
    set_state(s, SmState::inactive);
}

// ---- release (§6.3.3, §6.4.3) ------------------------------------------------------------------

Result<void> Sm::release(std::uint8_t psi, std::uint8_t cause) {
    auto it = sessions_.find(psi);
    if (it == sessions_.end() || it->second.info.state != SmState::active) {
        return make_error(Errc::invalid_argument, psi, "5GSM: no active PDU session with this identity");
    }
    Session& s = it->second;
    const std::uint8_t pti = next_pti();
    nas::Message m = make(kReleaseRequest, psi, pti);
    (void)nas::set(m, "5GSM cause", Bytes{cause});
    auto wire = nas::encode(m);
    if (!wire) {
        return wire.error();
    }
    Proc p;
    p.kind = Proc::Kind::release;
    p.pti = pti;
    p.uplink = SmUplink{psi, std::move(*wire), std::nullopt, std::nullopt, std::nullopt};
    if (auto sent = lower_(p.uplink); !sent) {
        return sent.error();
    }
    s.proc = std::move(p);
    set_state(s, SmState::inactive_pending);
    start_proc_timer(s);
    events_.emit("nas.sm.rel.request", cfg_.id, {{"psi", str(psi)}, {"pti", str(pti)}, {"cause", str(cause)}});
    return {};
}

void Sm::on_release_command(Session& s, const nas::Message& m, std::uint8_t pti) {
    const bool network = pti == 0;
    if (!network) {
        const bool ours = s.proc && s.proc->kind == Proc::Kind::release && s.proc->pti == pti;
        if (!ours) {
            if (s.released_pti == pti) {
                // §7.3.1 b 1): a retransmission of an accepted request.
                nas::Message c = make(kReleaseComplete, s.info.psi, pti);
                send(s, c, std::nullopt);
            } else {
                send_status(s.info.psi, pti, kPtiMismatch);
            }
            return;
        }
    }
    const std::uint8_t cause = cause_of(m);
    events_.emit("nas.sm.rel.command", cfg_.id,
                 {{"psi", str(s.info.psi)}, {"pti", str(pti)}, {"cause", str(cause)}, {"network", network ? "1" : "0"}});
    stop_proc(s);
    const SessionRequest again{s.info.psi, s.info.dnn, s.info.snssai};
    nas::Message c = make(kReleaseComplete, s.info.psi, pti);
    send(s, c, std::nullopt);
    if (!network) {
        s.released_pti = pti;
    }
    release_local(s, "release command");
    if (cause == kReactivationRequested) {
        // §6.3.3.3: #39: the UE should establish the session again.
        ex_.post([this, alive = alive_, again] {
            if (*alive) {
                (void)establish(again);
            }
        });
    }
}

void Sm::on_release_reject(Session& s, const nas::Message& m, std::uint8_t pti) {
    if (!s.proc || s.proc->kind != Proc::Kind::release || s.proc->pti != pti) {
        send_status(s.info.psi, pti, kPtiMismatch);   // §7.3.1 b 2)
        return;
    }
    stop_proc(s);
    const std::uint8_t cause = cause_of(m);
    events_.emit("nas.sm.rel.reject", cfg_.id, {{"psi", str(s.info.psi)}, {"cause", str(cause)}});
    if (cause == kInvalidPsi) {
        release_local(s, "release reject #43");   // §6.4.3.4
        return;
    }
    set_state(s, SmState::active);
}

void Sm::release_local(Session& s, const char* why) {
    stop_proc(s);
    const bool was_up = s.info.state == SmState::active || s.info.state == SmState::inactive_pending ||
                        s.info.state == SmState::modification_pending;
    const std::uint8_t psi = s.info.psi;
    events_.emit("nas.sm.release", cfg_.id, {{"psi", str(psi)}, {"why", why}});
    set_state(s, SmState::inactive);
    const auto released = s.released_pti;
    s = Session{};
    s.info.psi = psi;
    s.released_pti = released;
    if (was_up && upper_.down) {
        upper_.down(psi);
    }
}

void Sm::release_all_local(const char* why) {
    for (auto& [psi, s] : sessions_) {
        if (s.info.state != SmState::inactive) {
            release_local(s, why);
        }
    }
    // §6.4.1.4.3: a "deactivated" back-off holds until switch-off; any running one ends with the UE.
    if (std::string_view(why) == "switch-off") {
        for (auto& [k, b] : backoffs_) {
            if (b.id) {
                ex_.stop_timer(*b.id);
            }
        }
        backoffs_.clear();
    }
}

std::uint16_t Sm::active_bitmap() const {
    std::uint16_t out = 0;
    for (const auto& [psi, s] : sessions_) {
        if (s.info.state != SmState::inactive && s.info.state != SmState::active_pending) {
            out = static_cast<std::uint16_t>(out | (1U << psi));
        }
    }
    return out;
}

void Sm::sync(std::uint16_t network) {
    for (auto& [psi, s] : sessions_) {
        const bool here = s.info.state != SmState::inactive && s.info.state != SmState::active_pending;
        if (here && (network & (1U << psi)) == 0) {
            release_local(s, "PDU session status");
        }
    }
}

// ---- network-requested modification (§6.3.2) ---------------------------------------------------

void Sm::on_modification_command(Session& s, const nas::Message& m, std::uint8_t pti) {
    if (pti != 0) {
        send_status(s.info.psi, pti, kPtiMismatch);   // §7.3.1 a 3): UE-requested modification is not P1
        return;
    }
    if (const Bytes* a = nas::get(m, "Session AMBR")) {
        if (auto ambr = ie::SessionAmbr::decode(*a)) {
            s.info.ambr_dl_bps = ambr->dl_bps();
            s.info.ambr_ul_bps = ambr->ul_bps();
        }
    }
    bool rules_ok = true;
    if (const Bytes* r = nas::get(m, "Authorized QoS rules")) {
        if (auto rules = ie::QosRules::decode(*r)) {
            rules_ok = apply_rules(s, *rules, false);
        }
    }
    if (const Bytes* d = nas::get(m, "Authorized QoS flow descriptions")) {
        if (auto flows = ie::QosFlowDescriptions::decode(*d)) {
            apply_flows(s, *flows, false);
        }
    }
    std::string qfis;
    for (const auto& rule : s.rules) {
        if (rule.qfi) {
            qfis += (qfis.empty() ? "" : ",") + str(*rule.qfi);
        }
    }
    events_.emit("nas.sm.mod.command", cfg_.id,
                 {{"psi", str(s.info.psi)}, {"cause", str(cause_of(m))}, {"qfi", str(s.info.default_qfi)},
                  {"ambr_dl", s.info.ambr_dl_bps ? str(static_cast<std::int64_t>(*s.info.ambr_dl_bps)) : ""},
                  {"rules", str(static_cast<std::int64_t>(s.rules.size()))}, {"qfis", qfis.empty() ? "-" : qfis}});
    nas::Message c = make(kModificationComplete, s.info.psi, pti);
    send(s, c, std::nullopt);
    if (!rules_ok) {
        events_.emit("core.anomaly", cfg_.id,
                     {{"clause", "24.501 6.3.2.3"}, {"what", "the modified QoS rules hold no single default QoS rule"},
                      {"psi", str(s.info.psi)}});
        (void)release(s.info.psi, kQosSemanticError);
        return;
    }
    if (upper_.up) {
        upper_.up(s.info);
    }
}

// ---- 5GSM STATUS (§6.5) and messages the AMF did not forward (§5.4.5.2.5) ---------------------

void Sm::on_status(Session& s, const nas::Message& m, std::uint8_t pti) {
    const std::uint8_t cause = cause_of(m);
    events_.emit("nas.sm.status", cfg_.id, {{"direction", "dl"}, {"psi", str(s.info.psi)}, {"cause", str(cause)}});
    if (cause == kInvalidPsi) {
        release_local(s, "5GSM STATUS #43");   // §6.5.3
        return;
    }
    if (cause == kPtiMismatch && s.proc && s.proc->pti == pti) {
        if (s.proc->kind == Proc::Kind::establish) {
            stop_proc(s);
            set_state(s, SmState::inactive);
        } else {
            release_local(s, "5GSM STATUS #47");
        }
    }
}

void Sm::not_forwarded(Session& s, std::uint8_t mm_cause, const std::optional<ie::GprsTimer3>& backoff) {
    events_.emit("nas.sm.not_forwarded", cfg_.id, {{"psi", str(s.info.psi)}, {"mm_cause", str(mm_cause)}});
    if (!s.proc) {
        return;
    }
    if (s.proc->kind == Proc::Kind::establish) {
        stop_proc(s);
        if (mm_cause == 22 && backoff) {
            start_backoff(s, kInsufficientResources, backoff);   // §6.2.7: DNN based congestion control
        }
        set_state(s, SmState::inactive);
        return;
    }
    release_local(s, "release request not forwarded");
}

void Sm::on_downlink(const SmDownlink& d) {
    if (d.psi == 0 || d.psi > 15) {
        return;   // §7.3.2 a: unassigned or reserved
    }
    auto it = sessions_.find(d.psi);
    if (const auto& cause = d.mm_cause) {
        if (it != sessions_.end()) {
            not_forwarded(it->second, *cause, d.backoff);
        }
        return;
    }
    if (d.sm.size() < 4 || d.sm[0] != static_cast<std::uint8_t>(nas::Epd::sm)) {
        return;
    }
    const std::uint8_t pti = d.sm[2];
    if (pti == 255) {
        return;   // §7.3.1 f
    }
    if (it == sessions_.end() || it->second.info.state == SmState::inactive) {
        if (d.sm[3] != kStatus) {
            send_status(d.psi, pti, kInvalidPsi);   // §7.3.2 b
        }
        return;
    }
    Session& s = it->second;
    auto m = nas::decode(d.sm);
    if (!m) {
        send_status(d.psi, pti, m.error().code == Errc::unsupported ? kTypeNotImplemented : kInvalidMandatory);
        return;
    }
    if (!nas::missing_mandatory(*m).empty()) {
        send_status(d.psi, pti, kInvalidMandatory);
        return;
    }
    const std::uint8_t type = m->desc->type;
    if (pti == 0 && (type == kEstablishmentAccept || type == kEstablishmentReject || type == kReleaseReject)) {
        return;   // §7.3.1 e
    }
    switch (type) {
    case kEstablishmentAccept: on_accept(s, *m, pti); return;
    case kEstablishmentReject: on_reject(s, *m, pti); return;
    case kReleaseCommand: on_release_command(s, *m, pti); return;
    case kReleaseReject: on_release_reject(s, *m, pti); return;
    case kModificationCommand: on_modification_command(s, *m, pti); return;
    case kStatus: on_status(s, *m, pti); return;
    default: send_status(d.psi, pti, kTypeNotImplemented); return;
    }
}

// ---- sending and timers ------------------------------------------------------------------------

void Sm::send(Session& s, const nas::Message& m, std::optional<std::uint8_t> request_type) {
    auto wire = nas::encode(m);
    if (!wire) {
        return;
    }
    (void)lower_(SmUplink{s.info.psi, std::move(*wire), request_type, std::nullopt, std::nullopt});
}

void Sm::send_status(std::uint8_t psi, std::uint8_t pti, std::uint8_t cause) {
    nas::Message m = make(kStatus, psi, pti);
    (void)nas::set(m, "5GSM cause", Bytes{cause});
    events_.emit("nas.sm.status", cfg_.id, {{"direction", "ul"}, {"psi", str(psi)}, {"cause", str(cause)}});
    auto wire = nas::encode(m);
    if (wire) {
        (void)lower_(SmUplink{psi, std::move(*wire), std::nullopt, std::nullopt, std::nullopt});
    }
}

void Sm::start_proc_timer(Session& s) {
    if (!s.proc) {
        return;
    }
    if (s.proc->timer) {
        ex_.stop_timer(*s.proc->timer);
    }
    const Millis ms = s.proc->kind == Proc::Kind::establish ? cfg_.timers.t3580 : cfg_.timers.t3582;
    s.proc->timer = ex_.start_timer(ms, [this, alive = alive_, psi = s.info.psi] {
        if (*alive) {
            on_expiry(psi);
        }
    });
}

void Sm::stop_proc(Session& s) {
    if (s.proc && s.proc->timer) {
        ex_.stop_timer(*s.proc->timer);
    }
    s.proc.reset();
}

void Sm::on_expiry(std::uint8_t psi) {
    auto it = sessions_.find(psi);
    if (it == sessions_.end() || !it->second.proc) {
        return;
    }
    Session& s = it->second;
    if (!s.proc) {
        return;
    }
    Proc& p = *s.proc;
    p.timer.reset();
    ++p.expiries;
    const char* timer = p.kind == Proc::Kind::establish ? "T3580" : "T3582";
    events_.emit("nas.sm.timer.expiry", cfg_.id, {{"psi", str(psi)}, {"timer", timer}, {"count", str(p.expiries)}});
    if (p.expiries > kRetransmissions) {
        // §6.4.1.6 a: the establishment is aborted; §6.4.3.5 a: the session released locally.
        if (p.kind == Proc::Kind::establish) {
            stop_proc(s);
            events_.emit("nas.sm.est.abort", cfg_.id, {{"psi", str(psi)}, {"why", "T3580"}});
            set_state(s, SmState::inactive);
        } else {
            release_local(s, "T3582");
        }
        return;
    }
    (void)lower_(p.uplink);
    start_proc_timer(s);
}

} // namespace ksim::proc::ue
