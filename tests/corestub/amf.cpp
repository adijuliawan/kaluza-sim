// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "amf.hpp"

#include <algorithm>
#include <utility>

#include "codec/nas/build.hpp"
#include "crypto/keys5g.hpp"

namespace ksim::corestub {

namespace {

namespace ie = nas::ie;
using proc::ue::NasRole;
using proc::ue::NasSecurityContext;
using proc::ue::Sht;

constexpr std::uint8_t kRegistrationRequest = 0x41;
constexpr std::uint8_t kRegistrationAccept = 0x42;
constexpr std::uint8_t kRegistrationComplete = 0x43;
constexpr std::uint8_t kRegistrationReject = 0x44;
constexpr std::uint8_t kDeregistrationRequestUe = 0x45;
constexpr std::uint8_t kDeregistrationAcceptUe = 0x46;
constexpr std::uint8_t kAuthenticationRequest = 0x56;
constexpr std::uint8_t kAuthenticationResponse = 0x57;
constexpr std::uint8_t kAuthenticationReject = 0x58;
constexpr std::uint8_t kAuthenticationFailure = 0x59;
constexpr std::uint8_t kSecurityModeCommand = 0x5D;
constexpr std::uint8_t kSecurityModeComplete = 0x5E;
constexpr std::uint8_t kSecurityModeReject = 0x5F;
constexpr std::uint8_t kStatus = 0x64;

constexpr Millis kT3560 = 6'000;   // TS 24.501 Table 10.2.1
const Bytes kAbba{0x00, 0x00};

nas::Message make(std::uint8_t type) {
    auto m = nas::make(nas::Epd::mm, type);
    return m ? std::move(*m) : nas::Message{};
}

void put(nas::Message& m, std::string_view name, Bytes v) { (void)nas::set(m, name, std::move(v)); }
void put(nas::Message& m, std::string_view name, const Result<Bytes>& v) {
    if (v) {
        put(m, name, *v);
    }
}

std::uint8_t cause_of(const nas::Message& m) {
    const Bytes* c = nas::get(m, "5GMM cause");
    return c != nullptr && !c->empty() ? (*c)[0] : 0;
}

ie::GprsTimer3 timer3(int s) {
    if (s % 3600 == 0 && s / 3600 <= 31) {
        return {1, static_cast<std::uint8_t>(s / 3600)};
    }
    if (s % 60 == 0 && s / 60 <= 31) {
        return {5, static_cast<std::uint8_t>(s / 60)};
    }
    if (s % 30 == 0 && s / 30 <= 31) {
        return {4, static_cast<std::uint8_t>(s / 30)};
    }
    return {3, static_cast<std::uint8_t>(std::min(s / 2, 31))};
}

ie::GprsTimer timer2(int s) {
    if (s % 60 == 0 && s / 60 <= 31) {
        return {1, static_cast<std::uint8_t>(s / 60)};
    }
    return {0, static_cast<std::uint8_t>(std::min(s / 2, 31))};
}

Profile::Challenge challenge_named(const std::string& s, const Yaml& at) {
    using C = Profile::Challenge;
    if (s == "ok") return C::ok;
    if (s == "bad_mac") return C::bad_mac;
    if (s == "stale_sqn") return C::stale_sqn;
    if (s == "non_5g") return C::non_5g;
    if (s == "lose_response") return C::lose_response;
    if (s == "reject") return C::reject;
    if (s == "none") return C::none;
    throw YamlError(at.where(), at.path(), "unknown challenge '" + s + "'");
}

} // namespace

Profile Profile::from_yaml(const Yaml& y) {
    y.only({"challenges", "ea", "ia", "imeisv_request", "rinmr", "tamper_replayed_capabilities", "registration",
            "reject_cause", "tmsi", "amf_region", "amf_set", "amf_pointer", "tacs", "allowed_sst", "t3512_s",
            "t3502_s", "deregistration"});
    Profile p;
    if (y.has("challenges")) {
        p.challenges.clear();
        const Yaml c = y.at("challenges");
        for (std::size_t i = 0; i < c.size(); ++i) {
            p.challenges.push_back(challenge_named(c.at(i).as<std::string>(), c.at(i)));
        }
    }
    p.ea = static_cast<std::uint8_t>(y.get<int>("ea", p.ea));
    p.ia = static_cast<std::uint8_t>(y.get<int>("ia", p.ia));
    p.imeisv_request = y.get<bool>("imeisv_request", p.imeisv_request);
    p.rinmr = y.get<bool>("rinmr", p.rinmr);
    p.tamper_replayed_capabilities = y.get<bool>("tamper_replayed_capabilities", p.tamper_replayed_capabilities);
    const std::string r = y.get<std::string>("registration", "accept");
    if (r == "accept") {
        p.registration = Registration::accept;
    } else if (r == "reject") {
        p.registration = Registration::reject;
    } else if (r == "silent") {
        p.registration = Registration::silent;
    } else if (r == "accept_plain") {
        p.registration = Registration::accept_plain;
    } else {
        throw YamlError(y.at("registration").where(), y.at("registration").path(), "unknown registration '" + r + "'");
    }
    p.reject_cause = static_cast<std::uint8_t>(y.get<int>("reject_cause", p.reject_cause));
    p.tmsi = y.get<std::uint32_t>("tmsi", p.tmsi);
    p.amf_region = static_cast<std::uint8_t>(y.get<int>("amf_region", p.amf_region));
    p.amf_set = static_cast<std::uint16_t>(y.get<int>("amf_set", p.amf_set));
    p.amf_pointer = static_cast<std::uint8_t>(y.get<int>("amf_pointer", p.amf_pointer));
    if (y.has("tacs")) {
        p.tacs.clear();
        for (std::size_t i = 0; i < y.at("tacs").size(); ++i) {
            p.tacs.push_back(y.at("tacs").at(i).as<std::uint32_t>());
        }
    }
    if (y.has("allowed_sst")) {
        p.allowed_sst.clear();
        for (std::size_t i = 0; i < y.at("allowed_sst").size(); ++i) {
            p.allowed_sst.push_back(static_cast<std::uint8_t>(y.at("allowed_sst").at(i).as<int>()));
        }
    }
    if (y.has("t3512_s")) {
        p.t3512_s = y.at("t3512_s").is_null() ? std::nullopt : std::optional<int>(y.at("t3512_s").as<int>());
    }
    if (y.has("t3502_s")) {
        p.t3502_s = y.at("t3502_s").is_null() ? std::nullopt : std::optional<int>(y.at("t3502_s").as<int>());
    }
    const std::string d = y.get<std::string>("deregistration", "accept");
    if (d != "accept" && d != "silent") {
        throw YamlError(y.at("deregistration").where(), y.at("deregistration").path(),
                        "unknown deregistration '" + d + "'");
    }
    p.deregistration = d == "accept" ? Deregistration::accept : Deregistration::silent;
    return p;
}

Amf::Amf(Executor& ex, Home& home, ie::Plmn plmn, Profile p)
    : ex_(ex), home_(home), plmn_(std::move(plmn)), p_(std::move(p)), alive_(std::make_shared<bool>(true)) {}

Amf::~Amf() {
    *alive_ = false;
    stop_t3560();
}

void Amf::check(bool ok, const char* clause, const char* what, std::string detail) {
    verdicts_.push_back(Verdict{clause, what, ok, std::move(detail)});
}

std::vector<Verdict> Amf::failures() const {
    std::vector<Verdict> out;
    std::copy_if(verdicts_.begin(), verdicts_.end(), std::back_inserter(out), [](const Verdict& v) { return !v.ok; });
    return out;
}

std::size_t Amf::count_uplink(std::string_view name) const {
    return static_cast<std::size_t>(std::count(uplink_.begin(), uplink_.end(), name));
}

// ---- uplink ------------------------------------------------------------------------------

void Amf::on_uplink(ByteView wire, bool initial) {
    if (wire.size() < 3 || wire[0] != static_cast<std::uint8_t>(nas::Epd::mm)) {
        check(false, "9.2", "an uplink 5GMM message", "EPD or length");
        return;
    }
    const auto sht = static_cast<Sht>(wire[1] & 0x0F);
    if (sht == Sht::plain) {
        auto m = nas::decode(wire);
        if (!m) {
            check(false, "8", "the uplink message decodes", m.error().what);
            return;
        }
        on_message(*m, sht, initial);
        return;
    }
    if (!ctx_) {
        check(false, "4.4.3.3", "a protected uplink message has a context to check it with");
        return;
    }
    proc::ue::Inbound in = ctx_->unprotect(wire);
    check(in.verdict == proc::ue::Verdict::ok, "4.4.3.3", "the uplink MAC verifies", proc::ue::verdict_name(in.verdict));
    if (in.verdict != proc::ue::Verdict::ok) {
        return;
    }
    const std::uint32_t expected = last_ul_ ? *last_ul_ + 1 : 0;
    check(in.count == expected, "4.4.3.1", "the uplink NAS COUNT advances by one",
          "COUNT " + std::to_string(in.count) + ", expected " + std::to_string(expected));
    last_ul_ = in.count;
    auto m = nas::decode(in.plain);
    if (!m) {
        check(false, "8", "the uplink message decodes", m.error().what);
        return;
    }
    on_message(*m, in.sht, initial);
}

void Amf::on_message(const nas::Message& m, Sht sht, bool initial) {
    uplink_.emplace_back(m.desc->name);
    const auto missing = nas::missing_mandatory(m);
    check(missing.empty(), "8.2", "the mandatory IEs are present", missing.empty() ? "" : std::string(missing.front()));
    const std::uint8_t type = m.desc->type;
    if (sht == Sht::plain && state_ == State::registered && !(initial && type == kRegistrationRequest)) {
        check(false, "4.4.4.3", "no plain message once secure exchange is up", m.desc->name);
        return;
    }
    switch (type) {
    case kRegistrationRequest:
        on_registration_request(m, initial);
        return;
    case kAuthenticationResponse:
        on_authentication_response(m);
        return;
    case kAuthenticationFailure:
        on_authentication_failure(m);
        return;
    case kSecurityModeComplete:
        on_security_mode_complete(m, sht);
        return;
    case kSecurityModeReject:
        on_security_mode_reject(m);
        return;
    case kRegistrationComplete:
        check(state_ == State::accepting, "5.5.1.2.4", "REGISTRATION COMPLETE answers a REGISTRATION ACCEPT");
        check(sht == Sht::integrity_ciphered, "4.4.5", "REGISTRATION COMPLETE is integrity protected and ciphered");
        if (state_ == State::accepting) {
            state_ = State::registered;
        }
        return;
    case kDeregistrationRequestUe:
        on_deregistration_request(m);
        return;
    case kStatus:
        return;   // recorded in uplink_
    default:
        check(false, "5", "an uplink message the stub expects", m.desc->name);
        return;
    }
}

void Amf::on_registration_request(const nas::Message& m, bool initial) {
    check(initial, "5.5.1.2.2", "REGISTRATION REQUEST is the initial NAS message");
    stop_t3560();
    // A new N1 connection and a new procedure: what the stub knew of the last one goes.
    ctx_.reset();
    last_ul_.reset();
    av_.reset();
    lost_one_ = false;
    state_ = State::idle;
    initial_ = m;
    initial_had_context_ = false;
    auto split = proc::ue::split_initial(m);
    check(split && !split->has_non_cleartext, "4.4.6", "without a context the initial message holds cleartext IEs only");
    const Bytes* rt = nas::get(m, "5GS registration type");
    auto type = rt ? ie::RegistrationType::decode(*rt) : Result<ie::RegistrationType>(make_error(Errc::truncated, 0, ""));
    check(type && type->value == ie::RegistrationType::initial, "5.5.1.2.2", "the registration type is initial");
    const Bytes* k = nas::get(m, "ngKSI");
    auto ngksi = k ? ie::NgKsi::decode(*k) : Result<ie::NgKsi>(make_error(Errc::truncated, 0, ""));
    check(ngksi && ngksi->none(), "4.4.6, 9.11.3.32", "a plain initial message names no key (ngKSI 7)");
    const Bytes* caps = nas::get(m, "UE security capability");
    auto c = caps ? ie::UeSecurityCapability::decode(*caps)
                  : Result<ie::UeSecurityCapability>(make_error(Errc::truncated, 0, ""));
    check(c.has_value(), "5.5.1.2.2", "the UE security capability is included");
    ue_caps_ = c ? std::optional<ie::UeSecurityCapability>(*c) : std::nullopt;
    const Bytes* idv = nas::get(m, "5GS mobile identity");
    auto id = idv ? ie::MobileIdentity::decode(*idv) : Result<ie::MobileIdentity>(make_error(Errc::truncated, 0, ""));
    supi_.clear();
    if (id && id->type == ie::MobileIdentity::Type::suci) {
        check(id->protection_scheme == 0 && id->hn_key_id == 0, "TS 33.501 6.12.2", "the SUCI uses the null scheme (D6)");
        const std::string msin = id->null_scheme_msin();
        supi_ = home_.find(id->plmn.mcc, id->plmn.mnc, msin);
        check(!supi_.empty(), "TS 33.501 6.12.2, TS 23.003 2.2B",
              "a null-scheme SUCI's output is the MSIN of a known subscriber", "MSIN " + msin);
    } else if (id && id->type == ie::MobileIdentity::Type::guti) {
        const bool known = guti_ && guti_->tmsi == id->tmsi && guti_->amf_region == id->amf_region &&
                           guti_->amf_set == id->amf_set && guti_->amf_pointer == id->amf_pointer;
        check(known, "5.5.1.2.2", "the 5G-GUTI is the one this AMF assigned");
        if (known) {
            supi_ = guti_supi_;   // an unknown 5G-GUTI needs identification, which is N12
        }
    } else {
        check(false, "5.5.1.2.2", "the identity is a SUCI or a 5G-GUTI");
    }
    if (supi_.empty() || p_.registration == Profile::Registration::silent) {
        return;
    }
    challenges_ = 0;
    start_challenge();
}

Profile::Challenge Amf::challenge_kind() const {
    const auto i = static_cast<std::size_t>(std::max(challenges_ - 1, 0));
    return p_.challenges.at(std::min(i, p_.challenges.size() - 1));
}

void Amf::start_challenge() {
    ++challenges_;
    const Profile::Challenge kind = challenge_kind();
    if (kind == Profile::Challenge::none) {
        state_ = State::idle;
        return;
    }
    if (kind == Profile::Challenge::reject) {
        av_kind_ = kind;
        send(make(kAuthenticationReject), ctx_.has_value());
        state_ = State::released;
        release();
        return;
    }
    auto snn = crypto::keys5g::serving_network_name(plmn_.mcc, plmn_.mnc);
    AvOptions o;
    o.corrupt_mac = kind == Profile::Challenge::bad_mac;
    o.separation_bit = kind != Profile::Challenge::non_5g;
    if (kind == Profile::Challenge::stale_sqn) {
        o.seq = 0;   // never fresh: the USIM has accepted SEQ 0 or later (TS 33.102 C.2.2)
    }
    auto av = home_.make_av(supi_, snn ? *snn : std::string(), kAbba, o);
    check(av.has_value(), "TS 33.501 6.1.3.2", "the home functions made an authentication vector");
    if (!av) {
        return;
    }
    av_ = std::move(*av);
    av_kind_ = kind;
    ngksi_ = ie::NgKsi{false, next_ngksi_};
    next_ngksi_ = static_cast<std::uint8_t>(next_ngksi_ % 6 + 1);
    nas::Message r = make(kAuthenticationRequest);
    put(r, "ngKSI", ngksi_.encode());
    put(r, "ABBA", kAbba);
    put(r, "Authentication parameter RAND (5G authentication challenge)", av_->rand);
    put(r, "Authentication parameter AUTN (5G authentication challenge)", av_->autn);
    state_ = State::authenticating;
    send(r, false);
    t3560_expiries_ = 0;
    start_t3560();
}

void Amf::on_authentication_response(const nas::Message& m) {
    check(state_ == State::authenticating, "5.4.1.3.4", "AUTHENTICATION RESPONSE answers a challenge");
    if (state_ != State::authenticating || !av_ || !av_kind_) {
        return;
    }
    if (*av_kind_ == Profile::Challenge::lose_response && !lost_one_) {
        lost_one_ = true;   // T3560 runs on and the same challenge goes again (§5.4.1.3.7 b)
        return;
    }
    stop_t3560();
    const bool valid = *av_kind_ == Profile::Challenge::ok || *av_kind_ == Profile::Challenge::lose_response;
    check(valid, "5.4.1.3.7", "the UE answers only a valid challenge with a response");
    const Bytes* r = nas::get(m, "Authentication response parameter");
    const bool match = r != nullptr && ct_equal(av_->xres_star, *r);
    check(match, "5.4.1.3.4; TS 33.501 6.1.3.2", "RES* equals XRES*");
    if (valid && match) {
        send_security_mode_command();
    }
}

void Amf::on_authentication_failure(const nas::Message& m) {
    check(state_ == State::authenticating, "5.4.1.3.7", "AUTHENTICATION FAILURE answers a challenge");
    if (state_ != State::authenticating || !av_ || !av_kind_) {
        return;
    }
    stop_t3560();
    const std::uint8_t cause = cause_of(m);
    std::uint8_t expected = 0;
    switch (*av_kind_) {
    case Profile::Challenge::bad_mac: expected = 20; break;
    case Profile::Challenge::stale_sqn: expected = 21; break;
    case Profile::Challenge::non_5g: expected = 26; break;
    default: break;
    }
    check(cause == expected, "5.4.1.3.7 c, d, f", "the failure cause fits the challenge",
          "#" + std::to_string(cause) + ", expected #" + std::to_string(expected));
    if (cause == 21) {
        const Bytes* auts = nas::get(m, "Authentication failure parameter");
        check(auts != nullptr && auts->size() == 14, "5.4.1.3.7 f, 9.11.3.14", "a synch failure carries AUTS");
        if (auts != nullptr) {
            auto ok = home_.resync(supi_, av_->rand, *auts);
            check(ok && *ok, "TS 33.102 6.3.5", "MAC-S in AUTS verifies");
            ++resyncs_;
        }
    }
    start_challenge();
}

void Amf::send_security_mode_command() {
    if (!av_ || !ue_caps_) {
        return;
    }
    ie::UeSecurityCapability caps = *ue_caps_;
    if (p_.tamper_replayed_capabilities) {
        caps.ea = static_cast<std::uint8_t>(caps.ea ^ 0x20);   // flip 128-5G-EA2
    }
    nas::Message c = make(kSecurityModeCommand);
    put(c, "Selected NAS security algorithms", ie::NasSecurityAlgorithms{p_.ea, p_.ia}.encode());
    put(c, "ngKSI", ngksi_.encode());
    put(c, "Replayed UE security capabilities", caps.encode());
    imeisv_asked_ = p_.imeisv_request;
    if (p_.imeisv_request) {
        put(c, "IMEISV request", ie::ImeisvRequest{true}.encode());
    }
    if (p_.rinmr) {
        put(c, "Additional 5G security information", ie::Additional5gSecurityInformation{true, false}.encode());
    }
    auto plain = nas::encode(c);
    if (!plain) {
        return;
    }
    state_ = State::securing;
    last_ul_.reset();
    if (p_.ia == 0) {
        // 5G-IA0: a null MAC (TS 33.501 D.1); the stub's context refuses it, so build the header by hand.
        ctx_.reset();
        downlink(nas::encode_protected(nas::Protected{3, 0, 0, 0, *plain}));
        start_t3560();
        return;
    }
    auto ctx = NasSecurityContext::derive(ngksi_, av_->kamf.clone(), p_.ea, p_.ia, NasRole::network);
    check(ctx.has_value(), "5.4.2.2", "the AMF derived the new context");
    if (!ctx) {
        return;
    }
    ctx_ = std::move(*ctx);
    auto wire = ctx_->protect(*plain, Sht::integrity_new);
    if (wire) {
        pending_ = *plain;
        pending_plain_ = false;
        downlink(std::move(*wire));
        t3560_expiries_ = 0;
        start_t3560();
    }
}

void Amf::on_security_mode_complete(const nas::Message& m, Sht sht) {
    check(state_ == State::securing, "5.4.2.3", "SECURITY MODE COMPLETE answers a SECURITY MODE COMMAND");
    if (state_ != State::securing) {
        return;
    }
    stop_t3560();
    check(sht == Sht::integrity_ciphered_new, "5.4.2.3",
          "SECURITY MODE COMPLETE is integrity protected and ciphered with the new context");
    check(last_ul_ && *last_ul_ == 0, "5.4.2.3", "the uplink NAS COUNT is reset after 5G AKA");
    smc_count_ = last_ul_;
    const Bytes* imeisv = nas::get(m, "IMEISV");
    check((imeisv != nullptr) == imeisv_asked_, "5.4.2.3", "the IMEISV is included exactly when the AMF asked");
    if (imeisv != nullptr) {
        auto id = ie::MobileIdentity::decode(*imeisv);
        check(id && id->type == ie::MobileIdentity::Type::imeisv && id->digits.size() == 16, "9.11.3.4",
              "the IMEISV is sixteen digits");
    }
    const Bytes* container = nas::get(m, "NAS message container");
    const bool want = !initial_had_context_ || p_.rinmr;
    check((container != nullptr) == want, "5.4.2.3, 4.4.6",
          "the whole REGISTRATION REQUEST is returned when the UE had no context or RINMR asked");
    if (container != nullptr) {
        auto full = nas::decode(*container);
        const bool same = full && full->desc != nullptr && full->desc->type == kRegistrationRequest &&
                          nas::get(*full, "5GS mobile identity") != nullptr &&
                          *nas::get(*full, "5GS mobile identity") == *nas::get(initial_, "5GS mobile identity") &&
                          nas::get(*full, "UE security capability") != nullptr &&
                          *nas::get(*full, "UE security capability") == *nas::get(initial_, "UE security capability");
        check(same, "4.4.6", "the container repeats the initial message's cleartext IEs");
    }
    send_registration_result();
}

void Amf::on_security_mode_reject(const nas::Message& m) {
    check(state_ == State::securing, "5.4.2.5", "SECURITY MODE REJECT answers a SECURITY MODE COMMAND");
    stop_t3560();
    const std::uint8_t cause = cause_of(m);
    const std::uint8_t expected = p_.tamper_replayed_capabilities ? 23 : 24;
    check(cause == expected, "5.4.2.5", "the reject cause fits the command",
          "#" + std::to_string(cause) + ", expected #" + std::to_string(expected));
    ctx_.reset();
    state_ = State::released;
    release();   // §5.4.2.5: the AMF aborts the procedure the command was part of
}

void Amf::send_registration_result() {
    switch (p_.registration) {
    case Profile::Registration::accept:
    case Profile::Registration::accept_plain: {
        ie::MobileIdentity g;
        g.type = ie::MobileIdentity::Type::guti;
        g.plmn = plmn_;
        g.amf_region = p_.amf_region;
        g.amf_set = p_.amf_set;
        g.amf_pointer = p_.amf_pointer;
        g.tmsi = p_.tmsi;
        guti_ = g;
        guti_supi_ = supi_;
        nas::Message a = make(kRegistrationAccept);
        put(a, "5GS registration result", ie::RegistrationResult{}.encode());
        put(a, "5G-GUTI", g.encode());
        ie::TaiList tl;
        for (std::uint32_t tac : p_.tacs) {
            tl.tais.push_back(ie::Tai{plmn_, tac});
        }
        put(a, "TAI list", tl.encode());
        ie::Nssai allowed;
        for (std::uint8_t sst : p_.allowed_sst) {
            allowed.list.push_back(ie::Snssai{sst, std::nullopt, std::nullopt, std::nullopt});
        }
        if (!allowed.list.empty()) {
            put(a, "Allowed NSSAI", allowed.encode());
        }
        if (p_.t3512_s) {
            put(a, "T3512 value", timer3(*p_.t3512_s).encode());
        }
        if (p_.t3502_s) {
            put(a, "T3502 value", timer2(*p_.t3502_s).encode());
        }
        state_ = State::accepting;
        if (link_.initial_context && p_.registration == Profile::Registration::accept && ctx_) {
            auto plain = nas::encode(a);
            auto wire = plain ? ctx_->protect(*plain, Sht::integrity_ciphered) : Result<Bytes>(plain.error());
            auto key = kgnb();
            check(wire.has_value() && key.has_value(), "TS 33.501 6.8.1.2.2", "the AMF has K_gNB for the accept");
            if (wire && key) {
                link_.initial_context(std::move(*wire), std::move(*key));
            }
            return;
        }
        send(a, p_.registration == Profile::Registration::accept);
        return;
    }
    case Profile::Registration::reject: {
        nas::Message r = make(kRegistrationReject);
        put(r, "5GMM cause", Bytes{p_.reject_cause});
        send(r, true);
        state_ = State::released;
        release();
        return;
    }
    case Profile::Registration::silent:
        return;
    }
}

void Amf::on_deregistration_request(const nas::Message& m) {
    const Bytes* t = nas::get(m, "De-registration type");
    auto dt = t ? ie::DeregistrationType::decode(*t)
                : Result<ie::DeregistrationType>(make_error(Errc::truncated, 0, ""));
    check(dt && dt->access == 1, "5.5.2.2.1, 9.11.3.20", "the de-registration is for 3GPP access");
    const Bytes* idv = nas::get(m, "5GS mobile identity");
    auto id = idv ? ie::MobileIdentity::decode(*idv) : Result<ie::MobileIdentity>(make_error(Errc::truncated, 0, ""));
    if (guti_ && state_ == State::registered) {
        check(id && id->type == ie::MobileIdentity::Type::guti && id->tmsi == guti_->tmsi, "5.5.2.2.1",
              "a UE with a valid 5G-GUTI de-registers with it");
    }
    if (!dt) {
        return;
    }
    const bool was_secure = ctx_.has_value() && state_ == State::registered;
    state_ = State::idle;
    if (dt->switch_off) {
        // §5.5.2.2.2: no accept for a switch-off; the AMF still releases the
        // UE's N2 context (TS 23.502 4.2.2.3.2 step 8).
        release();
        return;
    }
    if (p_.deregistration == Profile::Deregistration::silent) {
        return;
    }
    send(make(kDeregistrationAcceptUe), was_secure);
    release();
}

// ---- downlink -----------------------------------------------------------------------------

void Amf::send(const nas::Message& m, bool protect) {
    auto plain = nas::encode(m);
    if (!plain) {
        check(false, "8", "the stub encoded its message", plain.error().what);
        return;
    }
    if (m.desc->type == kAuthenticationRequest) {
        pending_ = *plain;
        pending_plain_ = !protect;
    }
    if (!protect || !ctx_) {
        downlink(std::move(*plain));
        return;
    }
    auto wire = ctx_->protect(*plain, Sht::integrity_ciphered);
    if (wire) {
        downlink(std::move(*wire));
    }
}

void Amf::send_plain(Bytes plain) { downlink(std::move(plain)); }

Result<SecretBytes> Amf::kgnb() const {
    if (!ctx_ || !smc_count_) {
        return make_error(Errc::invalid_argument, 0, "stub: no context for K_gNB");
    }
    return crypto::keys5g::kgnb(ctx_->kamf(), *smc_count_);
}

void Amf::send_protected(Bytes plain) {
    if (!ctx_) {
        return;
    }
    auto wire = ctx_->protect(plain, Sht::integrity_ciphered);
    if (wire) {
        downlink(std::move(*wire));
    }
}

void Amf::downlink(Bytes wire) {
    if (link_.to_ue) {
        link_.to_ue(std::move(wire));
    }
}

void Amf::release() {
    stop_t3560();
    if (link_.release) {
        link_.release();
    }
}

void Amf::on_ue_released() {
    stop_t3560();
    if (state_ != State::registered) {
        state_ = State::idle;
    }
}

void Amf::start_t3560() {
    stop_t3560();
    t3560_ = ex_.start_timer(kT3560, [this, alive = alive_] {
        if (!*alive) {
            return;
        }
        t3560_.reset();
        // §5.4.1.3.7 b, §5.4.2.7 b: four retransmissions, then abort.
        if (++t3560_expiries_ >= 5) {
            t3560_expiries_ = 0;
            state_ = State::released;
            release();
            return;
        }
        if (state_ == State::authenticating) {
            downlink(pending_);   // the same challenge, the same RAND
        } else if (state_ == State::securing && ctx_) {
            auto wire = ctx_->protect(pending_, Sht::integrity_new);
            if (wire) {
                downlink(std::move(*wire));
            }
        }
        start_t3560();
    });
}

void Amf::stop_t3560() {
    if (t3560_) {
        ex_.stop_timer(*t3560_);
        t3560_.reset();
    }
}

} // namespace ksim::corestub
