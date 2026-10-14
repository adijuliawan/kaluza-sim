// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/nas_mm/mm.hpp"

#include <string>
#include <utility>

#include "codec/nas/build.hpp"
#include "crypto/kdf.hpp"
#include "crypto/keys5g.hpp"
#include "platform/mutation.hpp"
#include "proc/ue/nas_mm/suci.hpp"

namespace ksim::proc::ue {

namespace {

namespace ie = nas::ie;

// 5GMM message types (TS 24.501 Table 9.7.1).
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

// 5GMM causes (Annex A).
constexpr std::uint8_t kIllegalUe = 3;
constexpr std::uint8_t kIllegalMe = 6;
constexpr std::uint8_t kServicesNotAllowed = 7;
constexpr std::uint8_t kPlmnNotAllowed = 11;
constexpr std::uint8_t kTaNotAllowed = 12;
constexpr std::uint8_t kRoamingNotAllowedInTa = 13;
constexpr std::uint8_t kNoSuitableCells = 15;
constexpr std::uint8_t kMacFailure = 20;
constexpr std::uint8_t kSynchFailure = 21;
constexpr std::uint8_t kCapabilitiesMismatch = 23;
constexpr std::uint8_t kSecurityModeRejected = 24;
constexpr std::uint8_t kNon5gAuthentication = 26;
constexpr std::uint8_t kN1ModeNotAllowed = 27;
constexpr std::uint8_t kNgKsiInUse = 71;
constexpr std::uint8_t kInvalidMandatory = 96;
constexpr std::uint8_t kTypeNotImplemented = 97;
constexpr std::uint8_t kNotCompatibleWithState = 98;

constexpr int kMaxAttempts = 5;

std::string str(std::int64_t v) { return std::to_string(v); }

ByteView text(const std::string& s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }

nas::Message make(std::uint8_t type) {
    auto m = nas::make(nas::Epd::mm, type);
    return m ? std::move(*m) : nas::Message{};
}

void put(nas::Message& m, std::string_view name, Bytes value) { (void)nas::set(m, name, std::move(value)); }

void put(nas::Message& m, std::string_view name, const Result<Bytes>& value) {
    if (value) {
        put(m, name, *value);
    }
}

std::string hex_digits(std::uint32_t v, int digits) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(static_cast<std::size_t>(digits), '0');
    for (int i = digits - 1; i >= 0; --i, v >>= 4) {
        out[static_cast<std::size_t>(i)] = kHex[v & 0x0F];
    }
    return out;
}

/// "00101-ca-001-01-12345678": PLMN, AMF region, set and pointer, 5G-TMSI.
std::string guti_text(const ie::MobileIdentity& g) {
    return g.plmn.mcc + g.plmn.mnc + "-" + hex_digits(g.amf_region, 2) + "-" + hex_digits(g.amf_set, 3) + "-" +
           hex_digits(g.amf_pointer, 2) + "-" + hex_digits(g.tmsi, 8);
}

} // namespace

const char* mm_timer_name(MmTimer t) noexcept {
    switch (t) {
    case MmTimer::t3502: return "T3502";
    case MmTimer::t3510: return "T3510";
    case MmTimer::t3511: return "T3511";
    case MmTimer::t3516: return "T3516";
    case MmTimer::t3520: return "T3520";
    case MmTimer::t3521: return "T3521";
    }
    return "?";
}

Mm::Mm(Executor& ex, uicc::Terminal& card, INasLower& lower, IEventSink& events, MmConfig cfg)
    : ex_(ex), card_(card), lower_(lower), events_(events), cfg_(std::move(cfg)), alive_(std::make_shared<bool>(true)) {}

Mm::~Mm() {
    *alive_ = false;
    for (auto& t : timers_) {
        if (t) {
            ex_.stop_timer(*t);
        }
    }
}

// ---- power on and the subscription -------------------------------------------------

void Mm::power_on() {
    if (state_ != MmState::null) {
        return;
    }
    coro::spawn(read_card(alive_));
}

coro::Task<void> Mm::read_card(std::shared_ptr<bool> alive) {
    auto atr = co_await card_.power_on();
    bool ok = atr && co_await card_.select_usim();
    std::optional<Subscription> sub;
    std::string ri = "0";
    if (ok) {
        auto imsi = co_await card_.read_ef({0x6F07});
        auto ad = co_await card_.read_ef({0x6FAD});
        if (imsi && ad) {
            auto s = read_subscription(*imsi, *ad);
            if (s) {
                sub = std::move(*s);
            }
        }
        auto r = co_await card_.read_ef({0x5FC0, 0x4F0A});   // DF.5GS/EF.Routing_Indicator
        if (r) {
            ri = read_routing_indicator(*r);
        }
    }
    if (!*alive) {
        co_return;
    }
    usim_valid_ = sub.has_value();
    attempts_ = 0;   // §5.5.1.2.1: reset when the UE is powered on
    if (sub) {
        supi_ = sub->imsi;
        msin_ = sub->msin;
        home_ = sub->home;
        routing_indicator_ = ri;
    }
    events_.emit("nas.mm.power_on", cfg_.id,
                 {{"usim", usim_valid_ ? "valid" : "invalid"}, {"supi", usim_valid_ ? "imsi-" + supi_ : ""}});
    set_state(usim_valid_ ? MmState::deregistered_normal_service : MmState::deregistered_no_supi, "power on");
}

// ---- registration (§5.5.1.2) -------------------------------------------------------

void Mm::register_initial() {
    if (!usim_valid_ || !is_deregistered(state_)) {
        return;
    }
    start_registration();
}

ie::MobileIdentity Mm::identity() const {
    if (guti_) {
        return *guti_;
    }
    return null_suci(Subscription{supi_, home_, msin_}, routing_indicator_);
}

ie::NgKsi Mm::current_ngksi() const { return ctx_ ? ctx_->ngksi() : ie::NgKsi{false, 7}; }

void Mm::start_registration() {
    stop(MmTimer::t3511);
    stop(MmTimer::t3502);
    // Until N12 brings the protected initial message (§4.4.6), an initial
    // registration starts without a 5G NAS security context.
    ctx_.reset();
    partial_.reset();
    kgnb_count_.reset();
    ++gen_;
    nas::Message m = make(kRegistrationRequest);
    put(m, "5GS registration type", ie::RegistrationType{ie::RegistrationType::initial, cfg_.follow_on_request}.encode());
    put(m, "ngKSI", current_ngksi().encode());
    const ie::MobileIdentity id = identity();
    put(m, "5GS mobile identity", id.encode());
    put(m, "UE security capability", cfg_.security.encode());
    if (!cfg_.requested_nssai.empty()) {
        put(m, "Requested NSSAI", ie::Nssai{cfg_.requested_nssai}.encode());
    }
    initial_ = m;
    initial_without_context_ = true;
    // §4.4.6: without a valid context only the cleartext IEs go in the initial message.
    auto split = split_initial(m);
    if (!split) {
        return;
    }
    auto wire = nas::encode(split->cleartext);
    if (!wire) {
        return;
    }
    events_.emit("nas.reg.request", cfg_.id,
                 {{"type", "initial"},
                  {"identity", guti_ ? "5g-guti" : "suci"},
                  {"attempt", str(attempts_ + 1)}});
    set_state(MmState::registered_initiated, "registration request");
    if (cfg_.tap) {
        cfg_.tap(true, *wire);
    }
    send_wire(std::move(*wire));
    start(MmTimer::t3510, cfg_.timers.t3510);
}

void Mm::registration_abnormal(const char* reason) {
    // §5.5.1.2.7, cases c, d and e.
    stop(MmTimer::t3510);
    paused_t3510_ = false;
    if (attempts_ < kMaxAttempts) {
        ++attempts_;
    }
    events_.emit("nas.reg.abort", cfg_.id, {{"reason", reason}, {"attempt", str(attempts_)}});
    if (attempts_ < kMaxAttempts) {
        set_state(MmState::deregistered_attempting_registration, "registration attempt failed");
        start(MmTimer::t3511, cfg_.timers.t3511);
        return;
    }
    update_ = UpdateStatus::u2_not_updated;
    delete_registration_data(true);
    set_state(MmState::deregistered_attempting_registration, "fifth registration attempt failed");
    const Millis t3502 = t3502_net_.value_or(cfg_.timers.t3502);
    if (t3502 == 0) {
        on_expiry(MmTimer::t3502);
        return;
    }
    start(MmTimer::t3502, t3502);
}

void Mm::on_registration_accept(const nas::Message& m) {
    if (state_ != MmState::registered_initiated) {
        send_status(kNotCompatibleWithState);
        return;
    }
    const Bytes* result_v = nas::get(m, "5GS registration result");
    auto result = result_v ? ie::RegistrationResult::decode(*result_v) : Result<ie::RegistrationResult>(
                                                                              make_error(Errc::truncated, 0, "absent"));
    if (!result) {
        send_status(kInvalidMandatory);
        return;
    }
    stop(MmTimer::t3510);
    paused_t3510_ = false;
    attempts_ = 0;
    update_ = UpdateStatus::u1_updated;
    bool new_guti = false;
    if (const Bytes* g = nas::get(m, "5G-GUTI")) {
        auto id = ie::MobileIdentity::decode(*g);
        if (id && id->type == ie::MobileIdentity::Type::guti) {
            guti_ = std::move(*id);
            new_guti = true;
        }
    }
    if (const Bytes* t = nas::get(m, "TAI list")) {
        auto l = ie::TaiList::decode(*t);
        if (l) {
            tai_list_ = std::move(*l);
        }
    }
    allowed_nssai_.clear();
    if (const Bytes* a = nas::get(m, "Allowed NSSAI")) {
        auto n = ie::Nssai::decode(*a);
        if (n) {
            allowed_nssai_ = std::move(n->list);
        }
    }
    if (const Bytes* t = nas::get(m, "T3512 value")) {
        auto v = ie::GprsTimer3::decode(*t);
        if (v) {
            t3512_ = v->ms();
        }
    }
    t3502_net_.reset();
    if (const Bytes* t = nas::get(m, "T3502 value")) {
        auto v = ie::GprsTimer2::decode(*t);
        if (v) {
            t3502_net_ = v->ms();
        }
    }
    std::string nssai;
    for (const auto& s : allowed_nssai_) {
        nssai += (nssai.empty() ? "" : ",") + str(s.sst);
    }
    events_.emit("nas.reg.accept", cfg_.id,
                 {{"guti", guti_ ? guti_text(*guti_) : ""},
                  {"tai_count", str(tai_list_ ? static_cast<std::int64_t>(tai_list_->tais.size()) : 0)},
                  {"t3512_s", t3512_ ? str(*t3512_ / 1000) : "deactivated"},
                  {"allowed_nssai", nssai},
                  {"sms_allowed", result->sms_allowed ? "1" : "0"}});
    set_state(MmState::registered_normal_service, "registration accept");
    if (new_guti) {
        // §5.5.1.2.4: a 5G-GUTI in the accept is acknowledged.
        send(make(kRegistrationComplete));
        events_.emit("nas.reg.complete", cfg_.id, {});
    }
}

void Mm::on_registration_reject(const nas::Message& m) {
    if (state_ != MmState::registered_initiated) {
        send_status(kNotCompatibleWithState);
        return;
    }
    const Bytes* c = nas::get(m, "5GMM cause");
    const std::uint8_t cause = (c != nullptr && !c->empty()) ? (*c)[0] : 111;
    stop(MmTimer::t3510);
    paused_t3510_ = false;
    events_.emit("nas.reg.reject", cfg_.id, {{"cause", str(cause)}});
    switch (cause) {
    case kIllegalUe:
    case kIllegalMe:
    case kServicesNotAllowed:
        update_ = UpdateStatus::u3_roaming_not_allowed;
        delete_registration_data(true);
        usim_valid_ = false;
        set_state(MmState::deregistered_no_supi, "registration reject #3, #6 or #7");
        return;
    case kPlmnNotAllowed:
        update_ = UpdateStatus::u3_roaming_not_allowed;
        delete_registration_data(true);
        attempts_ = 0;
        set_state(MmState::deregistered_plmn_search, "registration reject #11");
        return;
    case kTaNotAllowed:
    case kRoamingNotAllowedInTa:
    case kNoSuitableCells:
        update_ = UpdateStatus::u3_roaming_not_allowed;
        delete_registration_data(true);
        attempts_ = 0;
        set_state(MmState::deregistered_limited_service, "registration reject #12, #13 or #15");
        return;
    case kN1ModeNotAllowed:
        update_ = UpdateStatus::u3_roaming_not_allowed;
        delete_registration_data(true);
        attempts_ = 0;
        set_state(MmState::deregistered_limited_service, "registration reject #27");
        return;
    default:
        // §5.5.1.2.7 d. N12 gives #22, #62, #72 and the rest their own handling.
        if (cause == 95 || cause == 96 || cause == 97 || cause == 99 || cause == 111) {
            attempts_ = kMaxAttempts;
        }
        registration_abnormal("reject");
        return;
    }
}

void Mm::delete_registration_data(bool guti_and_ngksi) {
    tai_list_.reset();
    if (guti_and_ngksi) {
        guti_.reset();
        ctx_.reset();
        partial_.reset();
    }
}

// ---- de-registration (§5.5.2.2) ----------------------------------------------------

void Mm::deregister(bool switch_off) {
    if (state_ != MmState::registered_initiated && !is_registered(state_)) {
        return;
    }
    // §5.5.1.2.7 f: an initial registration in progress is aborted, and the
    // request carries the identity that registration used.
    stop(MmTimer::t3510);
    stop(MmTimer::t3511);
    stop(MmTimer::t3502);
    paused_t3510_ = false;
    ++gen_;
    nas::Message m = make(kDeregistrationRequestUe);
    put(m, "De-registration type", ie::DeregistrationType{switch_off, false, 1}.encode());
    put(m, "ngKSI", current_ngksi().encode());
    put(m, "5GS mobile identity", identity().encode());
    dereg_ = m;
    dereg_switch_off_ = switch_off;
    t3521_expiries_ = 0;
    events_.emit("nas.dereg.sent", cfg_.id,
                 {{"switch_off", switch_off ? "1" : "0"}, {"identity", guti_ ? "5g-guti" : "suci"}, {"transmission", "1"}});
    send(m);
    if (switch_off) {
        // §5.5.2.2.1: the UE may be switched off as soon as the request is sent.
        for (std::size_t i = 0; i < kMmTimerCount; ++i) {
            stop(static_cast<MmTimer>(i));
        }
        clear_stored_challenge();
        lower_.release_local();
        connected_ = false;
        set_state(MmState::null, "switch off");
        return;
    }
    set_state(MmState::deregistered_initiated, "de-registration request");
    start(MmTimer::t3521, cfg_.timers.t3521);
}

void Mm::on_deregistration_accept() {
    if (state_ != MmState::deregistered_initiated) {
        send_status(kNotCompatibleWithState);
        return;
    }
    stop(MmTimer::t3521);
    paused_t3521_ = false;
    events_.emit("nas.dereg.accept", cfg_.id, {});
    set_state(MmState::deregistered_normal_service, "de-registration accept");
}

// ---- 5G AKA (§5.4.1.3) ---------------------------------------------------------------

void Mm::on_authentication_request(const nas::Message& m) {
    const Bytes* ngksi_v = nas::get(m, "ngKSI");
    const Bytes* abba_v = nas::get(m, "ABBA");
    const Bytes* rand_v = nas::get(m, "Authentication parameter RAND (5G authentication challenge)");
    const Bytes* autn_v = nas::get(m, "Authentication parameter AUTN (5G authentication challenge)");
    if (ngksi_v == nullptr || abba_v == nullptr || rand_v == nullptr || autn_v == nullptr) {
        // EAP-AKA' (an EAP message instead of RAND and AUTN) is N12.
        send_status(rand_v == nullptr && nas::get(m, "EAP message") != nullptr ? kTypeNotImplemented
                                                                                : kInvalidMandatory);
        return;
    }
    auto ngksi = ie::NgKsi::decode(*ngksi_v);
    auto rand = ie::Rand::decode(*rand_v);
    auto autn = ie::Autn::decode(*autn_v);
    if (!ngksi || !rand || !autn) {
        send_status(kInvalidMandatory);
        return;
    }
    // §5.4.1.3.7: a challenge while T3520 runs is a consecutive one.
    const bool consecutive = running(MmTimer::t3520);
    stop(MmTimer::t3520);
    if (!consecutive) {
        auth_failures_ = 0;
    }
    if (!stored_rand_.empty() && stored_rand_ == rand->value) {
        // §5.4.1.3.3: the same RAND again: the stored RES*, without the USIM.
        nas::Message r = make(kAuthenticationResponse);
        put(r, "Authentication response parameter", stored_res_star_);
        events_.emit("nas.auth.response", cfg_.id, {{"ngksi", str(ngksi->value)}, {"stored", "1"}});
        send(r);
        return;
    }
    if (ctx_ && !ngksi->mapped && ctx_->ngksi().value == ngksi->value) {
        send_authentication_failure(kNgKsiInUse, {});
        return;
    }
    if ((autn->value.at(6) & 0x80) == 0) {
        // TS 33.501 §6.1.3.2: the AMF separation bit must be 1 for 5G.
        send_authentication_failure(kNon5gAuthentication, {});
        return;
    }
    coro::spawn(run_aka(alive_, gen_, *ngksi, rand->value, autn->value, *abba_v));
}

coro::Task<void> Mm::run_aka(std::shared_ptr<bool> alive, std::uint64_t gen, ie::NgKsi ngksi, Bytes rand, Bytes autn,
                             Bytes abba) {
    auto out = co_await card_.authenticate(rand, autn);
    if (!*alive || gen != gen_) {
        co_return;
    }
    if (!out) {
        send_authentication_failure(kMacFailure, {});
        co_return;
    }
    if (out->kind == uicc::AuthOutcome::Kind::sync_failure) {
        send_authentication_failure(kSynchFailure, std::move(out->auts));
        co_return;
    }
    if (out->kind != uicc::AuthOutcome::Kind::success) {
        send_authentication_failure(kMacFailure, {});
        co_return;
    }
    auto snn = crypto::keys5g::serving_network_name(cfg_.plmn.mcc, cfg_.plmn.mnc);
    if (!snn) {
        co_return;
    }
    const ByteView sqn_xor_ak = ByteView(autn).subspan(0, 6);
    SecretBytes res_star = crypto::keys5g::res_star(out->ck, out->ik, *snn, rand, out->res);
    SecretBytes kausf = crypto::keys5g::kausf(out->ck, out->ik, *snn, sqn_xor_ak);
    SecretBytes kseaf = crypto::keys5g::kseaf(kausf, *snn);
    SecretBytes kamf;
    if (KSIM_MUTANT("kamf_input_sbi_spelling")) {
        const std::string uri = "imsi-" + supi_;   // the SBI form, which TS 33.501 A.7.0 does not use
        kamf = crypto::kdf(kseaf.expose(), 0x6D, {text(uri), abba});
    } else {
        auto k = crypto::keys5g::kamf(kseaf, supi_, abba);
        if (!k) {
            co_return;
        }
        kamf = std::move(*k);
    }
    partial_ = Partial{ngksi, std::move(kamf)};
    stored_rand_ = rand;
    stored_res_star_ = Bytes(res_star.expose().begin(), res_star.expose().end());   // sent in clear
    start(MmTimer::t3516, cfg_.timers.t3516);
    auth_failures_ = 0;
    resume_retransmission_timers();
    nas::Message r = make(kAuthenticationResponse);
    put(r, "Authentication response parameter", stored_res_star_);
    events_.emit("nas.auth.response", cfg_.id, {{"ngksi", str(ngksi.value)}, {"stored", "0"}});
    send(r);
}

void Mm::send_authentication_failure(std::uint8_t cause, Bytes auts) {
    // §5.4.1.3.7 c-f: the retransmission timers stop, T3520 starts.
    if (running(MmTimer::t3510)) {
        stop(MmTimer::t3510);
        paused_t3510_ = true;
    }
    if (running(MmTimer::t3521)) {
        stop(MmTimer::t3521);
        paused_t3521_ = true;
    }
    ++auth_failures_;
    events_.emit("nas.auth.failure", cfg_.id, {{"cause", str(cause)}, {"consecutive", str(auth_failures_)}});
    if (auth_failures_ >= 3) {
        network_failed_authentication();
        return;
    }
    nas::Message f = make(kAuthenticationFailure);
    put(f, "5GMM cause", Bytes{cause});
    if (cause == kSynchFailure) {
        put(f, "Authentication failure parameter", std::move(auts));
    }
    send(f);
    start(MmTimer::t3520, cfg_.timers.t3520);
}

void Mm::network_failed_authentication() {
    // §5.4.1.3.7 g: release locally and treat the cell as barred (P1 has one
    // fixed cell, ledger A-12: the event says so); resume the paused timers.
    stop(MmTimer::t3520);
    auth_failures_ = 0;
    events_.emit("nas.auth.network_failed", cfg_.id, {});
    resume_retransmission_timers();
    clear_stored_challenge();
    if (connected_) {
        lower_.release_local();
        connected_ = false;
    }
}

void Mm::resume_retransmission_timers() {
    if (paused_t3510_) {
        paused_t3510_ = false;
        start(MmTimer::t3510, cfg_.timers.t3510);
    }
    if (paused_t3521_) {
        paused_t3521_ = false;
        start(MmTimer::t3521, cfg_.timers.t3521);
    }
}

void Mm::on_authentication_reject(bool integrity_ok) {
    // §5.4.1.3.7 m: a plain reject counts only while T3516 or T3520 runs.
    if (!integrity_ok && !running(MmTimer::t3516) && !running(MmTimer::t3520)) {
        events_.emit("nas.sec.discard", cfg_.id, {{"message", "AUTHENTICATION REJECT"}, {"verdict", "unprotected"}});
        return;
    }
    // §5.4.1.3.5.
    for (MmTimer t : {MmTimer::t3510, MmTimer::t3516, MmTimer::t3520, MmTimer::t3521}) {
        stop(t);
    }
    paused_t3510_ = paused_t3521_ = false;
    ++gen_;
    clear_stored_challenge();
    update_ = UpdateStatus::u3_roaming_not_allowed;
    delete_registration_data(true);
    attempts_ = 0;
    usim_valid_ = false;
    events_.emit("nas.auth.reject", cfg_.id, {});
    set_state(MmState::deregistered_no_supi, "authentication reject");
}

void Mm::clear_stored_challenge() {
    stored_rand_.clear();
    secure_zero(stored_res_star_);
    stored_res_star_.clear();
    stop(MmTimer::t3516);
}

// ---- security mode control (§5.4.2) --------------------------------------------------

void Mm::on_security_mode_command(ByteView wire) {
    auto p = nas::decode_protected(wire);
    auto m = p ? nas::decode(p->payload) : Result<nas::Message>(make_error(Errc::malformed, 0, "protected"));
    if (!m || m->desc == nullptr || m->desc->type != kSecurityModeCommand) {
        events_.emit("nas.sec.discard", cfg_.id, {{"message", "?"}, {"verdict", "new context, not a SECURITY MODE COMMAND"}});
        return;
    }
    const Bytes* alg_v = nas::get(*m, "Selected NAS security algorithms");
    const Bytes* ngksi_v = nas::get(*m, "ngKSI");
    const Bytes* caps_v = nas::get(*m, "Replayed UE security capabilities");
    auto alg = alg_v ? ie::NasSecurityAlgorithms::decode(*alg_v)
                     : Result<ie::NasSecurityAlgorithms>(make_error(Errc::truncated, 0, "absent"));
    auto ngksi = ngksi_v ? ie::NgKsi::decode(*ngksi_v) : Result<ie::NgKsi>(make_error(Errc::truncated, 0, "absent"));
    auto caps = caps_v ? ie::UeSecurityCapability::decode(*caps_v)
                       : Result<ie::UeSecurityCapability>(make_error(Errc::truncated, 0, "absent"));
    if (!alg || !ngksi || !caps) {
        reject_security_mode(kSecurityModeRejected);
        return;
    }
    // The K_AMF the ngKSI names: the one the last 5G AKA made, or the current context's.
    const SecretBytes* kamf = nullptr;
    bool current_kamf = false;
    if (partial_ && partial_->ngksi == *ngksi) {
        kamf = &partial_->kamf;
    } else if (ctx_ && ctx_->ngksi() == *ngksi) {
        kamf = &ctx_->kamf();
        current_kamf = true;
    }
    // §5.4.2.3: 5G-IA0 only for emergency, which P1 does not have; an algorithm
    // the UE did not offer cannot be taken into use either.
    if (kamf == nullptr || alg->integrity == 0 || !cfg_.security.supports_ia(alg->integrity) ||
        !cfg_.security.supports_ea(alg->ciphering)) {
        reject_security_mode(kSecurityModeRejected);
        return;
    }
    auto candidate = NasSecurityContext::derive(*ngksi, kamf->clone(), alg->ciphering, alg->integrity);
    if (!candidate) {
        reject_security_mode(kSecurityModeRejected);
        return;
    }
    if (current_kamf) {
        // The current K_AMF with new algorithms: the COUNTs go on (§4.4.3.1),
        // so a replayed command does not verify.
        candidate->restore_counts(ctx_->ul_count(), ctx_->dl_count());
    }
    // The integrity check with the candidate context, before anything else is believed.
    Inbound in = candidate->unprotect(wire);
    if (in.verdict != Verdict::ok) {
        events_.emit("nas.sec.discard", cfg_.id, {{"message", "SECURITY MODE COMMAND"}, {"verdict", verdict_name(in.verdict)}});
        return;
    }
    if (cfg_.tap) {
        cfg_.tap(false, in.plain);
    }
    if (!(*caps == cfg_.security)) {
        reject_security_mode(kCapabilitiesMismatch);
        return;
    }
    clear_stored_challenge();
    ctx_ = std::move(*candidate);
    partial_.reset();

    nas::Message c = make(kSecurityModeComplete);
    bool imeisv = false;
    if (const Bytes* r = nas::get(*m, "IMEISV request")) {
        auto req = ie::ImeisvRequest::decode(*r);
        imeisv = req && req->requested && !cfg_.imeisv.empty();
    }
    if (imeisv) {
        ie::MobileIdentity id;
        id.type = ie::MobileIdentity::Type::imeisv;
        id.digits = cfg_.imeisv;
        put(c, "IMEISV", id.encode());
    }
    bool rinmr = false;
    if (const Bytes* a = nas::get(*m, "Additional 5G security information")) {
        auto info = ie::Additional5gSecurityInformation::decode(*a);
        rinmr = info && info->rinmr;
    }
    // §5.4.2.3: the whole REGISTRATION REQUEST when the network asks for it, or
    // when the UE had no valid context when it sent it.
    const bool container = state_ == MmState::registered_initiated && (rinmr || initial_without_context_);
    if (container) {
        put(c, "NAS message container", nas::encode(initial_));
    }
    auto plain = nas::encode(c);
    if (!plain) {
        return;
    }
    kgnb_count_ = ctx_->ul_count();   // the SECURITY MODE COMPLETE's COUNT (TS 33.501 6.8.1.2.2)
    if (cfg_.tap) {
        cfg_.tap(true, *plain);
    }
    auto out = ctx_->protect(*plain, Sht::integrity_ciphered_new);
    if (!out) {
        return;
    }
    events_.emit("nas.smc.complete", cfg_.id,
                 {{"ea", str(ctx_->ea())},
                  {"ia", str(ctx_->ia())},
                  {"ngksi", str(ngksi->value)},
                  {"imeisv", imeisv ? "1" : "0"},
                  {"container", container ? "1" : "0"}});
    send_wire(std::move(*out));
}

void Mm::reject_security_mode(std::uint8_t cause) {
    // §5.4.2.5: protected with the context in use before, if any.
    nas::Message r = make(kSecurityModeReject);
    put(r, "5GMM cause", Bytes{cause});
    events_.emit("nas.smc.reject", cfg_.id, {{"cause", str(cause)}});
    send(r);
}

// ---- AS keys ---------------------------------------------------------------------------

Result<SecretBytes> Mm::kgnb() const {
    if (!ctx_ || !kgnb_count_) {
        return make_error(Errc::invalid_argument, 0, "5GMM: no 5G NAS security context for K_gNB");
    }
    std::uint32_t count = *kgnb_count_;
    if (KSIM_MUTANT("kgnb_wrong_ul_count")) {
        count = ctx_->ul_count();   // the next uplink COUNT, not the SECURITY MODE COMPLETE's
    }
    return crypto::keys5g::kgnb(ctx_->kamf(), count);
}

std::optional<std::uint64_t> Mm::s_tmsi() const noexcept {
    if (!guti_) {
        return std::nullopt;
    }
    return (static_cast<std::uint64_t>(guti_->amf_set & 0x3FF) << 38) |
           (static_cast<std::uint64_t>(guti_->amf_pointer & 0x3F) << 32) | guti_->tmsi;
}

// ---- receiving -------------------------------------------------------------------------

void Mm::on_nas(ByteView wire) {
    if (state_ == MmState::null) {
        return;
    }
    connected_ = true;
    if (wire.size() < 3 || wire[0] != static_cast<std::uint8_t>(nas::Epd::mm)) {
        return;   // 5GSM is N10; anything else is not 5GMM's
    }
    const auto sht = static_cast<Sht>(wire[1] & 0x0F);
    if (sht == Sht::integrity_new) {
        on_security_mode_command(wire);
        return;
    }
    if (sht == Sht::plain) {
        auto m = nas::decode(wire);
        if (!m) {
            // Once secure exchange is up a plain message is not processed at
            // all (§4.4.4.2); before, a status says what was wrong (§7).
            if (!ctx_) {
                send_status(m.error().code == Errc::unsupported ? kTypeNotImplemented : kInvalidMandatory);
            }
            return;
        }
        if (cfg_.tap) {
            cfg_.tap(false, wire);
        }
        if (!processed_unprotected(*m, ctx_.has_value())) {
            events_.emit("nas.sec.discard", cfg_.id,
                         {{"message", m->desc != nullptr ? m->desc->name : "?"}, {"verdict", "unprotected"}});
            return;
        }
        on_plain(*m, false);
        return;
    }
    if (!ctx_) {
        events_.emit("nas.sec.discard", cfg_.id, {{"message", "?"}, {"verdict", verdict_name(Verdict::discard_no_context)}});
        return;
    }
    Inbound in = ctx_->unprotect(wire);
    if (in.verdict != Verdict::ok) {
        events_.emit("nas.sec.discard", cfg_.id, {{"message", "?"}, {"verdict", verdict_name(in.verdict)}});
        return;
    }
    if (cfg_.tap) {
        cfg_.tap(false, in.plain);
    }
    auto m = nas::decode(in.plain);
    if (!m) {
        send_status(m.error().code == Errc::unsupported ? kTypeNotImplemented : kInvalidMandatory);
        return;
    }
    on_plain(*m, true);
}

void Mm::on_plain(const nas::Message& m, bool integrity_ok) {
    if (m.desc->epd != nas::Epd::mm) {
        return;
    }
    if (!nas::missing_mandatory(m).empty()) {
        send_status(kInvalidMandatory);
        return;
    }
    switch (m.desc->type) {
    case kAuthenticationRequest:
        on_authentication_request(m);
        return;
    case kAuthenticationReject:
        on_authentication_reject(integrity_ok);
        return;
    case kRegistrationAccept:
        on_registration_accept(m);
        return;
    case kRegistrationReject:
        on_registration_reject(m);
        return;
    case kDeregistrationAcceptUe:
        on_deregistration_accept();
        return;
    case kSecurityModeCommand:
        // Only with a new context (security header type 3) in N5; a command
        // under the current context (re-keying) is N12.
        send_status(kNotCompatibleWithState);
        return;
    case kStatus: {
        const Bytes* c = nas::get(m, "5GMM cause");
        events_.emit("nas.mm.status", cfg_.id, {{"direction", "dl"}, {"cause", c && !c->empty() ? str((*c)[0]) : ""}});
        return;   // §7: no state change
    }
    default:
        // A message of 24.501 that N5 does not implement yet (§7.4).
        send_status(kTypeNotImplemented);
        return;
    }
}

void Mm::on_released() {
    connected_ = false;
    // §5.4.1.3.3 d and §5.4.1.3.7: entering 5GMM-IDLE ends the stored challenge and T3520.
    clear_stored_challenge();
    stop(MmTimer::t3520);
    resume_retransmission_timers();
    partial_.reset();
    ++gen_;
    if (state_ == MmState::registered_initiated) {
        registration_abnormal("released");   // §5.5.1.2.7 e
    } else if (state_ == MmState::deregistered_initiated) {
        stop(MmTimer::t3521);   // §5.5.2.2.6 a
        paused_t3521_ = false;
        events_.emit("nas.dereg.abort", cfg_.id, {{"reason", "released"}});
        set_state(MmState::deregistered_normal_service, "released before the de-registration accept");
    }
}

// ---- sending ---------------------------------------------------------------------------

void Mm::send(const nas::Message& m) {
    auto plain = nas::encode(m);
    if (!plain) {
        return;
    }
    if (cfg_.tap) {
        cfg_.tap(true, *plain);
    }
    if (!ctx_) {
        send_wire(std::move(*plain));
        return;
    }
    // §4.4.5: an initial NAS message is integrity protected, not ciphered.
    auto out = ctx_->protect(*plain, connected_ ? Sht::integrity_ciphered : Sht::integrity);
    if (out) {
        send_wire(std::move(*out));
    }
}

void Mm::send_wire(Bytes wire) {
    connected_ = true;
    lower_.send_nas(std::move(wire));
}

void Mm::send_status(std::uint8_t cause) {
    nas::Message s = make(kStatus);
    put(s, "5GMM cause", Bytes{cause});
    events_.emit("nas.mm.status", cfg_.id, {{"direction", "ul"}, {"cause", str(cause)}});
    send(s);
}

// ---- states and timers -----------------------------------------------------------------

void Mm::set_state(MmState to, const char* why) {
    if (to == state_) {
        return;
    }
    const MmTransition* t = find_transition(state_, to);
    if (t == nullptr) {
        ++unlisted_;
    }
    events_.emit("nas.mm.state", cfg_.id,
                 {{"from", mm_state_name(state_)},
                  {"to", mm_state_name(to)},
                  {"clause", t != nullptr ? t->clause : "unlisted"},
                  {"why", why}});
    state_ = to;
}

void Mm::start(MmTimer t, Millis ms) {
    stop(t);
    const auto i = static_cast<std::size_t>(t);
    timers_.at(i) = ex_.start_timer(ms, [this, t, alive = alive_] {
        if (!*alive) {
            return;
        }
        timers_.at(static_cast<std::size_t>(t)).reset();
        on_expiry(t);
    });
}

void Mm::stop(MmTimer t) {
    auto& id = timers_.at(static_cast<std::size_t>(t));
    if (id) {
        ex_.stop_timer(*id);
        id.reset();
    }
}

void Mm::on_expiry(MmTimer t) {
    events_.emit("nas.timer.expiry", cfg_.id, {{"timer", mm_timer_name(t)}});
    switch (t) {
    case MmTimer::t3510:
        // §5.5.1.2.7 c: abort, and release the signalling connection locally.
        ++gen_;
        if (connected_) {
            lower_.release_local();
            connected_ = false;
        }
        clear_stored_challenge();
        stop(MmTimer::t3520);
        partial_.reset();
        registration_abnormal("T3510");
        return;
    case MmTimer::t3511:
        if (state_ == MmState::deregistered_attempting_registration && usim_valid_) {
            start_registration();
        }
        return;
    case MmTimer::t3502:
        if (state_ == MmState::deregistered_attempting_registration && usim_valid_) {
            attempts_ = 0;   // §5.5.1.2.1
            start_registration();
        }
        return;
    case MmTimer::t3516:
        clear_stored_challenge();   // §5.4.1.3.3 b
        return;
    case MmTimer::t3520:
        network_failed_authentication();   // §5.4.1.3.7: the network failed the check
        return;
    case MmTimer::t3521:
        // §5.5.2.2.6 c: four retransmissions, then abort on the fifth expiry.
        if (state_ != MmState::deregistered_initiated) {
            return;
        }
        if (++t3521_expiries_ < 5) {
            events_.emit("nas.dereg.sent", cfg_.id,
                         {{"switch_off", "0"}, {"identity", guti_ ? "5g-guti" : "suci"},
                          {"transmission", str(t3521_expiries_ + 1)}});
            send(dereg_);
            start(MmTimer::t3521, cfg_.timers.t3521);
            return;
        }
        if (connected_) {
            lower_.release_local();
            connected_ = false;
        }
        events_.emit("nas.dereg.abort", cfg_.id, {{"reason", "T3521"}});
        set_state(MmState::deregistered_normal_service, "fifth T3521 expiry");
        return;
    }
}

} // namespace ksim::proc::ue
