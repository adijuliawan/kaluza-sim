// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/nas_mm/mm.hpp"

#include <algorithm>
#include <string>
#include <utility>

#include "codec/nas/build.hpp"
#include "crypto/kdf.hpp"
#include "crypto/keys5g.hpp"
#include "platform/mutation.hpp"
#include "proc/ue/nas_mm/suci.hpp"
#include "proc/ue/nas_sec/persist.hpp"

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
constexpr std::uint8_t kUlNasTransport = 0x67;
constexpr std::uint8_t kDlNasTransport = 0x68;
constexpr std::uint8_t kDeregistrationRequestUeTerminated = 0x47;
constexpr std::uint8_t kDeregistrationAcceptUeTerminated = 0x48;
constexpr std::uint8_t kServiceRequest = 0x4C;
constexpr std::uint8_t kServiceReject = 0x4D;
constexpr std::uint8_t kServiceAccept = 0x4E;
constexpr std::uint8_t kConfigurationUpdateCommand = 0x54;
constexpr std::uint8_t kConfigurationUpdateComplete = 0x55;
constexpr std::uint8_t kIdentityRequest = 0x5B;
constexpr std::uint8_t kIdentityResponse = 0x5C;

// 5GMM causes (Annex A).
constexpr std::uint8_t kIllegalUe = 3;
constexpr std::uint8_t kIllegalMe = 6;
constexpr std::uint8_t kUeIdentityNotDerived = 9;
constexpr std::uint8_t kImplicitlyDeregistered = 10;
constexpr std::uint8_t kCongestion = 22;
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
    case MmTimer::t3512: return "T3512";
    case MmTimer::t3517: return "T3517";
    case MmTimer::t3346: return "T3346";
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
    // A power cycle: only what the card holds survives (TS 31.102 4.4.11).
    for (std::size_t i = 0; i < kMmTimerCount; ++i) {
        stop(static_cast<MmTimer>(i));
    }
    guti_.reset();
    tai_list_.reset();
    last_tai_.reset();
    allowed_nssai_.clear();
    t3512_.reset();
    t3502_net_.reset();
    ctx_.reset();
    partial_.reset();
    kgnb_count_.reset();
    pending_sm_.clear();
    sr_uplink_ = 0;
    reregister_pending_ = false;
    update_registration_pending_ = false;
    forbidden_plmns_.clear();   // §5.3.13: the lists go when the UE is switched off
    forbidden_tais_.clear();
    update_ = UpdateStatus::u2_not_updated;
    connected_ = false;
    ++gen_;
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
    // What the last power cycle left on the card (TS 31.102 4.4.11.2, 4.4.11.4).
    std::optional<persist::Loci> loci;
    std::optional<NasSecurityContext> stored;
    if (ok && sub) {
        if (auto l = co_await card_.read_ef({persist::kDf5gs, persist::kLoci}); l) {
            if (auto d = persist::decode_loci(*l)) {
                loci = std::move(*d);
            }
        }
        if (auto n = co_await card_.read_record({persist::kDf5gs, persist::kNsc}, 1); n) {
            nsc_record_size_ = n->size();
            if (auto d = persist::decode_nsc(*n); d && *d) {
                stored = std::move(**d);
            }
        }
    }
    if (!*alive) {
        co_return;
    }
    if (loci && !KSIM_MUTANT("guti_not_persisted")) {
        guti_ = loci->guti;
        last_tai_ = loci->tai;
        update_ = loci->update_status == 0   ? UpdateStatus::u1_updated
                  : loci->update_status == 2 ? UpdateStatus::u3_roaming_not_allowed
                                             : UpdateStatus::u2_not_updated;
    }
    if (stored && guti_) {
        ctx_ = std::move(*stored);   // §4.4.2.1: the stored native context, valid
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
                 {{"usim", usim_valid_ ? "valid" : "invalid"},
                  {"supi", usim_valid_ ? "imsi-" + supi_ : ""},
                  {"guti", guti_ ? guti_text(*guti_) : ""},
                  {"context", ctx_ ? "stored" : "none"}});
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

namespace {

const char* reg_type_name(std::uint8_t t) {
    switch (t) {
    case 1: return "initial";
    case 2: return "mobility";
    case 3: return "periodic";
    default: return "?";
    }
}

} // namespace

void Mm::start_registration(RegType type) {
    stop(MmTimer::t3511);
    stop(MmTimer::t3502);
    stop(MmTimer::t3512);
    if (running(MmTimer::t3346)) {
        // §5.5.1.2.7 / §5.3.9: not while the network's back-off runs.
        events_.emit("nas.reg.blocked", cfg_.id, {{"why", "T3346"}});
        return;
    }
    const bool forbidden_plmn = std::find(forbidden_plmns_.begin(), forbidden_plmns_.end(), cfg_.plmn) != forbidden_plmns_.end();
    const std::optional<ie::Tai>& here = current_tai_ ? current_tai_ : last_tai_;
    const bool forbidden_ta = here && std::find(forbidden_tais_.begin(), forbidden_tais_.end(), *here) != forbidden_tais_.end();
    if (type == RegType::initial && (forbidden_plmn || forbidden_ta)) {
        events_.emit("nas.reg.blocked", cfg_.id, {{"why", forbidden_plmn ? "forbidden PLMN" : "forbidden TA"}});
        return;
    }
    partial_.reset();
    kgnb_count_.reset();
    ++gen_;
    reg_type_ = type;
    // §4.4.6 b: with a 5G-GUTI and a valid context the request is protected
    // with it; otherwise it starts from no context at all.
    const bool with_context = ctx_.has_value() && guti_.has_value();
    if (!with_context) {
        ctx_.reset();
    }
    if (type == RegType::initial) {
        persist_nsc(false);   // §4.4.2.1.2: the stored context is marked invalid
    }
    nas::Message m = make(kRegistrationRequest);
    put(m, "5GS registration type", ie::RegistrationType{static_cast<std::uint8_t>(type), cfg_.follow_on_request}.encode());
    put(m, "ngKSI", current_ngksi().encode());
    const ie::MobileIdentity id = identity();
    put(m, "5GS mobile identity", id.encode());
    put(m, "UE security capability", cfg_.security.encode());
    if (!cfg_.requested_nssai.empty()) {
        put(m, "Requested NSSAI", ie::Nssai{cfg_.requested_nssai}.encode());
    }
    if (with_context && cfg_.sm_hooks.active) {
        ie::PsiBitmap status{cfg_.sm_hooks.active()};
        put(m, "PDU session status", status.encode());
    }
    if (type == RegType::initial) {
        reg_uplink_ = 0;
    } else if (reg_uplink_ != 0) {
        // §5.5.1.3.2 cases f and o; kept for the attempts T3511 restarts until an accept.
        put(m, "Uplink data status", ie::PsiBitmap{reg_uplink_}.encode());
    }
    initial_ = m;
    initial_without_context_ = !with_context;
    Result<Bytes> wire = Bytes{};
    if (with_context) {
        wire = protect_initial(m);
    } else {
        // §4.4.6 a: without a valid context only the cleartext IEs go.
        auto split = split_initial(m);
        if (!split) {
            return;
        }
        wire = nas::encode(split->cleartext);
        if (wire && cfg_.tap) {
            cfg_.tap(true, *wire);
        }
    }
    if (!wire) {
        return;
    }
    events_.emit("nas.reg.request", cfg_.id,
                 {{"type", reg_type_name(static_cast<std::uint8_t>(type))},
                  {"identity", guti_ ? "5g-guti" : "suci"},
                  {"protected", with_context ? "integrity" : "plain"},
                  {"attempt", str(attempts_ + 1)}});
    set_state(MmState::registered_initiated, "registration request");
    send_wire(std::move(*wire));
    start(MmTimer::t3510, cfg_.timers.t3510);
}

Result<Bytes> Mm::protect_initial(const nas::Message& m) {
    if (!ctx_) {
        return make_error(Errc::invalid_argument, 0, "5GMM: no context to protect the initial message with");
    }
    auto split = split_initial(m);
    if (!split) {
        return split.error();
    }
    const std::uint32_t count = ctx_->ul_count();
    nas::Message out = split->cleartext;
    if (split->has_non_cleartext) {
        // §4.4.6 b 1): the whole message in the container, its value ciphered.
        auto whole = nas::encode(m);
        if (!whole) {
            return whole.error();
        }
        if (cfg_.tap) {
            cfg_.tap(true, *whole);
        }
        auto ciphered = ctx_->container_cipher(*whole, count);
        if (!ciphered) {
            return ciphered.error();
        }
        put(out, "NAS message container", std::move(*ciphered));
    }
    auto plain = nas::encode(out);
    if (!plain) {
        return plain.error();
    }
    if (cfg_.tap && !split->has_non_cleartext) {
        cfg_.tap(true, *plain);
    }
    kgnb_count_ = count;   // K_gNB from this COUNT unless a SECURITY MODE COMMAND follows
    return ctx_->protect(*plain, Sht::integrity);
}

void Mm::registration_abnormal(const char* reason) {
    // §5.5.1.2.7, cases c, d and e.
    stop(MmTimer::t3510);
    paused_t3510_ = false;
    if (reg_type_ != RegType::initial) {
        // §5.5.1.3.7: a periodic or mobility update failed: still registered, tried again after T3511.
        events_.emit("nas.reg.abort", cfg_.id, {{"reason", reason}, {"attempt", str(attempts_)}});
        set_state(MmState::registered_normal_service, "registration update failed");
        start(MmTimer::t3511, cfg_.timers.t3511);
        return;
    }
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
    reg_uplink_ = 0;   // answered (§5.5.1.3.4: the reactivation result, if any, says how)
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
    } else if (reg_type_ == RegType::initial) {
        t3512_ = cfg_.timers.t3512;   // §5.3.7: the default when the network gives none
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
    if (tai_list_ && !tai_list_->tais.empty()) {
        last_tai_ = tai_list_->tais.front();   // the cell's TA is in the list (fixed camping, A-12)
    }
    persist_loci();
    events_.emit("nas.reg.accept", cfg_.id,
                 {{"type", reg_type_name(static_cast<std::uint8_t>(reg_type_))},
                  {"guti", guti_ ? guti_text(*guti_) : ""},
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
    if (const Bytes* ps = nas::get(m, "PDU session status"); ps != nullptr && cfg_.sm_hooks.sync) {
        if (auto b = ie::PsiBitmap::decode(*ps)) {
            cfg_.sm_hooks.sync(b->psis);   // §5.5.1.3.4: the network's view of the sessions
        }
    }
    flush_pending_sm();
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
        forbidden_plmns_.push_back(cfg_.plmn);   // §5.5.1.2.5: the forbidden PLMN list
        persist_loci();
        set_state(MmState::deregistered_plmn_search, "registration reject #11");
        return;
    case kTaNotAllowed:
    case kRoamingNotAllowedInTa:
    case kNoSuitableCells:
        update_ = UpdateStatus::u3_roaming_not_allowed;
        // §5.5.1.2.5: the current TAI goes on the forbidden TA lists of §5.3.13.
        if (const auto& here = current_tai_ ? current_tai_ : last_tai_; here) {
            forbidden_tais_.push_back(*here);
        }
        delete_registration_data(true);
        attempts_ = 0;
        persist_loci();
        set_state(MmState::deregistered_limited_service, "registration reject #12, #13 or #15");
        return;
    case kCongestion:
        // §5.5.1.2.5 #22: with T3346 the UE waits it out; the attempt counter is not touched.
        if (const Bytes* t = nas::get(m, "T3346 value")) {
            auto v = ie::GprsTimer2::decode(*t);
            if (const auto ms = v ? v->ms() : std::nullopt; ms && *ms > 0) {
                stop(MmTimer::t3510);
                start(MmTimer::t3346, static_cast<Millis>(*ms));
                events_.emit("nas.mm.t3346", cfg_.id, {{"seconds", str(*ms / 1000)}});
                set_state(MmState::deregistered_attempting_registration, "registration reject #22");
                return;
            }
        }
        registration_abnormal("reject");
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
    const bool was_connected = connected_;   // send() marks the connection as on its way
    send(m);
    if (switch_off) {
        entering_deregistered();   // §4.4.2.1.3: the context goes to the card before power off
        // §5.5.2.2.1: the UE may be switched off as soon as the request is sent.
        for (std::size_t i = 0; i < kMmTimerCount; ++i) {
            stop(static_cast<MmTimer>(i));
        }
        clear_stored_challenge();
        if (was_connected) {
            lower_.release_local();   // the request is out already
        }
        // From 5GMM-IDLE the request still waits for the RRC connection: a local
        // release would drop it (F-46); the radio goes off once it is sent.
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
    entering_deregistered();
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
    kausf_ = std::move(kausf);   // EF.5GAUTHKEYS, written with the context
    kseaf_ = std::move(kseaf);
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
    case kDlNasTransport:
        on_dl_nas_transport(m);
        return;
    case kServiceAccept:
        on_service_accept(m);
        return;
    case kServiceReject:
        on_service_reject(m);
        return;
    case kDeregistrationRequestUeTerminated:
        on_network_deregistration(m);
        return;
    case kConfigurationUpdateCommand:
        on_configuration_update(m);
        return;
    case kIdentityRequest:
        on_identity_request(m);
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

void Mm::on_camped(std::uint32_t tac) { current_tai_ = ie::Tai{cfg_.plmn, tac}; }

void Mm::on_connection_failure(std::uint16_t up_psis) {
    recovery_pending_ = true;
    recovery_up_ = up_psis;
}

void Mm::on_released() {
    const bool recovery = std::exchange(recovery_pending_, false);
    const std::uint16_t recovery_up = std::exchange(recovery_up_, std::uint16_t{0});
    connected_ = false;
    kgnb_count_.reset();   // the next connection's K_gNB comes from its own initial message or SMC
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
        entering_deregistered();
        set_state(MmState::deregistered_normal_service, "released before the de-registration accept");
    } else if (state_ == MmState::service_request_initiated) {
        stop(MmTimer::t3517);   // §5.6.1.7 a: the lower layers failed
        events_.emit("nas.sr.abort", cfg_.id, {{"why", "released"}});
        set_state(MmState::registered_normal_service, "service request aborted");
    }
    if (is_registered(state_)) {
        events_.emit("nas.mm.cm_idle", cfg_.id, {{"state", mm_state_name(state_)}});
        // §5.3.7: T3512 starts as the UE enters 5GMM-IDLE.
        if (const auto t3512 = t3512_; t3512 && *t3512 > 0) {
            start(MmTimer::t3512, *t3512);
            events_.emit("nas.mm.t3512", cfg_.id, {{"seconds", str(*t3512 / 1000)}});
        }
        if (update_registration_pending_) {
            update_registration_pending_ = false;
            start_registration(RegType::mobility);   // §5.4.4.3: the configuration update asked for it
        } else if (recovery && pending_sm_.empty() && state_ == MmState::registered_normal_service) {
            // §5.5.1.3.2 f: NAS signalling connection recovery; the Uplink data
            // status names the sessions with uplink data and those whose user plane was up.
            reg_uplink_ = static_cast<std::uint16_t>(recovery_up | sr_uplink_);
            sr_uplink_ = 0;
            start_registration(RegType::mobility);
        } else if (!pending_sm_.empty() || sr_uplink_ != 0) {
            (void)service_request(sr_uplink_ != 0 ? ie::ServiceType::data : ie::ServiceType::signalling, sr_uplink_);
        }
    } else if (reregister_pending_ && is_deregistered(state_) && usim_valid_) {
        reregister_pending_ = false;
        start_registration(RegType::initial);   // §5.5.2.3.2: re-registration required
    }
}

void Mm::entering_connected() {
    stop(MmTimer::t3512);   // §5.3.7: T3512 stops as the UE enters 5GMM-CONNECTED
}

void Mm::entering_deregistered() {
    // §4.4.2.1.3: the current native context goes to the card, marked valid.
    stop(MmTimer::t3512);
    reg_uplink_ = 0;
    persist_nsc(ctx_.has_value());
    persist_loci();
    persist_auth_keys();
}

void Mm::power_off_abrupt() {
    for (std::size_t i = 0; i < kMmTimerCount; ++i) {
        stop(static_cast<MmTimer>(i));
    }
    ++gen_;
    connected_ = false;
    pending_sm_.clear();
    sr_uplink_ = 0;
    events_.emit("nas.mm.power_off", cfg_.id, {{"mode", "abrupt"}});
    set_state(MmState::null, "power off");
}

// ---- the service request (§5.6.1) ------------------------------------------------------

Result<void> Mm::service_request(std::uint8_t type, std::uint16_t uplink) {
    if (!is_registered(state_) || !guti_ || !ctx_) {
        return make_error(Errc::invalid_argument, 0, "5GMM: a service request needs a registration with a 5G-GUTI");
    }
    if (connected_) {
        flush_pending_sm();
        return {};
    }
    if (state_ == MmState::service_request_initiated) {
        sr_uplink_ |= uplink;   // the running one carries on; the rest waits for the bearers
        return {};
    }
    if (running(MmTimer::t3346)) {
        events_.emit("nas.sr.blocked", cfg_.id, {{"why", "T3346"}});
        return make_error(Errc::invalid_argument, 0, "5GMM: T3346 runs");
    }
    auto tmsi = s_tmsi();
    ie::MobileIdentity s;
    s.type = ie::MobileIdentity::Type::s_tmsi;
    s.amf_set = guti_->amf_set;
    s.amf_pointer = guti_->amf_pointer;
    s.tmsi = guti_->tmsi;
    nas::Message m = make(kServiceRequest);
    put(m, "ngKSI", current_ngksi().encode());
    put(m, "Service type", ie::ServiceType{type}.encode());
    put(m, "5G-S-TMSI", s.encode());
    if (uplink != 0) {
        put(m, "Uplink data status", ie::PsiBitmap{uplink}.encode());
    }
    if (cfg_.sm_hooks.active) {
        put(m, "PDU session status", ie::PsiBitmap{cfg_.sm_hooks.active()}.encode());
    }
    auto wire = protect_initial(m);
    if (!wire) {
        return wire.error();
    }
    sr_type_ = type;
    sr_uplink_ = uplink;
    events_.emit("nas.sr.request", cfg_.id,
                 {{"type", str(type)}, {"uplink", str(uplink)}, {"s_tmsi", tmsi ? str(static_cast<std::int64_t>(*tmsi)) : ""}});
    set_state(MmState::service_request_initiated, "service request");
    send_wire(std::move(*wire));
    start(MmTimer::t3517, cfg_.timers.t3517);
    return {};
}

void Mm::on_paged() {
    if (KSIM_MUTANT("paging_ignore")) {
        return;   // the planted fault: the paging record is not answered
    }
    events_.emit("nas.mm.paged", cfg_.id, {{"state", mm_state_name(state_)}});
    if (!is_registered(state_) || connected_) {
        return;
    }
    // §5.6.2.2.1 / §5.6.1.2: "mobile terminated services", with any uplink pending.
    (void)service_request(ie::ServiceType::mobile_terminated, sr_uplink_);
}

void Mm::on_service_accept(const nas::Message& m) {
    if (state_ != MmState::service_request_initiated) {
        send_status(kNotCompatibleWithState);
        return;
    }
    stop(MmTimer::t3517);
    set_state(MmState::registered_normal_service, "service accept");
    std::uint16_t network = 0;
    bool synced = false;
    if (const Bytes* ps = nas::get(m, "PDU session status")) {
        if (auto b = ie::PsiBitmap::decode(*ps)) {
            network = b->psis;
            synced = true;
        }
    }
    events_.emit("nas.sr.accept", cfg_.id,
                 {{"type", str(sr_type_)}, {"uplink", str(sr_uplink_)}, {"pending_uplink", sr_uplink_ != 0 ? "1" : "0"},
                  {"pdu_session_status", synced ? str(network) : ""}});
    if (synced && cfg_.sm_hooks.sync) {
        cfg_.sm_hooks.sync(network);   // §5.6.1.4: sessions the network does not hold go locally
    }
    sr_uplink_ = 0;
    flush_pending_sm();
}

void Mm::on_service_reject(const nas::Message& m) {
    if (state_ != MmState::service_request_initiated) {
        send_status(kNotCompatibleWithState);
        return;
    }
    stop(MmTimer::t3517);
    const Bytes* c = nas::get(m, "5GMM cause");
    const std::uint8_t cause = c != nullptr && !c->empty() ? (*c)[0] : 111;
    events_.emit("nas.sr.reject", cfg_.id, {{"cause", str(cause)}});
    sr_uplink_ = 0;
    switch (cause) {
    case kUeIdentityNotDerived:
    case kImplicitlyDeregistered:
        // §5.6.1.5 #9, #10: a new initial registration (#9 without the 5G-GUTI or the context).
        if (cause == kUeIdentityNotDerived) {
            update_ = UpdateStatus::u2_not_updated;
            delete_registration_data(true);
            persist_loci();
        }
        if (cfg_.sm_hooks.release_all) {
            cfg_.sm_hooks.release_all();
        }
        reregister_pending_ = true;
        entering_deregistered();
        set_state(MmState::deregistered_normal_service, "service reject #9 or #10");
        return;
    case kCongestion:
        if (const Bytes* t = nas::get(m, "T3346 value")) {
            auto v = ie::GprsTimer2::decode(*t);
            if (const auto ms = v ? v->ms() : std::nullopt; ms && *ms > 0) {
                start(MmTimer::t3346, static_cast<Millis>(*ms));
                events_.emit("nas.mm.t3346", cfg_.id, {{"seconds", str(*ms / 1000)}});
            }
        }
        set_state(MmState::registered_normal_service, "service reject #22");
        return;
    default:
        set_state(MmState::registered_normal_service, "service reject");
        return;
    }
}

void Mm::flush_pending_sm() {
    if (!connected_ || !is_registered(state_)) {
        return;
    }
    auto queued = std::move(pending_sm_);
    pending_sm_.clear();
    for (const auto& u : queued) {
        (void)send_sm(u);
    }
}

// ---- network-initiated procedures (§5.5.2.3, §5.4.4, §5.4.3) ----------------------------

void Mm::on_network_deregistration(const nas::Message& m) {
    const Bytes* t = nas::get(m, "De-registration type");
    auto dt = t != nullptr ? ie::DeregistrationType::decode(*t)
                           : Result<ie::DeregistrationType>(make_error(Errc::truncated, 0, "absent"));
    if (!dt) {
        send_status(kInvalidMandatory);
        return;
    }
    const Bytes* c = nas::get(m, "5GMM cause");
    const std::uint8_t cause = c != nullptr && !c->empty() ? (*c)[0] : 0;
    for (MmTimer tm : {MmTimer::t3510, MmTimer::t3517, MmTimer::t3521, MmTimer::t3512}) {
        stop(tm);
    }
    // §5.5.2.3.2: the accept, a local release of the PDU sessions, 5GMM-DEREGISTERED.
    send(make(kDeregistrationAcceptUeTerminated));
    if (cfg_.sm_hooks.release_all) {
        cfg_.sm_hooks.release_all();
    }
    events_.emit("nas.dereg.network", cfg_.id,
                 {{"reregistration", dt->reregistration_required ? "1" : "0"}, {"cause", cause != 0 ? str(cause) : ""}});
    entering_deregistered();
    set_state(MmState::deregistered_normal_service, "network de-registration");
    if (dt->reregistration_required && !KSIM_MUTANT("dereg_no_reregistration")) {
        // An initial registration once the network has released the connection.
        reregister_pending_ = true;
        ex_.start_timer(2'000, [this, alive = alive_, gen = gen_] {
            if (*alive && gen == gen_ && reregister_pending_ && is_deregistered(state_)) {
                reregister_pending_ = false;
                start_registration(RegType::initial);
            }
        });
    }
}

void Mm::on_configuration_update(const nas::Message& m) {
    stop(MmTimer::t3346);   // §5.4.4.3
    ie::ConfigurationUpdateIndication ind;
    if (const Bytes* i = nas::get(m, "Configuration update indication")) {
        if (auto v = ie::ConfigurationUpdateIndication::decode(*i)) {
            ind = *v;
        }
    }
    bool new_guti = false;
    if (const Bytes* g = nas::get(m, "5G-GUTI")) {
        if (auto id = ie::MobileIdentity::decode(*g); id && id->type == ie::MobileIdentity::Type::guti) {
            guti_ = std::move(*id);
            new_guti = true;
        }
    }
    if (const Bytes* t = nas::get(m, "TAI list")) {
        if (auto l = ie::TaiList::decode(*t)) {
            tai_list_ = std::move(*l);
        }
    }
    if (const Bytes* a = nas::get(m, "Allowed NSSAI")) {
        if (auto n = ie::Nssai::decode(*a)) {
            allowed_nssai_ = std::move(n->list);
        }
    }
    if (new_guti) {
        persist_loci();
    }
    events_.emit("nas.mm.config_update", cfg_.id,
                 {{"guti", new_guti && guti_ ? guti_text(*guti_) : ""},
                  {"ack", ind.ack_requested ? "1" : "0"},
                  {"registration_requested", ind.registration_requested ? "1" : "0"}});
    // §5.4.4.3: acknowledged when asked (or when it gave a new 5G-GUTI).
    if (ind.ack_requested || new_guti) {
        send(make(kConfigurationUpdateComplete));
    }
    if (ind.registration_requested) {
        update_registration_pending_ = true;   // a mobility registration once released
    }
}

void Mm::on_identity_request(const nas::Message& m) {
    const Bytes* t = nas::get(m, "Identity type");
    auto it = t != nullptr ? ie::IdentityType::decode(*t) : Result<ie::IdentityType>(make_error(Errc::truncated, 0, "absent"));
    if (!it) {
        send_status(kInvalidMandatory);
        return;
    }
    ie::MobileIdentity id;
    switch (it->value) {
    case ie::IdentityType::suci:
        id = null_suci(Subscription{supi_, home_, msin_}, routing_indicator_);
        break;
    case ie::IdentityType::guti:
        if (guti_) {
            id = *guti_;
        }
        break;
    case ie::IdentityType::imeisv:
        id.type = ie::MobileIdentity::Type::imeisv;
        id.digits = cfg_.imeisv;
        break;
    case ie::IdentityType::imei: {
        // The IMEI: the IMEISV's TAC and SNR, then the Luhn check digit (TS 23.003 6.2.1).
        id.type = ie::MobileIdentity::Type::imei;
        const std::string body = cfg_.imeisv.substr(0, 14);
        int sum = 0;
        for (std::size_t i = 0; i < body.size(); ++i) {
            int d = body[i] - '0';
            if (i % 2 == 1) {
                d *= 2;
                d = d > 9 ? d - 9 : d;
            }
            sum += d;
        }
        id.digits = body + static_cast<char>('0' + (10 - sum % 10) % 10);
        break;
    }
    default:
        break;   // no such identity: "no identity"
    }
    nas::Message r = make(kIdentityResponse);
    put(r, "Mobile identity", id.encode());
    events_.emit("nas.mm.identity", cfg_.id, {{"type", str(it->value)}});
    send(r);
}

// ---- the USIM (TS 31.102 4.4.11) --------------------------------------------------------

void Mm::card_job(CardWrite w) {
    card_jobs_.push_back(std::move(w));
    if (!card_busy_) {
        card_busy_ = true;
        coro::spawn(run_card_jobs(alive_));
    }
}

coro::Task<void> Mm::run_card_jobs(std::shared_ptr<bool> alive) {
    while (*alive && !card_jobs_.empty()) {
        CardWrite w = std::move(card_jobs_.front());
        card_jobs_.pop_front();
        Bytes raw(w.data->expose().begin(), w.data->expose().end());
        const std::vector<std::uint16_t> path{persist::kDf5gs, w.fid};
        auto r = w.record ? co_await card_.update_record(path, 1, raw) : co_await card_.update_ef(path, raw);
        secure_zero(raw);
        if (!*alive) {
            co_return;
        }
        if (!r) {
            events_.emit("nas.mm.usim_error", cfg_.id, {{"fid", str(w.fid)}, {"what", r.error().what}});
        }
    }
    if (*alive) {
        card_busy_ = false;
    }
}

void Mm::persist_loci() {
    if (KSIM_MUTANT("guti_not_persisted")) {
        return;   // the planted fault: EF.5GS3GPPLOCI is never written
    }
    const std::uint8_t status = update_ == UpdateStatus::u1_updated ? 0 : update_ == UpdateStatus::u2_not_updated ? 1 : 2;
    const Bytes data = persist::encode_loci(persist::Loci{guti_, last_tai_, status});
    card_job(CardWrite{persist::kLoci, false, std::make_shared<SecretBytes>(SecretBytes::copy_of(data))});
}

void Mm::persist_nsc(bool valid) {
    card_job(CardWrite{persist::kNsc, true,
                       std::make_shared<SecretBytes>(persist::encode_nsc(valid && ctx_ ? &*ctx_ : nullptr, nsc_record_size_))});
}

void Mm::persist_auth_keys() {
    if (kausf_.empty()) {
        return;
    }
    // TS 31.102 4.4.11.6: with service n°133 not available only K_AUSF and
    // K_SEAF for 3GPP access, in octets 0 to 67 (the rest is left alone).
    card_job(CardWrite{persist::kAuthKeys, false,
                       std::make_shared<SecretBytes>(persist::encode_auth_keys(&kausf_, &kseaf_, 68))});
}

// ---- the NAS transport of 5GSM (§5.4.5) -------------------------------------------------

Result<void> Mm::send_sm(const SmUplink& u) {
    if (!is_registered(state_) || !ctx_) {
        return make_error(Errc::invalid_argument, 0, "5GMM: not registered");
    }
    if (!connected_ || state_ == MmState::service_request_initiated) {
        // §5.6.1.1 c: uplink signalling pending: a service request brings the connection.
        pending_sm_.push_back(u);
        if (!connected_) {
            return service_request(ie::ServiceType::signalling, sr_uplink_);
        }
        return {};
    }
    nas::Message m = make(kUlNasTransport);
    put(m, "Payload container type", Bytes{ie::PayloadContainerType::n1_sm});
    put(m, "Payload container", u.sm);
    put(m, "PDU session ID", Bytes{u.psi});   // §5.4.5.2.2: for N1 SM, always
    if (u.request_type) {
        put(m, "Request type", Bytes{*u.request_type});
    }
    if (u.snssai) {
        put(m, "S-NSSAI", u.snssai->encode());
    }
    if (u.dnn) {
        put(m, "DNN", ie::Dnn{*u.dnn}.encode());
    }
    send(m);
    return {};
}

void Mm::on_dl_nas_transport(const nas::Message& m) {
    const Bytes* type = nas::get(m, "Payload container type");
    const Bytes* payload = nas::get(m, "Payload container");
    if (type == nullptr || type->empty() || payload == nullptr) {
        return;
    }
    if (((*type)[0] & 0x0F) != ie::PayloadContainerType::n1_sm) {
        // SMS is N13; other payloads are not P1 (§5.4.5.3.3: discarded).
        events_.emit("nas.mm.transport.discard", cfg_.id, {{"payload_type", str((*type)[0] & 0x0F)}});
        return;
    }
    const Bytes* psi = nas::get(m, "PDU session ID");
    if (psi == nullptr || psi->empty()) {
        events_.emit("nas.mm.transport.discard", cfg_.id, {{"payload_type", "1"}, {"why", "no PDU session ID"}});
        return;
    }
    SmDownlink d;
    d.psi = (*psi)[0];
    d.sm = *payload;
    if (const Bytes* c = nas::get(m, "5GMM cause"); c != nullptr && !c->empty()) {
        d.mm_cause = (*c)[0];
    }
    if (const Bytes* b = nas::get(m, "Back-off timer value")) {
        if (auto t = ie::GprsTimer3::decode(*b)) {
            d.backoff = *t;
        }
    }
    if (cfg_.sm) {
        cfg_.sm(d);
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
    if (!connected_) {
        entering_connected();
    }
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
        } else if (state_ == MmState::registered_normal_service && reg_type_ != RegType::initial && !connected_) {
            start_registration(reg_type_);   // §5.5.1.3.7: the update again
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
    case MmTimer::t3512:
        // §5.3.7: periodic registration, from 5GMM-REGISTERED in 5GMM-IDLE.
        if (state_ == MmState::registered_normal_service && !connected_) {
            start_registration(RegType::periodic);
        }
        return;
    case MmTimer::t3517:
        // §5.6.1.7 c: abort, release locally, back to 5GMM-REGISTERED.
        events_.emit("nas.sr.abort", cfg_.id, {{"why", "T3517"}});
        sr_uplink_ = 0;
        pending_sm_.clear();
        if (connected_) {
            lower_.release_local();
            connected_ = false;
        }
        set_state(MmState::registered_normal_service, "T3517 expiry");
        return;
    case MmTimer::t3346:
        if (state_ == MmState::deregistered_attempting_registration && usim_valid_) {
            start_registration(RegType::initial);
        }
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
