// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/nas_sec/nas_sec.hpp"

#include <algorithm>
#include <array>

#include "crypto/keys5g.hpp"

namespace ksim::proc::ue {

namespace {

// The BEARER input is the NAS connection identifier (TS 33.501 §6.4.3.1, §6.4.4.1),
// 0x01 for 3GPP access and 0x02 for non-3GPP access (§6.4.2.1). It was 0 until
// P1 N8, which the core stub shared; the Open5GS control found it (KS-SEC-D2).
constexpr std::uint8_t kBearer3gpp = 1;
constexpr std::uint8_t kUplink = 0;
constexpr std::uint8_t kDownlink = 1;

std::uint8_t send_dir(NasRole r) { return r == NasRole::ue ? kUplink : kDownlink; }
std::uint8_t recv_dir(NasRole r) { return r == NasRole::ue ? kDownlink : kUplink; }

std::optional<crypto::Nea> nea_of(std::uint8_t ea) {
    switch (ea) {
    case 0: return crypto::Nea::nea0;
    case 1: return crypto::Nea::nea1;
    case 2: return crypto::Nea::nea2;
    default: return std::nullopt;   // 5G-EA3: KS-SEC-G1
    }
}

std::optional<crypto::Nia> nia_of(std::uint8_t ia) {
    switch (ia) {
    case 1: return crypto::Nia::nia1;
    case 2: return crypto::Nia::nia2;
    default: return std::nullopt;   // 5G-IA0 outside emergency, 5G-IA3: refused
    }
}

std::uint32_t mac_value(const crypto::Mac& m) {
    return (std::uint32_t{m[0]} << 24) | (std::uint32_t{m[1]} << 16) | (std::uint32_t{m[2]} << 8) | m[3];
}

bool is_ciphered(Sht s) { return s == Sht::integrity_ciphered || s == Sht::integrity_ciphered_new; }

} // namespace

const char* verdict_name(Verdict v) noexcept {
    switch (v) {
    case Verdict::ok: return "ok";
    case Verdict::discard_unprotected: return "discard_unprotected";
    case Verdict::discard_mac: return "discard_mac";
    case Verdict::discard_no_context: return "discard_no_context";
    case Verdict::discard_malformed: return "discard_malformed";
    }
    return "?";
}

Result<NasSecurityContext> NasSecurityContext::derive(nas::ie::NgKsi ngksi, SecretBytes kamf, std::uint8_t ea, std::uint8_t ia,
                                                     NasRole role) {
    if (!nea_of(ea)) {
        return make_error(Errc::unsupported, ea, "nas security: 5G-EA3 is a declared gap (KS-SEC-G1)");
    }
    if (!nia_of(ia)) {
        return make_error(Errc::unsupported, ia, "nas security: 5G-IA0 outside emergency, or 5G-IA3");
    }
    if (ngksi.none()) {
        return make_error(Errc::invalid_argument, 0, "nas security: ngKSI 7 is 'no key available'");
    }
    // TS 33.501 Annex A.8: K_NASint and K_NASenc from K_AMF, algorithm type
    // distinguishers 0x02 (NAS integrity) and 0x01 (NAS encryption).
    auto kint = crypto::keys5g::algorithm_key(kamf, crypto::keys5g::AlgType::nas_int, ia);
    auto kenc = crypto::keys5g::algorithm_key(kamf, crypto::keys5g::AlgType::nas_enc, ea);
    if (!kint || !kenc) {
        return make_error(Errc::internal, 0, "nas security: the key derivation failed");
    }
    NasSecurityContext c;
    c.ngksi_ = ngksi;
    c.kamf_ = std::move(kamf);
    c.knas_int_ = std::move(*kint);
    c.knas_enc_ = std::move(*kenc);
    c.ea_ = ea;
    c.ia_ = ia;
    c.role_ = role;
    return c;
}

void NasSecurityContext::restore_counts(std::uint32_t ul, std::optional<std::uint32_t> dl) noexcept {
    ul_count_ = ul & 0xFFFFFF;
    dl_count_ = dl ? std::optional<std::uint32_t>(*dl & 0xFFFFFF) : std::nullopt;
}

Result<crypto::Mac> NasSecurityContext::mac_of(std::uint32_t count, std::uint8_t direction, ByteView seq_and_message) const {
    const auto nia = nia_of(ia_);
    if (!nia) {
        return make_error(Errc::unsupported, ia_, "nas security: no integrity algorithm");
    }
    return crypto::nia(*nia, knas_int_, crypto::SecInput{count, kBearer3gpp, direction}, seq_and_message,
                       seq_and_message.size() * 8);
}

Result<Bytes> NasSecurityContext::protect(ByteView plain, Sht sht) {
    if (sht == Sht::plain) {
        return make_error(Errc::invalid_argument, 0, "nas security: protect() needs a protected header type");
    }
    const std::uint32_t count = ul_count_;
    Bytes body;   // the sequence number, then the message (ciphered if asked)
    body.push_back(static_cast<std::uint8_t>(count & 0xFF));
    if (is_ciphered(sht)) {
        const std::optional<crypto::Nea> alg = nea_of(ea_);
        if (!alg.has_value()) {
            return make_error(Errc::unsupported, ea_, "nas security: no ciphering algorithm");
        }
        auto c = crypto::nea(alg.value(), knas_enc_, crypto::SecInput{count, kBearer3gpp, send_dir(role_)}, plain, plain.size() * 8);
        if (!c) {
            return c.error();
        }
        body.insert(body.end(), c->begin(), c->end());
    } else {
        body.insert(body.end(), plain.begin(), plain.end());
    }
    auto mac = mac_of(count, send_dir(role_), body);
    if (!mac) {
        return mac.error();
    }
    nas::Protected p;
    p.security_header_type = static_cast<std::uint8_t>(sht);
    p.mac = mac_value(*mac);
    p.sequence_number = body[0];
    p.payload.assign(body.begin() + 1, body.end());
    ul_count_ = (ul_count_ + 1) & 0xFFFFFF;   // the overflow counter carries with the wrap (§4.4.3.1)
    return nas::encode_protected(p);
}

std::uint32_t NasSecurityContext::estimate(std::uint8_t sqn) const noexcept {
    if (!dl_count_) {
        return sqn;   // the first downlink message of the context: overflow 0
    }
    std::uint32_t overflow = *dl_count_ >> 8;
    if (sqn <= (*dl_count_ & 0xFF)) {
        ++overflow;   // the estimate is always above the stored COUNT (§4.4.3.1)
    }
    return ((overflow << 8) | sqn) & 0xFFFFFF;
}

Inbound NasSecurityContext::unprotect(ByteView wire) {
    Inbound in;
    auto p = nas::decode_protected(wire);
    if (!p) {
        in.verdict = Verdict::discard_malformed;
        return in;
    }
    in.sht = static_cast<Sht>(p->security_header_type);
    const std::uint32_t count = estimate(p->sequence_number);
    Bytes body{p->sequence_number};
    body.insert(body.end(), p->payload.begin(), p->payload.end());
    auto mac = mac_of(count, recv_dir(role_), body);
    if (!mac || mac_value(*mac) != p->mac) {
        in.verdict = Verdict::discard_mac;
        return in;
    }
    if (is_ciphered(in.sht)) {
        const std::optional<crypto::Nea> alg = nea_of(ea_);
        if (!alg.has_value()) {
            in.verdict = Verdict::discard_malformed;
            return in;
        }
        auto d = crypto::nea(alg.value(), knas_enc_, crypto::SecInput{count, kBearer3gpp, recv_dir(role_)}, p->payload,
                             p->payload.size() * 8);
        if (!d) {
            in.verdict = Verdict::discard_malformed;
            return in;
        }
        in.plain = std::move(*d);
    } else {
        in.plain = std::move(p->payload);
    }
    dl_count_ = count;
    in.count = count;
    in.verdict = Verdict::ok;
    return in;
}

bool processed_unprotected(const nas::Message& m, bool secure_exchange) {
    if (secure_exchange || m.desc == nullptr || m.desc->epd != nas::Epd::mm) {
        return false;
    }
    const auto cause = [&]() -> int {
        const nas::Ie* c = m.find("5GMM cause");
        return c != nullptr && !c->value.empty() ? c->value[0] : -1;
    };
    switch (m.desc->type) {
    case 0x5B: {   // IDENTITY REQUEST: only for the SUCI
        const nas::Ie* t = m.find("Identity type");
        return t != nullptr && !t->value.empty() && (t->value[0] & 0x07) == nas::ie::IdentityType::suci;
    }
    case 0x56:     // AUTHENTICATION REQUEST
    case 0x5A:     // AUTHENTICATION RESULT
    case 0x58:     // AUTHENTICATION REJECT
        return true;
    case 0x44: {   // REGISTRATION REJECT, unless #76, #78, #81 or #82
        const int c = cause();
        return c != 76 && c != 78 && c != 81 && c != 82;
    }
    case 0x46:     // DEREGISTRATION ACCEPT (UE originating)
    case 0x48:     // DEREGISTRATION ACCEPT (UE terminated)
        return true;   // the UE expects none after a switch-off: its entity drops one there
    case 0x4D: {   // SERVICE REJECT, unless #76 or #78
        const int c = cause();
        return c != 76 && c != 78;
    }
    default:
        return false;
    }
}

Result<InitialSplit> split_initial(const nas::Message& m) {
    if (m.desc == nullptr) {
        return make_error(Errc::invalid_argument, 0, "nas security: not a known message");
    }
    std::vector<std::string_view> clear;
    switch (m.desc->type) {
    case 0x41:   // REGISTRATION REQUEST
        clear = {"Extended protocol discriminator", "Security header type", "Spare half octet",
                 "Registration request message identity", "5GS registration type", "ngKSI", "5GS mobile identity",
                 "UE security capability", "Additional GUTI", "UE status", "EPS NAS message container", "NID",
                 "UE determined PLMN with disaster condition"};
        break;
    case 0x45:   // DEREGISTRATION REQUEST (UE originating)
        clear = {"Extended protocol discriminator", "Security header type", "Spare half octet",
                 "De-registration request message identity", "De-registration type", "ngKSI", "5GS mobile identity"};
        break;
    case 0x4C:   // SERVICE REQUEST
        clear = {"Extended protocol discriminator", "Security header type", "Spare half octet", "ngKSI",
                 "Service request message identity", "Service type", "5G-S-TMSI"};
        break;
    default:
        return make_error(Errc::invalid_argument, m.desc->type, "nas security: not an initial NAS message");
    }
    InitialSplit out;
    out.cleartext.desc = m.desc;
    for (const auto& e : m.ies) {
        const bool keep = e.desc != nullptr &&
                          std::find(clear.begin(), clear.end(), std::string_view(e.desc->name)) != clear.end();
        if (keep) {
            out.cleartext.ies.push_back(e);
        } else {
            out.has_non_cleartext = true;
        }
    }
    return out;
}

} // namespace ksim::proc::ue
