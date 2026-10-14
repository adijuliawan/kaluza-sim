// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/usim/usim.hpp"

#include <algorithm>
#include <array>

#include "codec/uicc/apdu.hpp"
#include "crypto/milenage.hpp"
#include "crypto/tuak.hpp"
#include "uicc/os/keyfile.hpp"

namespace ksim::uicc::usim {

namespace {

Response sw(std::uint16_t s) {
    Response r;
    r.sw1 = static_cast<std::uint8_t>(s >> 8);
    r.sw2 = static_cast<std::uint8_t>(s & 0xFF);
    return r;
}

constexpr std::uint16_t kOk = 0x9000;
constexpr std::uint16_t kAuthMacFailure = 0x9862;   // TS 31.102 §7.1.2.1: authentication error, incorrect MAC
constexpr std::uint16_t kSecurityNotSatisfied = 0x6982;
constexpr std::uint16_t kConditionsNotSatisfied = 0x6985;
constexpr std::uint16_t kWrongData = 0x6A80;
constexpr std::uint16_t kWrongP1P2 = 0x6A86;
constexpr std::uint16_t kWrongLength = 0x6700;
constexpr std::uint16_t kInternal = 0x6F00;

std::uint64_t be48(ByteView b) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 6; ++i) {
        v = (v << 8) | b[i];
    }
    return v;
}

void put48(std::uint8_t* out, std::uint64_t v) {
    for (int i = 5; i >= 0; --i) {
        out[i] = static_cast<std::uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

/// The algorithm set of AF20, run for one (SQN, AMF).
struct Algorithm {
    enum class Kind { milenage, tuak } kind = Kind::milenage;
    SecretBytes k;
    SecretBytes opc;        // OPc or TOPc
    crypto::tuak::Sizes sizes{};
    bool res4 = false;      // "only 4 bytes RES in 3G"

    struct Out {
        Bytes mac_a;
        Bytes mac_s;
        SecretBytes res;
        SecretBytes ck;
        SecretBytes ik;
        SecretBytes ak;
        SecretBytes ak_star;
    };

    Result<Out> run(ByteView rand, ByteView sqn, ByteView amf) const {
        if (kind == Kind::milenage) {
            auto o = crypto::milenage::compute(k, opc, rand, sqn, amf);
            if (!o) {
                return o.error();
            }
            return Out{o->mac_a, o->mac_s, std::move(o->res), std::move(o->ck), std::move(o->ik), std::move(o->ak),
                       std::move(o->ak_star)};
        }
        auto o = crypto::tuak::compute(k, opc, rand, sqn, amf, sizes);
        if (!o) {
            return o.error();
        }
        return Out{o->mac_a, o->mac_s, std::move(o->res), std::move(o->ck), std::move(o->ik), std::move(o->ak),
                   std::move(o->ak_star)};
    }
};

std::optional<Algorithm> load_algorithm(const os::File& f) {
    const std::uint8_t cfg = os::key_byte(f, 0, 0);
    const bool use_opc = (cfg & 0x10) != 0;
    Algorithm a;
    a.res4 = (cfg & 0x40) != 0;
    switch (cfg & 0x0F) {
    case 4: {   // Milenage
        a.kind = Algorithm::Kind::milenage;
        a.k = os::key_slice(f, 1, 16);
        SecretBytes op = os::key_slice(f, 17, 16);
        if (a.k.empty() || op.empty()) {
            return std::nullopt;
        }
        if (use_opc) {
            a.opc = std::move(op);
        } else {
            auto c = crypto::milenage::opc(a.k, op);
            if (!c) {
                return std::nullopt;
            }
            a.opc = std::move(*c);
        }
        return a;
    }
    case 6: {   // TUAK
        a.kind = Algorithm::Kind::tuak;
        const std::uint8_t tcfg = os::key_byte(f, 1, 0);
        static constexpr std::array<std::size_t, 4> kMac = {8, 16, 32, 0};
        static constexpr std::array<std::size_t, 8> kRes = {4, 8, 16, 32, 0, 0, 0, 0};
        a.sizes.k = (cfg & 0x40) != 0 ? 32 : 16;
        a.res4 = false;
        a.sizes.ck = a.sizes.ik = (tcfg & 0x40) != 0 ? 32 : 16;
        a.sizes.mac = kMac[(tcfg >> 3) & 0x03];
        a.sizes.res = kRes[tcfg & 0x07];
        a.sizes.iterations = os::key_byte(f, 2, 1);
        if (a.sizes.mac == 0 || a.sizes.res == 0 || a.sizes.iterations == 0) {
            return std::nullopt;
        }
        SecretBytes top = os::key_slice(f, 3, 32);
        a.k = os::key_slice(f, 35, a.sizes.k);
        if (a.k.empty() || top.empty()) {
            return std::nullopt;
        }
        if (use_opc) {
            a.opc = std::move(top);
        } else {
            auto c = crypto::tuak::topc(a.k, top, a.sizes);
            if (!c) {
                return std::nullopt;
            }
            a.opc = std::move(*c);
        }
        return a;
    }
    default:
        return std::nullopt;   // XOR, SHA-1 AKA: not on our cards
    }
}

/// EF.USIM_SQN as the card keeps it.
struct SqnState {
    bool skip_next = false;
    bool delta_check = false;
    bool sqn_check = true;
    unsigned ind_len = 5;
    std::uint64_t delta_max = 0;
    std::vector<std::uint64_t> highest;   // per IND value

    static SqnState read(ByteView d) {
        SqnState s;
        if (d.size() < 14) {
            s.sqn_check = false;
            return s;
        }
        s.skip_next = (d[0] & 0x80) != 0;
        s.delta_check = (d[0] & 0x40) != 0;
        s.sqn_check = (d[0] & 0x10) != 0;
        s.ind_len = d[0] & 0x0F;
        s.delta_max = be48(d.subspan(2));
        for (std::size_t off = 14; off + 6 <= d.size() && s.highest.size() < (1U << s.ind_len); off += 6) {
            s.highest.push_back(be48(d.subspan(off)));
        }
        s.highest.resize(std::size_t{1} << s.ind_len, 0);
        return s;
    }

    std::uint64_t highest_overall() const {
        return highest.empty() ? 0 : *std::max_element(highest.begin(), highest.end());
    }
};

} // namespace

bool service_available(ByteView ust, unsigned n) noexcept {
    if (n == 0 || (n - 1) / 8 >= ust.size()) {
        return false;
    }
    return (ust[(n - 1) / 8] & (1U << ((n - 1) % 8))) != 0;
}

std::optional<Response> Usim::handle(os::Card& card, os::Channel& ch, const Command& c) {
    if (c.ins == 0x88 && (c.cla & 0x80) == 0) {
        return authenticate(card, ch, c);
    }
    if (c.ins == 0x78 && (c.cla & 0x80) != 0) {
        return get_identity(card, ch, c);
    }
    return std::nullopt;
}

// TS 31.102 §7.1: AUTHENTICATE, the 3G context (P2 '81').
Response Usim::authenticate(os::Card& card, os::Channel& ch, const Command& c) {
    if (c.p1 != 0x00) {
        return sw(kWrongP1P2);
    }
    if (c.p2 != 0x81) {
        return sw(kWrongP1P2);   // the GSM context needs service 27, which our cards do not offer
    }
    if (const os::Pin* pin1 = card.pin(os::kPin1); pin1 != nullptr && pin1->enabled && !pin1->verified) {
        return sw(kSecurityNotSatisfied);   // §7.1.1: the application PIN must be verified
    }
    auto ch_data = uicc::decode_auth_challenge(c.data, uicc::AuthContext::umts);
    if (!ch_data || ch_data->rand.size() != 16 || ch_data->autn.size() != 16) {
        return sw(ch_data ? kWrongData : kWrongLength);
    }
    const os::File* keys = card.find_ef(*ch.app, kEfAuthKey);
    if (keys == nullptr || !keys->secret) {
        return sw(kConditionsNotSatisfied);
    }
    auto alg = load_algorithm(*keys);
    if (!alg) {
        return sw(kConditionsNotSatisfied);
    }
    const ByteView rand = ch_data->rand;
    const ByteView autn = ch_data->autn;
    static constexpr std::array<std::uint8_t, 6> kZeroSqn{};
    static constexpr std::array<std::uint8_t, 2> kZeroAmf{};
    // f5 does not depend on SQN or AMF: AK first, then SQN = (SQN ⊕ AK) ⊕ AK.
    auto first = alg->run(rand, kZeroSqn, kZeroAmf);
    if (!first) {
        return sw(kInternal);
    }
    std::array<std::uint8_t, 6> sqn{};
    {
        const ByteView ak = first->ak.expose();
        for (std::size_t i = 0; i < 6; ++i) {
            sqn[i] = static_cast<std::uint8_t>(autn[i] ^ ak[i]);
        }
    }
    const ByteView amf = autn.subspan(6, 2);
    const ByteView mac = autn.subspan(8, 8);
    auto out = alg->run(rand, sqn, amf);
    if (!out) {
        return sw(kInternal);
    }
    if (out->mac_a.size() != mac.size() || !std::equal(mac.begin(), mac.end(), out->mac_a.begin())) {
        return sw(kAuthMacFailure);
    }

    // The SQN check (TS 33.102 §6.3.3, Annex C.2): fresh when SEQ is above the
    // highest SEQ accepted for this IND, and (with the Δ check) not too far ahead.
    os::File* sqn_file = card.find_ef(*ch.app, kEfSqn);
    if (sqn_file != nullptr) {
        SqnState st = SqnState::read(sqn_file->data);
        const std::uint64_t got = be48(sqn);
        const std::uint64_t ind_mask = (std::uint64_t{1} << st.ind_len) - 1;
        const std::size_t ind = static_cast<std::size_t>(got & ind_mask);
        bool fresh = true;
        if (st.skip_next) {
            sqn_file->data[0] = static_cast<std::uint8_t>(sqn_file->data[0] & 0x7F);
        } else if (st.sqn_check) {
            const std::uint64_t seq = got >> st.ind_len;
            const std::uint64_t seq_ms = st.highest[ind] >> st.ind_len;
            fresh = seq > seq_ms;
            const std::uint64_t top = st.highest_overall();
            if (fresh && st.delta_check && got > top && got - top > st.delta_max) {
                fresh = false;
            }
        }
        if (!fresh) {
            // Synch failure: AUTS = SQN_MS ⊕ AK* ‖ MAC-S, with AMF* zero (TS 33.102 §6.3.3, §6.3.5).
            std::array<std::uint8_t, 6> sqn_ms{};
            put48(sqn_ms.data(), st.highest_overall());
            auto resync = alg->run(rand, sqn_ms, kZeroAmf);
            if (!resync) {
                return sw(kInternal);
            }
            Bytes auts(14);
            const ByteView ak_star = resync->ak_star.expose();
            for (std::size_t i = 0; i < 6; ++i) {
                auts[i] = static_cast<std::uint8_t>(sqn_ms[i] ^ ak_star[i]);
            }
            std::copy(resync->mac_s.begin(), resync->mac_s.end(), auts.begin() + 6);
            card.changed();
            Response r;
            r.data = uicc::encode_auth_sync_failure(auts);
            return r;
        }
        if (sqn_file->data.size() >= 14 + 6 * (ind + 1)) {
            put48(sqn_file->data.data() + 14 + 6 * ind, got);
        }
        card.changed();
    }

    ByteView res = out->res.expose();
    if (alg->res4 && res.size() > 4) {
        res = res.first(4);
    }
    Response r = sw(kOk);
    r.data = uicc::encode_auth_success(res, out->ck.expose(), out->ik.expose(), {});
    return r;
}

// TS 31.102 §7.5: GET IDENTITY. Card-side SUCI needs services 124 and 125;
// with 125 off the ME computes the SUCI and the card answers '6985' (§7.5.1.1).
Response Usim::get_identity(os::Card& card, os::Channel& ch, const Command& c) {
    (void)c;
    const os::File* ust = card.find_ef(*ch.app, kEfUst);
    const ByteView u = ust != nullptr ? ByteView(ust->data) : ByteView{};
    if (!service_available(u, 124) || !service_available(u, 125)) {
        return sw(kConditionsNotSatisfied);
    }
    // SUCI calculation on the card is the user's later decision (Profile A/B
    // key ids, KS-UICC-G2): until then a card offering it is refused.
    return sw(kConditionsNotSatisfied);
}

} // namespace ksim::uicc::usim
