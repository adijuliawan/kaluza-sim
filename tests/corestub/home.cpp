// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "home.hpp"

#include "crypto/eap_aka_prime.hpp"
#include "crypto/keys5g.hpp"
#include "crypto/milenage.hpp"

namespace ksim::corestub {

namespace {

constexpr unsigned kIndBits = 5;

Bytes be48(std::uint64_t v) {
    Bytes out(6);
    for (int i = 5; i >= 0; --i, v >>= 8) {
        out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v & 0xFF);
    }
    return out;
}

std::uint64_t read48(ByteView b) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 6; ++i) {
        v = (v << 8) | b[i];
    }
    return v;
}

} // namespace

void Home::add(std::string supi, SecretBytes k, SecretBytes opc, std::uint64_t seq) {
    subs_[std::move(supi)] = Sub{std::move(k), std::move(opc), seq};
}

std::string Home::find(std::string_view mcc, std::string_view mnc, std::string_view msin) const {
    std::string supi = std::string(mcc) + std::string(mnc) + std::string(msin);
    return subs_.count(supi) != 0 ? supi : std::string();
}

std::uint64_t Home::seq(const std::string& supi) const {
    auto it = subs_.find(supi);
    return it != subs_.end() ? it->second.seq : 0;
}

Result<Av> Home::make_av(const std::string& supi, std::string_view snn, ByteView abba, const AvOptions& o) {
    auto it = subs_.find(supi);
    if (it == subs_.end()) {
        return make_error(Errc::invalid_argument, 0, "home: unknown SUPI");
    }
    Sub& s = it->second;
    const std::uint64_t seq = o.seq.value_or(s.seq + 1);
    if (!o.seq) {
        s.seq = seq;
    }
    const Bytes sqn = be48(seq << kIndBits);
    const Bytes amf = {static_cast<std::uint8_t>(o.separation_bit ? 0x80 : 0x00), 0x00};
    Av av;
    av.rand.resize(16);
    rng_.fill(av.rand);
    auto m = crypto::milenage::compute(s.k, s.opc, av.rand, sqn, amf);
    if (!m) {
        return m.error();
    }
    av.autn.resize(16);
    for (std::size_t i = 0; i < 6; ++i) {
        av.autn[i] = static_cast<std::uint8_t>(sqn[i] ^ m->ak.expose()[i]);
    }
    av.autn[6] = amf[0];
    av.autn[7] = amf[1];
    std::copy(m->mac_a.begin(), m->mac_a.end(), av.autn.begin() + 8);
    if (o.corrupt_mac) {
        av.autn[15] ^= 0x01;
    }
    av.xres_star = crypto::keys5g::res_star(m->ck, m->ik, snn, av.rand, m->res);
    SecretBytes kausf;
    if (o.eap) {
        // TS 33.501 6.1.3.1 steps 1 and 10, Annex F.3: CK' and IK' for the serving
        // network name, MK for the IMSI, K_AUSF from EMSK.
        auto prime = crypto::keys5g::ck_ik_prime(m->ck, m->ik, snn, ByteView(av.autn).subspan(0, 6));
        auto keys = crypto::eap_aka_prime::derive(prime.ck_prime, prime.ik_prime, supi);
        kausf = crypto::eap_aka_prime::kausf(keys);
        av.xres = m->res.clone();
        av.k_aut = std::move(keys.k_aut);
    } else {
        kausf = crypto::keys5g::kausf(m->ck, m->ik, snn, ByteView(av.autn).subspan(0, 6));
    }
    const SecretBytes kseaf = crypto::keys5g::kseaf(kausf, snn);
    auto kamf = crypto::keys5g::kamf(kseaf, supi, abba);
    if (!kamf) {
        return kamf.error();
    }
    av.kamf = std::move(*kamf);
    return av;
}

Result<bool> Home::resync(const std::string& supi, ByteView rand, ByteView auts) {
    auto it = subs_.find(supi);
    if (it == subs_.end() || auts.size() != 14 || rand.size() != 16) {
        return make_error(Errc::invalid_argument, 0, "home: resync input");
    }
    Sub& s = it->second;
    const Bytes zero_amf = {0x00, 0x00};   // TS 33.102 §6.3.3: MAC-S over a dummy AMF of zeros
    auto first = crypto::milenage::compute(s.k, s.opc, rand, be48(0), zero_amf);
    if (!first) {
        return first.error();
    }
    Bytes sqn_ms(6);
    for (std::size_t i = 0; i < 6; ++i) {
        sqn_ms[i] = static_cast<std::uint8_t>(auts[i] ^ first->ak_star.expose()[i]);
    }
    auto m = crypto::milenage::compute(s.k, s.opc, rand, sqn_ms, zero_amf);
    if (!m) {
        return m.error();
    }
    if (!std::equal(m->mac_s.begin(), m->mac_s.end(), auts.begin() + 6)) {
        return false;
    }
    s.seq = read48(sqn_ms) >> kIndBits;
    return true;
}

} // namespace ksim::corestub
