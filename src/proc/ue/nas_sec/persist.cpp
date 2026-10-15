// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/nas_sec/persist.hpp"

#include <algorithm>

namespace ksim::proc::ue::persist {

namespace ie = nas::ie;

namespace {

constexpr std::uint8_t kNscTag = 0xA0;
constexpr std::uint8_t kNgKsiTag = 0x80;
constexpr std::uint8_t kKamfTag = 0x81;
constexpr std::uint8_t kUlTag = 0x82;
constexpr std::uint8_t kDlTag = 0x83;
constexpr std::uint8_t kAlgTag = 0x84;
constexpr std::size_t kKeySize = 32;

void put32(Bytes& out, std::uint32_t v) {
    for (int s = 24; s >= 0; s -= 8) {
        out.push_back(static_cast<std::uint8_t>(v >> s));
    }
}

void pad(Bytes& out, std::size_t size) {
    if (out.size() < size) {
        out.resize(size, 0xFF);
    }
}

Error bad(const char* what) { return make_error(Errc::malformed, 0, what); }

} // namespace

Bytes encode_loci(const Loci& l) {
    Bytes out;
    out.reserve(kLociSize);
    if (l.guti) {
        // Bytes 1-13: octets 2-14 of a 5GS mobile identity IE holding a 5G-GUTI (its length, then the value).
        if (auto v = l.guti->encode(); v && v->size() == 11) {
            out.push_back(0);
            out.push_back(11);
            out.insert(out.end(), v->begin(), v->end());
        }
    }
    out.resize(13, 0xFF);
    if (l.tai) {
        // Bytes 14-19: octets 2-7 of a 5GS tracking area identity IE.
        const Bytes t = ie::TaiIe{*l.tai}.encode();
        out.insert(out.end(), t.begin(), t.end());
    }
    out.resize(19, 0xFF);
    out.push_back(static_cast<std::uint8_t>(l.update_status & 0x07));
    return out;
}

Result<Loci> decode_loci(ByteView in) {
    if (in.size() < kLociSize) {
        return make_error(Errc::truncated, static_cast<std::uint32_t>(in.size()), "EF.5GS3GPPLOCI: 20 octets");
    }
    Loci l;
    const std::size_t len = static_cast<std::size_t>(in[0]) << 8 | in[1];
    if (len == 11) {
        auto g = ie::MobileIdentity::decode(in.subspan(2, 11));
        if (g && g->type == ie::MobileIdentity::Type::guti) {
            l.guti = std::move(*g);
        }
    }
    // A deleted TAI: the PLMN 'FFFFFF' (a fresh card has TAC 000000 behind it).
    if (!std::all_of(in.begin() + 13, in.begin() + 16, [](std::uint8_t b) { return b == 0xFF; })) {
        auto t = ie::TaiIe::decode(in.subspan(13, 6));
        if (!t) {
            return bad("EF.5GS3GPPLOCI: the TAI");
        }
        l.tai = t->tai;
    }
    l.update_status = static_cast<std::uint8_t>(in[19] & 0x07);
    return l;
}

SecretBytes encode_nsc(const NasSecurityContext* ctx, std::size_t size) {
    Bytes body;
    body.push_back(kNgKsiTag);
    body.push_back(1);
    if (ctx == nullptr) {
        body.push_back(0x07);   // no key available
        body.push_back(kKamfTag);
        body.push_back(0);
    } else {
        body.push_back(static_cast<std::uint8_t>(ctx->ngksi().value & 0x07));
        body.push_back(kKamfTag);
        body.push_back(static_cast<std::uint8_t>(kKeySize));
        const auto k = ctx->kamf().expose();
        body.insert(body.end(), k.begin(), k.end());
        body.push_back(kUlTag);
        body.push_back(4);
        put32(body, ctx->ul_count());
        body.push_back(kDlTag);
        body.push_back(4);
        put32(body, ctx->dl_count().value_or(0));
        body.push_back(kAlgTag);
        body.push_back(1);
        body.push_back(static_cast<std::uint8_t>((ctx->ea() & 0x0F) << 4 | (ctx->ia() & 0x0F)));
    }
    Bytes out;
    out.reserve(std::max(size, body.size() + 2));
    out.push_back(kNscTag);
    out.push_back(static_cast<std::uint8_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    secure_zero(body);
    pad(out, size);
    SecretBytes s = SecretBytes::copy_of(out);
    secure_zero(out);
    return s;
}

Result<std::optional<NasSecurityContext>> decode_nsc(ByteView record) {
    if (record.size() < 2 || record[0] != kNscTag) {
        return bad("EF.5GS3GPPNSC: no 5GS NAS security context tag");
    }
    const std::size_t len = record[1];
    if (len + 2 > record.size()) {
        return bad("EF.5GS3GPPNSC: the length runs past the record");
    }
    std::optional<std::uint8_t> ngksi;
    std::optional<ByteView> kamf;
    std::optional<std::uint32_t> ul;
    std::optional<std::uint32_t> dl;
    std::optional<std::uint8_t> alg;
    std::size_t pos = 2;
    while (pos + 2 <= len + 2) {
        const std::uint8_t tag = record[pos];
        const std::size_t l = record[pos + 1];
        if (pos + 2 + l > len + 2) {
            return bad("EF.5GS3GPPNSC: a TLV runs past the context");
        }
        const ByteView v = record.subspan(pos + 2, l);
        auto u32 = [&](ByteView b) {
            return static_cast<std::uint32_t>(b[0]) << 24 | static_cast<std::uint32_t>(b[1]) << 16 |
                   static_cast<std::uint32_t>(b[2]) << 8 | b[3];
        };
        switch (tag) {
        case kNgKsiTag: if (l == 1) { ngksi = static_cast<std::uint8_t>(v[0] & 0x07); } break;
        case kKamfTag: if (l == kKeySize) { kamf = v; } break;
        case kUlTag: if (l == 4) { ul = u32(v); } break;
        case kDlTag: if (l == 4) { dl = u32(v); } break;
        case kAlgTag: if (l == 1) { alg = v[0]; } break;
        default: break;
        }
        pos += 2 + l;
    }
    if (!ngksi || *ngksi == 7 || !kamf || !ul || !alg) {
        return std::optional<NasSecurityContext>{};   // no valid context stored
    }
    auto ctx = NasSecurityContext::derive(ie::NgKsi{false, *ngksi}, SecretBytes::copy_of(*kamf),
                                          static_cast<std::uint8_t>(*alg >> 4), static_cast<std::uint8_t>(*alg & 0x0F));
    if (!ctx) {
        return ctx.error();
    }
    ctx->restore_counts(*ul, dl);
    return std::optional<NasSecurityContext>(std::move(*ctx));
}

SecretBytes encode_auth_keys(const SecretBytes* kausf, const SecretBytes* kseaf, std::size_t size) {
    Bytes out;
    for (auto [tag, key] : {std::pair{std::uint8_t{0x80}, kausf}, std::pair{std::uint8_t{0x81}, kseaf}}) {
        out.push_back(tag);
        if (key == nullptr) {
            out.push_back(32);   // no valid key: 'FF...FF' (TS 31.102 4.4.11.6)
            out.insert(out.end(), 32, std::uint8_t{0xFF});
            continue;
        }
        const auto k = key->expose();
        out.push_back(static_cast<std::uint8_t>(k.size()));
        out.insert(out.end(), k.begin(), k.end());
    }
    pad(out, size);
    SecretBytes s = SecretBytes::copy_of(out);
    secure_zero(out);
    return s;
}

} // namespace ksim::proc::ue::persist
