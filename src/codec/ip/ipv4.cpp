// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/ip/ipv4.hpp"

#include <algorithm>

namespace ksim::ip {

namespace {

constexpr std::size_t kHeader = 20;
constexpr std::size_t kIcmpHeader = 8;

std::uint16_t be16(ByteView in, std::size_t at) noexcept {
    return static_cast<std::uint16_t>(in[at] << 8 | in[at + 1]);
}

void put16(Bytes& out, std::size_t at, std::uint16_t v) {
    out[at] = static_cast<std::uint8_t>(v >> 8);
    out[at + 1] = static_cast<std::uint8_t>(v & 0xFF);
}

} // namespace

std::uint16_t checksum(ByteView in) noexcept {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    for (; i + 1 < in.size(); i += 2) {
        sum += be16(in, i);
    }
    if (i < in.size()) {
        sum += static_cast<std::uint32_t>(in[i]) << 8;
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFF);
}

Bytes encode(const Ipv4& p) {
    Bytes out(kHeader, 0);
    out[0] = 0x45;   // version 4, IHL 5
    out[1] = p.tos;
    put16(out, 2, static_cast<std::uint16_t>(kHeader + p.payload.size()));
    put16(out, 4, p.id);
    out[6] = p.dont_fragment ? 0x40 : 0x00;
    out[8] = p.ttl;
    out[9] = p.protocol;
    std::copy(p.src.begin(), p.src.end(), out.begin() + 12);
    std::copy(p.dst.begin(), p.dst.end(), out.begin() + 16);
    put16(out, 10, checksum(out));
    out.insert(out.end(), p.payload.begin(), p.payload.end());
    return out;
}

Result<Ipv4> decode(ByteView in) {
    if (in.size() < kHeader) {
        return make_error(Errc::truncated, static_cast<std::uint32_t>(in.size()), "ipv4: shorter than a header");
    }
    if ((in[0] >> 4) != 4) {
        return make_error(Errc::malformed, 0, "ipv4: not version 4");
    }
    const std::size_t ihl = static_cast<std::size_t>(in[0] & 0x0F) * 4;
    const std::size_t total = be16(in, 2);
    if (ihl < kHeader || ihl > in.size() || total < ihl || total > in.size()) {
        return make_error(Errc::malformed, 0, "ipv4: header or total length");
    }
    if (checksum(in.first(ihl)) != 0) {
        return make_error(Errc::malformed, 10, "ipv4: header checksum");
    }
    const std::uint16_t frag = be16(in, 6);
    if ((frag & 0x2000) != 0 || (frag & 0x1FFF) != 0) {
        return make_error(Errc::unsupported, 6, "ipv4: a fragment");
    }
    Ipv4 p;
    p.tos = in[1];
    p.id = be16(in, 4);
    p.dont_fragment = (frag & 0x4000) != 0;
    p.ttl = in[8];
    p.protocol = in[9];
    std::copy(in.begin() + 12, in.begin() + 16, p.src.begin());
    std::copy(in.begin() + 16, in.begin() + 20, p.dst.begin());
    p.payload.assign(in.begin() + static_cast<std::ptrdiff_t>(ihl), in.begin() + static_cast<std::ptrdiff_t>(total));
    return p;
}

Bytes encode_icmp(const Echo& e) {
    Bytes out(kIcmpHeader, 0);
    out[0] = e.reply ? 0 : 8;
    put16(out, 4, e.id);
    put16(out, 6, e.seq);
    out.insert(out.end(), e.data.begin(), e.data.end());
    put16(out, 2, checksum(out));
    return out;
}

Result<std::optional<Echo>> decode_icmp(ByteView in) {
    if (in.size() < kIcmpHeader) {
        return make_error(Errc::truncated, static_cast<std::uint32_t>(in.size()), "icmp: shorter than a header");
    }
    if (checksum(in) != 0) {
        return make_error(Errc::malformed, 2, "icmp: checksum");
    }
    if ((in[0] != 0 && in[0] != 8) || in[1] != 0) {
        return std::optional<Echo>{};
    }
    Echo e;
    e.reply = in[0] == 0;
    e.id = be16(in, 4);
    e.seq = be16(in, 6);
    e.data.assign(in.begin() + kIcmpHeader, in.end());
    return std::optional<Echo>{std::move(e)};
}

Bytes ping(const Addr& src, const Addr& dst, std::uint16_t id, std::uint16_t seq, std::size_t size) {
    Echo e;
    e.id = id;
    e.seq = seq;
    e.data.resize(size);
    for (std::size_t i = 0; i < size; ++i) {
        e.data[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    Ipv4 p;
    p.id = seq;
    p.dont_fragment = true;
    p.protocol = kIcmp;
    p.src = src;
    p.dst = dst;
    p.payload = encode_icmp(e);
    return encode(p);
}

} // namespace ksim::ip
