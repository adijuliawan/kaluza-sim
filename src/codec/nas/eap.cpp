// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/nas/eap.hpp"

#include <algorithm>

namespace ksim::eap {

namespace {

Error bad(const char* what) { return make_error(Errc::malformed, 0, what); }

constexpr std::size_t kHeader = 4;      // code, identifier, length
constexpr std::size_t kAkaHeader = 8;   // + type, subtype, reserved

Attribute with_reserved(Attr t, ByteView v) {
    Attribute a{static_cast<std::uint8_t>(t), Bytes{0, 0}};
    a.value.insert(a.value.end(), v.begin(), v.end());
    return a;
}

void pad4(Bytes& v) {
    // The whole attribute (type, length, value) is a multiple of four octets.
    while ((v.size() + 2) % 4 != 0) {
        v.push_back(0);
    }
}

} // namespace

const Attribute* Packet::find(Attr a) const {
    for (const auto& x : attrs) {
        if (x.type == static_cast<std::uint8_t>(a)) {
            return &x;
        }
    }
    return nullptr;
}

Result<Packet> decode(ByteView in) {
    if (in.size() < kHeader) {
        return bad("eap: shorter than its header");
    }
    Packet p;
    if (in[0] < 1 || in[0] > 4) {
        return bad("eap: unknown code");
    }
    p.code = static_cast<Code>(in[0]);
    p.id = in[1];
    const std::size_t len = static_cast<std::size_t>(in[2]) << 8 | in[3];
    if (len != in.size()) {
        return bad("eap: the length field disagrees with the packet");
    }
    if (p.code == Code::success || p.code == Code::failure) {
        if (len != kHeader) {
            return bad("eap: success and failure are four octets");
        }
        return p;
    }
    if (len < kHeader + 1) {
        return bad("eap: a request or response without a type");
    }
    p.type = in[4];
    if (p.type != kTypeAkaPrime) {
        return p;   // another method: its data is not parsed here
    }
    if (len < kAkaHeader) {
        return bad("eap-aka': shorter than its header");
    }
    p.subtype = static_cast<Subtype>(in[5]);
    std::size_t off = kAkaHeader;
    while (off < len) {
        if (len - off < 2) {
            return bad("eap-aka': a truncated attribute");
        }
        const std::size_t alen = std::size_t{in[off + 1]} * 4;
        if (alen == 0) {
            return bad("eap-aka': an attribute of length 0");
        }
        if (alen > len - off) {
            return bad("eap-aka': an attribute overruns the packet");
        }
        p.attrs.push_back(Attribute{in[off], Bytes(in.begin() + static_cast<std::ptrdiff_t>(off + 2),
                                                   in.begin() + static_cast<std::ptrdiff_t>(off + alen))});
        off += alen;
    }
    return p;
}

Result<Bytes> encode(const Packet& p) {
    Bytes out{static_cast<std::uint8_t>(p.code), p.id, 0, 0};
    if (p.code == Code::request || p.code == Code::response) {
        out.push_back(p.type);
        out.push_back(static_cast<std::uint8_t>(p.subtype));
        out.push_back(0);
        out.push_back(0);
        for (const auto& a : p.attrs) {
            const std::size_t alen = a.value.size() + 2;
            if (alen % 4 != 0 || alen / 4 > 0xFF) {
                return bad("eap-aka': an attribute of a length that is not a multiple of four");
            }
            out.push_back(a.type);
            out.push_back(static_cast<std::uint8_t>(alen / 4));
            out.insert(out.end(), a.value.begin(), a.value.end());
        }
    }
    if (out.size() > 0xFFFF) {
        return bad("eap: too long");
    }
    out[2] = static_cast<std::uint8_t>(out.size() >> 8);
    out[3] = static_cast<std::uint8_t>(out.size());
    return out;
}

Attribute at_rand(ByteView rand) { return with_reserved(Attr::rand, rand); }
Attribute at_autn(ByteView autn) { return with_reserved(Attr::autn, autn); }
Attribute at_auts(ByteView auts) { return Attribute{static_cast<std::uint8_t>(Attr::auts), Bytes(auts.begin(), auts.end())}; }
Attribute at_mac_zero() { return with_reserved(Attr::mac, Bytes(16, 0)); }

Attribute at_res(ByteView res) {
    const std::size_t bits = res.size() * 8;
    Attribute a{static_cast<std::uint8_t>(Attr::res),
                Bytes{static_cast<std::uint8_t>(bits >> 8), static_cast<std::uint8_t>(bits)}};
    a.value.insert(a.value.end(), res.begin(), res.end());
    pad4(a.value);
    return a;
}

Attribute at_kdf(std::uint16_t kdf) {
    return Attribute{static_cast<std::uint8_t>(Attr::kdf),
                     Bytes{static_cast<std::uint8_t>(kdf >> 8), static_cast<std::uint8_t>(kdf)}};
}

Attribute at_kdf_input(const std::string& network_name) {
    Attribute a{static_cast<std::uint8_t>(Attr::kdf_input),
                Bytes{static_cast<std::uint8_t>(network_name.size() >> 8), static_cast<std::uint8_t>(network_name.size())}};
    a.value.insert(a.value.end(), network_name.begin(), network_name.end());
    pad4(a.value);
    return a;
}

Attribute at_client_error_code(std::uint16_t code) {
    return Attribute{static_cast<std::uint8_t>(Attr::client_error_code),
                     Bytes{static_cast<std::uint8_t>(code >> 8), static_cast<std::uint8_t>(code)}};
}

std::optional<Bytes> value16(const Attribute& a) {
    if (a.value.size() != 18) {
        return std::nullopt;
    }
    return Bytes(a.value.begin() + 2, a.value.end());
}

std::optional<Bytes> res_of(const Attribute& a) {
    if (a.value.size() < 2) {
        return std::nullopt;
    }
    const std::size_t bits = std::size_t{a.value[0]} << 8 | a.value[1];
    // RFC 4187 10.8: 32 to 128 bits; P1 takes whole octets (MILENAGE's f2 gives 64).
    if (bits < 32 || bits > 128 || bits % 8 != 0 || bits / 8 > a.value.size() - 2) {
        return std::nullopt;
    }
    return Bytes(a.value.begin() + 2, a.value.begin() + 2 + static_cast<std::ptrdiff_t>(bits / 8));
}

std::optional<Bytes> auts_of(const Attribute& a) {
    if (a.value.size() != 14) {
        return std::nullopt;
    }
    return a.value;
}

std::optional<std::uint16_t> kdf_of(const Attribute& a) {
    if (a.value.size() != 2) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(a.value[0] << 8 | a.value[1]);
}

std::optional<std::string> network_name_of(const Attribute& a) {
    if (a.value.size() < 2) {
        return std::nullopt;
    }
    const std::size_t n = std::size_t{a.value[0]} << 8 | a.value[1];
    if (n > a.value.size() - 2) {
        return std::nullopt;
    }
    return std::string(a.value.begin() + 2, a.value.begin() + 2 + static_cast<std::ptrdiff_t>(n));
}

std::optional<std::size_t> mac_offset(ByteView packet) {
    auto p = decode(packet);
    if (!p || p->type != kTypeAkaPrime || (p->code != Code::request && p->code != Code::response)) {
        return std::nullopt;
    }
    std::size_t off = kAkaHeader;
    for (const auto& a : p->attrs) {
        if (a.type == static_cast<std::uint8_t>(Attr::mac) && a.value.size() == 18) {
            return off + 4;   // type, length, two reserved octets
        }
        off += a.value.size() + 2;
    }
    return std::nullopt;
}

} // namespace ksim::eap
