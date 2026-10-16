// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/uicc/fcp.hpp"

#include <algorithm>

namespace ksim::uicc {

namespace {

Error err(Errc c, std::size_t off, const char* what) {
    return make_error(c, static_cast<std::uint32_t>(off), what);
}

constexpr std::uint32_t kFcp = 0x62;

Result<std::vector<Tlv>> decode_at(ByteView in, std::size_t base, int depth) {
    if (depth > 8) {
        return err(Errc::malformed, base, "BER-TLV: nested too deep");
    }
    std::vector<Tlv> out;
    std::size_t pos = 0;
    while (pos < in.size()) {
        Tlv t;
        t.offset = base + pos;
        t.tag = in[pos++];
        if ((t.tag & 0x1F) == 0x1F) {   // more tag octets follow, while b8 is set
            do {
                if (pos >= in.size() || t.tag_octets == 3) {
                    return err(Errc::malformed, t.offset, "BER-TLV: tag runs on");
                }
                t.tag = (t.tag << 8) | in[pos];
                ++t.tag_octets;
            } while ((in[pos++] & 0x80) != 0);
        }
        if (pos >= in.size()) {
            return err(Errc::truncated, base + pos, "BER-TLV: no length");
        }
        std::size_t len = in[pos++];
        if (len == 0x81 || len == 0x82) {
            t.length_octets = static_cast<std::uint8_t>(len == 0x81 ? 2 : 3);
            if (pos + t.length_octets - 1 > in.size()) {
                return err(Errc::truncated, base + pos, "BER-TLV: long length cut short");
            }
            len = in[pos++];
            if (t.length_octets == 3) {
                len = (len << 8) | in[pos++];
            }
        } else if (len > 0x7F) {
            return err(Errc::malformed, base + pos - 1, "BER-TLV: length form not used by TS 102 221");
        }
        if (pos + len > in.size()) {
            return err(Errc::truncated, base + pos, "BER-TLV: value runs past the end");
        }
        const ByteView v = in.subspan(pos, len);
        if (t.constructed()) {
            auto kids = decode_at(v, base + pos, depth + 1);
            if (!kids) {
                return kids.error();
            }
            t.children = std::move(*kids);
        } else {
            t.value.assign(v.begin(), v.end());
        }
        pos += len;
        out.push_back(std::move(t));
    }
    return out;
}

Result<void> encode_into(ByteWriter& w, const Tlv& t) {
    for (int k = t.tag_octets - 1; k >= 0; --k) {
        w.u8(static_cast<std::uint8_t>(t.tag >> (8 * k)));
    }
    Bytes body;
    if (t.constructed()) {
        auto b = encode_ber(t.children);
        if (!b) {
            return b.error();
        }
        body = std::move(*b);
    } else {
        body = t.value;
    }
    const std::size_t n = body.size();
    const std::uint8_t need = n < 0x80 ? 1 : n <= 0xFF ? 2 : n <= 0xFFFF ? 3 : 4;
    const std::uint8_t form = std::max(need, t.length_octets);
    if (form == 1) {
        w.u8(static_cast<std::uint8_t>(n));
    } else if (form == 2) {
        w.u8(0x81);
        w.u8(static_cast<std::uint8_t>(n));
    } else if (form == 3) {
        w.u8(0x82);
        w.u16(static_cast<std::uint16_t>(n));
    } else {
        return err(Errc::overflow, w.size(), "BER-TLV: value over 65535 octets");
    }
    w.bytes(body);
    return {};
}

std::uint64_t number(const Bytes& b) {
    std::uint64_t v = 0;
    for (std::uint8_t o : b) {
        v = (v << 8) | o;
    }
    return v;
}

} // namespace

bool Tlv::constructed() const noexcept {
    const int shift = tag_octets > 0 ? 8 * (tag_octets - 1) : 0;   // a hand-built Tlv may leave it 0
    const auto first = static_cast<std::uint8_t>(tag >> shift);
    return (first & 0x20) != 0;
}

const Tlv* Tlv::find(std::uint32_t t) const noexcept {
    for (const Tlv& c : children) {
        if (c.tag == t) {
            return &c;
        }
    }
    return nullptr;
}

Result<std::vector<Tlv>> decode_ber(ByteView in) {
    return decode_at(in, 0, 0);
}

Result<Bytes> encode_ber(const std::vector<Tlv>& objects) {
    ByteWriter w(32);
    for (const Tlv& t : objects) {
        if (auto ok = encode_into(w, t); !ok) {
            return ok.error();
        }
    }
    return std::move(w).take();
}

const char* FileDescriptor::file_type() const noexcept {
    const unsigned t = (descriptor >> 3) & 0x07;
    if (t == 0x07) {
        return (descriptor & 0x07) == 0x00 ? "df" : (descriptor & 0x07) == 0x01 ? "working_ef" : "rfu";
    }
    return t == 0 ? "working_ef" : t == 1 ? "internal_ef" : "rfu";
}

const char* FileDescriptor::structure() const noexcept {
    if ((descriptor & 0x38) == 0x38) {   // b6-b4 all set: a DF (b3-b1 000) or a BER-TLV EF (001)
        return (descriptor & 0x07) == 0x01 ? "ber_tlv" : "none";
    }
    switch (descriptor & 0x07) {
    case 0: return "none";
    case 1: return "transparent";
    case 2: return "linear_fixed";
    case 6: return "cyclic";
    default: return "rfu";
    }
}

std::optional<FileDescriptor> Fcp::file_descriptor() const {
    const Tlv* t = root.find(0x82);
    if (t == nullptr || (t->value.size() != 2 && t->value.size() != 5)) {
        return std::nullopt;
    }
    FileDescriptor d{t->value[0], t->value[1], std::nullopt, std::nullopt};
    if (t->value.size() == 5) {
        d.record_length = static_cast<std::uint16_t>((t->value[2] << 8) | t->value[3]);
        d.records = t->value[4];
    }
    return d;
}

std::optional<std::uint16_t> Fcp::file_id() const {
    const Tlv* t = root.find(0x83);
    if (t == nullptr || t->value.size() != 2) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>((t->value[0] << 8) | t->value[1]);
}

std::optional<Bytes> Fcp::df_name() const {
    const Tlv* t = root.find(0x84);
    return t != nullptr ? std::optional<Bytes>(t->value) : std::nullopt;
}

std::optional<std::uint8_t> Fcp::life_cycle() const {
    const Tlv* t = root.find(0x8A);
    return t != nullptr && t->value.size() == 1 ? std::optional<std::uint8_t>(t->value[0]) : std::nullopt;
}

std::optional<std::uint64_t> Fcp::file_size() const {
    const Tlv* t = root.find(0x80);
    return t != nullptr && !t->value.empty() && t->value.size() <= 8 ? std::optional(number(t->value)) : std::nullopt;
}

std::optional<std::uint64_t> Fcp::total_file_size() const {
    const Tlv* t = root.find(0x81);
    return t != nullptr && !t->value.empty() && t->value.size() <= 8 ? std::optional(number(t->value)) : std::nullopt;
}

std::optional<std::uint8_t> Fcp::sfi() const {
    if (const Tlv* t = root.find(0x88); t != nullptr) {
        if (t->value.size() != 1) {
            return std::nullopt;
        }
        return static_cast<std::uint8_t>(t->value[0] >> 3);
    }
    if (auto fid = file_id(); fid) {
        return static_cast<std::uint8_t>(*fid & 0x1F);
    }
    return std::nullopt;
}

std::vector<std::uint8_t> Fcp::pin_key_references() const {
    // 'C6' is a template of PS_DO ('90'), usage qualifiers ('95') and key
    // references ('83') though its tag's constructed bit (b6) is clear, so its
    // value is read as BER-TLV here (11.1.1.4.10).
    std::vector<std::uint8_t> out;
    if (const Tlv* c6 = root.find(0xC6); c6 != nullptr) {
        auto inner = c6->constructed() ? std::optional(c6->children) : std::nullopt;
        if (!inner) {
            if (auto parsed = decode_ber(c6->value); parsed) {
                inner = std::move(*parsed);
            }
        }
        for (const Tlv& t : inner.value_or(std::vector<Tlv>{})) {
            if (t.tag == 0x83 && t.value.size() == 1) {
                out.push_back(t.value[0]);
            }
        }
    }
    return out;
}

std::optional<bool> Fcp::pin_enabled(std::uint8_t ref) const {
    const Tlv* c6 = root.find(0xC6);
    if (c6 == nullptr) {
        return std::nullopt;
    }
    auto inner = c6->constructed() ? std::optional(c6->children) : std::nullopt;
    if (!inner) {
        if (auto parsed = decode_ber(c6->value); parsed) {
            inner = std::move(*parsed);
        }
    }
    if (!inner) {
        return std::nullopt;
    }
    const Bytes* ps = nullptr;   // into *inner, which outlives it
    std::size_t index = 0;
    std::optional<std::size_t> at;
    for (const Tlv& t : *inner) {
        if (t.tag == 0x90) {
            ps = &t.value;
        } else if (t.tag == 0x83 && t.value.size() == 1) {
            if (t.value[0] == ref && !at) {
                at = index;
            }
            ++index;
        }
    }
    if (ps == nullptr || !at || *at / 8 >= ps->size()) {
        return std::nullopt;
    }
    return ((*ps)[*at / 8] & (0x80U >> (*at % 8))) != 0;
}

Result<Fcp> decode_fcp(ByteView in) {
    auto objs = decode_ber(in);
    if (!objs) {
        return objs.error();
    }
    if (objs->size() != 1 || objs->front().tag != kFcp) {
        return err(Errc::malformed, 0, "FCP: not one template with tag '62'");
    }
    Fcp f{std::move(objs->front())};
    if (!f.file_descriptor()) {
        return err(Errc::malformed, 2, "FCP: no file descriptor ('82', 2 or 5 octets)");
    }
    return f;
}

Result<Bytes> encode_fcp(const Fcp& f) {
    return encode_ber({f.root});
}

std::string to_json(const Fcp& f) {
    std::string s = "{\"protocol\":\"fcp\"";
    if (auto d = f.file_descriptor(); d) {
        s += ",\"descriptor\":" + std::to_string(d->descriptor) + ",\"file_type\":\"" + d->file_type() +
             "\",\"structure\":\"" + d->structure() + "\",\"shareable\":" + (d->shareable() ? "true" : "false");
        if (d->record_length && d->records) {
            s += ",\"record_length\":" + std::to_string(*d->record_length) + ",\"records\":" + std::to_string(*d->records);
        }
    }
    if (auto v = f.file_id(); v) {
        s += ",\"file_id\":" + std::to_string(*v);
    }
    if (auto v = f.df_name(); v) {
        s += ",\"df_name\":\"" + to_hex(*v) + "\"";
    }
    if (auto v = f.life_cycle(); v) {
        s += ",\"life_cycle\":" + std::to_string(*v);
    }
    if (auto v = f.file_size(); v) {
        s += ",\"file_size\":" + std::to_string(*v);
    }
    if (auto v = f.total_file_size(); v) {
        s += ",\"total_file_size\":" + std::to_string(*v);
    }
    if (auto v = f.sfi(); v) {
        s += ",\"sfi\":" + std::to_string(*v);
    }
    const auto refs = f.pin_key_references();
    if (f.root.find(0xC6) != nullptr) {
        s += ",\"pin_key_references\":[";
        for (std::size_t i = 0; i < refs.size(); ++i) {
            s += (i != 0 ? "," : "") + std::to_string(refs[i]);
        }
        s += "]";
    }
    for (std::uint32_t tag : {0x8BU, 0x8CU, 0xABU}) {
        if (const Tlv* t = f.root.find(tag); t != nullptr) {
            s += ",\"security_tag\":" + std::to_string(tag) + ",\"security\":\"" + to_hex(t->value) + "\"";
        }
    }
    s += ",\"tags\":[";
    for (std::size_t i = 0; i < f.root.children.size(); ++i) {
        s += (i != 0 ? "," : "") + std::to_string(f.root.children[i].tag);
    }
    return s + "]}";
}

} // namespace ksim::uicc
