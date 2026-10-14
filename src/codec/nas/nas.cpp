// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/nas/nas.hpp"

#include <cstring>

namespace ksim::nas {

namespace {

Error err(Errc c, std::size_t off, const char* what) {
    return make_error(c, static_cast<std::uint32_t>(off), what);
}

/// TS 24.007 11.2.4: the format an IEI unknown in the message implies (5GS).
Format implied_format(std::uint8_t iei) {
    if ((iei & 0x80) != 0) {
        return Format::tv;  // type 1 or type 2: the whole IE is one octet
    }
    if ((iei & 0x70) == 0x70) {
        return Format::tlv_e;
    }
    return Format::tlv;
}

/// TS 24.007 11.2.4: 'comprehension required' (type 4: bits 8-5 zero; type 6:
/// bit 8 zero and bits 7-2 one).
bool comprehension_required(std::uint8_t iei, Format f) {
    if (f == Format::tlv) {
        return (iei & 0xF0) == 0;
    }
    if (f == Format::tlv_e) {
        return (iei & 0xFE) == 0x7E;
    }
    return false;
}

/// The descriptor for an IEI in the message's non-imperative part.
const IeDesc* known(const MsgDesc& m, std::uint8_t octet) {
    for (const IeDesc& d : m.table()) {
        if (d.iei_kind == IeiKind::full && d.iei == octet) {
            return &d;
        }
    }
    for (const IeDesc& d : m.table()) {
        if (d.iei_kind == IeiKind::half && d.iei == (octet >> 4)) {
            return &d;
        }
    }
    return nullptr;
}

bool length_ok(const IeDesc& d, std::size_t total) {
    return total >= d.min_len && (d.max_len == 0xFFFF || total <= d.max_len);
}

} // namespace

const MsgDesc* find_message(Epd epd, std::uint8_t type) noexcept {
    for (const MsgDesc& m : messages()) {
        if (m.epd == epd && m.type == type && std::strcmp(m.key, "8.2.28") != 0) {
            return &m;
        }
    }
    return nullptr;
}

const Ie* Message::find(std::string_view ie_name) const noexcept {
    for (const Ie& ie : ies) {
        if (ie.desc != nullptr && !ie.repeated && ie_name == ie.desc->name) {
            return &ie;
        }
    }
    return nullptr;
}

std::size_t Message::unknown_count() const noexcept {
    std::size_t n = 0;
    for (const Ie& ie : ies) {
        n += ie.desc == nullptr ? 1 : 0;
    }
    return n;
}

Result<Message> decode(ByteView in) {
    if (in.size() < 3) {
        return err(Errc::truncated, 0, "NAS: shorter than a header");
    }
    Epd epd;
    std::uint8_t type;
    if (in[0] == static_cast<std::uint8_t>(Epd::mm)) {
        if ((in[1] & 0x0F) != 0) {
            return err(Errc::invalid_argument, 1, "NAS: security protected; use decode_protected()");
        }
        epd = Epd::mm;
        type = in[2];
    } else if (in[0] == static_cast<std::uint8_t>(Epd::sm)) {
        if (in.size() < 4) {
            return err(Errc::truncated, 0, "NAS: shorter than a 5GSM header");
        }
        epd = Epd::sm;
        type = in[3];
    } else {
        return err(Errc::malformed, 0, "NAS: not a 5GMM or 5GSM extended protocol discriminator");
    }
    Message m;
    m.desc = find_message(epd, type);
    if (m.desc == nullptr) {
        return err(Errc::unsupported, epd == Epd::mm ? 2 : 3, "NAS: message type not in TS 24.501");
    }

    std::size_t pos = 0;
    bool high_nibble = false;  // the next half-octet IE takes bits 8-5 of the current octet
    const auto table = m.desc->table();
    std::size_t i = 0;
    // Imperative part: every IE without an IEI, in table order.
    for (; i < table.size() && table[i].iei_kind == IeiKind::none; ++i) {
        const IeDesc& d = table[i];
        Ie ie;
        ie.desc = &d;
        ie.offset = pos;
        if (d.half_octet()) {
            if (pos >= in.size()) {
                return err(Errc::truncated, pos, "NAS: imperative part ends early");
            }
            ie.value.push_back(high_nibble ? static_cast<std::uint8_t>(in[pos] >> 4)
                                           : static_cast<std::uint8_t>(in[pos] & 0x0F));
            if (high_nibble) {
                ++pos;
            }
            high_nibble = !high_nibble;
            m.ies.push_back(std::move(ie));
            continue;
        }
        if (high_nibble) {
            return err(Errc::malformed, pos, "NAS: a lone half-octet IE in the table");
        }
        std::size_t len = 0;
        std::size_t hdr = 0;
        if (d.format == Format::v) {
            // a V IE has a fixed length, except the last one of a message that
            // runs to its end (the plain NAS message of 8.2.28)
            len = d.min_len == d.max_len ? d.min_len : in.size() - pos;
        } else if (d.format == Format::lv) {
            if (pos >= in.size()) {
                return err(Errc::truncated, pos, "NAS: missing length");
            }
            len = in[pos];
            hdr = 1;
        } else if (d.format == Format::lv_e) {
            if (pos + 2 > in.size()) {
                return err(Errc::truncated, pos, "NAS: missing length");
            }
            len = (std::size_t{in[pos]} << 8) | in[pos + 1];
            hdr = 2;
        } else {
            return err(Errc::internal, pos, "NAS: an IEI-less IE with an IEI format");
        }
        if (pos + hdr + len > in.size()) {
            return err(Errc::truncated, pos, "NAS: mandatory IE runs past the end");
        }
        if (!length_ok(d, hdr + len) && d.format != Format::v) {
            return err(Errc::malformed, pos, "NAS: mandatory IE length outside its table range");
        }
        ie.value.assign(in.begin() + static_cast<std::ptrdiff_t>(pos + hdr),
                        in.begin() + static_cast<std::ptrdiff_t>(pos + hdr + len));
        pos += hdr + len;
        m.ies.push_back(std::move(ie));
    }
    if (high_nibble) {
        return err(Errc::malformed, pos, "NAS: the imperative part ends on a half octet");
    }

    // Non-imperative part: by IEI, any order.
    while (pos < in.size()) {
        const std::uint8_t octet = in[pos];
        const IeDesc* d = known(*m.desc, octet);
        Ie ie;
        ie.iei = octet;
        ie.offset = pos;
        const Format f = d != nullptr ? d->format : implied_format(octet);
        std::size_t total = 0;
        std::size_t hdr = 1;
        switch (f) {
        case Format::t:
            total = 1;
            break;
        case Format::tv:
            if (d != nullptr && d->iei_kind == IeiKind::half) {
                total = 1;  // type 1: IEI in bits 8-5, value in bits 4-1
            } else {
                total = d != nullptr ? d->min_len : 1;
            }
            break;
        case Format::tlv:
            if (pos + 2 > in.size()) {
                return err(Errc::truncated, pos, "NAS: TLV IE without its length");
            }
            hdr = 2;
            total = 2 + in[pos + 1];
            break;
        case Format::tlv_e:
            if (pos + 3 > in.size()) {
                return err(Errc::truncated, pos, "NAS: TLV-E IE without its length");
            }
            hdr = 3;
            total = 3 + ((std::size_t{in[pos + 1]} << 8) | in[pos + 2]);
            break;
        default:
            return err(Errc::internal, pos, "NAS: an imperative format in the non-imperative part");
        }
        if (pos + total > in.size()) {
            return err(Errc::truncated, pos, "NAS: optional IE runs past the end");
        }
        if (d == nullptr) {
            if (comprehension_required(octet, f)) {
                return err(Errc::malformed, pos, "NAS: unknown IE encoded as comprehension required");
            }
            ie.raw.assign(in.begin() + static_cast<std::ptrdiff_t>(pos),
                          in.begin() + static_cast<std::ptrdiff_t>(pos + total));
        } else {
            ie.desc = d;
            if (d->iei_kind == IeiKind::half) {
                ie.value.push_back(static_cast<std::uint8_t>(octet & 0x0F));
            } else if (total > hdr) {
                ie.value.assign(in.begin() + static_cast<std::ptrdiff_t>(pos + hdr),
                                in.begin() + static_cast<std::ptrdiff_t>(pos + total));
            }
            ie.out_of_range = d->iei_kind != IeiKind::half && !length_ok(*d, total);
            for (const Ie& seen : m.ies) {
                if (seen.desc == d) {
                    ie.repeated = true;
                    break;
                }
            }
        }
        pos += total;
        m.ies.push_back(std::move(ie));
    }
    // Every mandatory IE of the table is in the imperative part, so it is present here.
    return m;
}

Result<Bytes> encode(const Message& m) {
    if (m.desc == nullptr) {
        return err(Errc::invalid_argument, 0, "NAS: no message descriptor");
    }
    ByteWriter w(64);
    bool high_nibble = false;
    std::uint8_t pending = 0;
    for (const Ie& ie : m.ies) {
        if (ie.desc == nullptr) {
            w.bytes(ie.raw);
            continue;
        }
        const IeDesc& d = *ie.desc;
        if (d.iei_kind == IeiKind::none && d.half_octet()) {
            const std::uint8_t v = ie.value.empty() ? 0 : static_cast<std::uint8_t>(ie.value[0] & 0x0F);
            if (!high_nibble) {
                pending = v;
            } else {
                w.u8(static_cast<std::uint8_t>(pending | (v << 4)));
            }
            high_nibble = !high_nibble;
            continue;
        }
        if (high_nibble) {
            return err(Errc::invalid_argument, w.size(), "NAS: a half-octet IE without its pair");
        }
        switch (d.format) {
        case Format::v:
            w.bytes(ie.value);
            break;
        case Format::lv:
            if (ie.value.size() > 0xFF) {
                return err(Errc::overflow, w.size(), "NAS: LV value over 255 octets");
            }
            w.u8(static_cast<std::uint8_t>(ie.value.size()));
            w.bytes(ie.value);
            break;
        case Format::lv_e:
            if (ie.value.size() > 0xFFFF) {
                return err(Errc::overflow, w.size(), "NAS: LV-E value over 65535 octets");
            }
            w.u16(static_cast<std::uint16_t>(ie.value.size()));
            w.bytes(ie.value);
            break;
        case Format::t:
            w.u8(d.iei);
            break;
        case Format::tv:
            if (d.iei_kind == IeiKind::half) {
                const std::uint8_t v = ie.value.empty() ? 0 : static_cast<std::uint8_t>(ie.value[0] & 0x0F);
                w.u8(static_cast<std::uint8_t>((d.iei << 4) | v));
            } else {
                w.u8(ie.iei != 0 ? ie.iei : d.iei);
                w.bytes(ie.value);
            }
            break;
        case Format::tlv:
            if (ie.value.size() > 0xFF) {
                return err(Errc::overflow, w.size(), "NAS: TLV value over 255 octets");
            }
            w.u8(ie.iei != 0 ? ie.iei : d.iei);
            w.u8(static_cast<std::uint8_t>(ie.value.size()));
            w.bytes(ie.value);
            break;
        case Format::tlv_e:
            if (ie.value.size() > 0xFFFF) {
                return err(Errc::overflow, w.size(), "NAS: TLV-E value over 65535 octets");
            }
            w.u8(ie.iei != 0 ? ie.iei : d.iei);
            w.u16(static_cast<std::uint16_t>(ie.value.size()));
            w.bytes(ie.value);
            break;
        }
    }
    if (high_nibble) {
        return err(Errc::invalid_argument, w.size(), "NAS: an odd number of half-octet IEs");
    }
    return std::move(w).take();
}

bool is_protected(ByteView in) noexcept {
    return in.size() >= 2 && in[0] == static_cast<std::uint8_t>(Epd::mm) && (in[1] & 0x0F) != 0;
}

Result<Protected> decode_protected(ByteView in) {
    if (!is_protected(in)) {
        return err(Errc::invalid_argument, 0, "NAS: not a security protected 5GMM message");
    }
    if (in.size() < 7) {
        return err(Errc::truncated, 0, "NAS: security protected header is 7 octets");
    }
    if ((in[1] & 0x0F) > 4) {
        return err(Errc::malformed, 1, "NAS: reserved security header type");
    }
    Protected p;
    p.security_header_type = static_cast<std::uint8_t>(in[1] & 0x0F);
    p.mac = (std::uint32_t{in[2]} << 24) | (std::uint32_t{in[3]} << 16) | (std::uint32_t{in[4]} << 8) | in[5];
    p.sequence_number = in[6];
    p.payload.assign(in.begin() + 7, in.end());
    return p;
}

Bytes encode_protected(const Protected& p) {
    ByteWriter w(7 + p.payload.size());
    w.u8(static_cast<std::uint8_t>(Epd::mm));
    w.u8(static_cast<std::uint8_t>(p.security_header_type & 0x0F));
    w.u32(p.mac);
    w.u8(p.sequence_number);
    w.bytes(p.payload);
    return std::move(w).take();
}

const EpcoDesc* find_epco(std::uint16_t id, Direction dir) noexcept {
    for (const EpcoDesc& d : epco_containers()) {
        if (d.id == id && d.direction == dir) {
            return &d;
        }
    }
    return nullptr;
}

namespace {
bool long_length(std::uint16_t id, Direction dir) {
    const EpcoDesc* d = find_epco(id, dir);
    return d != nullptr && d->length_octets == 2;
}
} // namespace

Result<Epco> decode_epco(ByteView in, Direction dir) {
    if (in.empty()) {
        return err(Errc::truncated, 0, "ePCO: no configuration protocol octet");
    }
    Epco e;
    e.octet3 = in[0];
    std::size_t pos = 1;
    while (pos < in.size()) {
        if (pos + 3 > in.size()) {
            return err(Errc::truncated, pos, "ePCO: a unit without its identifier and length");
        }
        EpcoUnit u;
        u.offset = pos;
        u.id = static_cast<std::uint16_t>((in[pos] << 8) | in[pos + 1]);
        std::size_t len = in[pos + 2];
        std::size_t hdr = 3;
        if (long_length(u.id, dir)) {
            if (pos + 4 > in.size()) {
                return err(Errc::truncated, pos, "ePCO: a two-octet length cut short");
            }
            len = (len << 8) | in[pos + 3];
            hdr = 4;
        }
        if (pos + hdr + len > in.size()) {
            return err(Errc::truncated, pos, "ePCO: unit contents run past the end");
        }
        u.contents.assign(in.begin() + static_cast<std::ptrdiff_t>(pos + hdr),
                          in.begin() + static_cast<std::ptrdiff_t>(pos + hdr + len));
        pos += hdr + len;
        e.units.push_back(std::move(u));
    }
    return e;
}

Result<Bytes> encode_epco(const Epco& e, Direction dir) {
    ByteWriter w(16);
    w.u8(e.octet3);
    for (const EpcoUnit& u : e.units) {
        w.u16(u.id);
        if (long_length(u.id, dir)) {
            if (u.contents.size() > 0xFFFF) {
                return err(Errc::overflow, w.size(), "ePCO: contents over 65535 octets");
            }
            w.u16(static_cast<std::uint16_t>(u.contents.size()));
        } else {
            if (u.contents.size() > 0xFF) {
                return err(Errc::overflow, w.size(), "ePCO: contents over 255 octets with a one-octet length");
            }
            w.u8(static_cast<std::uint8_t>(u.contents.size()));
        }
        w.bytes(u.contents);
    }
    return std::move(w).take();
}

namespace {
std::string json_text(std::string_view s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += static_cast<unsigned char>(c) < 0x20 ? ' ' : c;
    }
    return out;
}
} // namespace

std::string to_json(const Message& m) {
    std::string out = "{\"message\":\"";
    out += json_text(m.desc != nullptr ? m.desc->name : "?");
    out += "\",\"ies\":[";
    bool first = true;
    for (const Ie& ie : m.ies) {
        out += first ? "" : ",";
        first = false;
        if (ie.desc == nullptr) {
            out += "{\"unknown\":\"" + to_hex(ie.raw) + "\",\"at\":" + std::to_string(ie.offset) + "}";
            continue;
        }
        out += "{\"ie\":\"";
        out += json_text(ie.desc->name);
        out += "\",\"iei\":" + std::to_string(ie.iei) + ",\"value\":\"" + to_hex(ie.value) + "\"";
        out += ",\"at\":" + std::to_string(ie.offset);
        if (std::string_view(ie.desc->reference) == "9.11.4.6" && m.desc->direction != Direction::both) {
            // the units, offsets in the message: IEI, two length octets, octet 3
            auto e = decode_epco(ie.value, m.desc->direction);
            if (!e) {
                out += ",\"epco_error\":\"" + json_text(e.error().what) + "\"";
            } else {
                out += ",\"epco\":[";
                for (std::size_t k = 0; k < e->units.size(); ++k) {
                    const EpcoUnit& u = e->units[k];
                    out += (k != 0 ? "," : "") + std::string("{\"id\":") + std::to_string(u.id) +
                           ",\"at\":" + std::to_string(ie.offset + 3 + u.offset) +
                           ",\"len\":" + std::to_string(u.contents.size()) + "}";
                }
                out += "]";
            }
        }
        out += ie.desc->half_octet() ? ",\"half\":true" : "";
        out += ie.repeated ? ",\"repeated\":true" : "";
        out += ie.out_of_range ? ",\"out_of_range\":true" : "";
        out += "}";
    }
    out += "]}";
    return out;
}

} // namespace ksim::nas
