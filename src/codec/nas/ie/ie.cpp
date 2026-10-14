// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Clause references are to 3GPP TS 24.501 j80 unless stated otherwise.

#include "codec/nas/ie/ie.hpp"

#include <algorithm>

namespace ksim::nas::ie {

namespace {

Error bad(const char* what) { return make_error(Errc::malformed, 0, what); }
Error range(const char* what) { return make_error(Errc::out_of_range, 0, what); }

Result<std::uint8_t> one(ByteView v, const char* what) {
    if (v.size() != 1) {
        return bad(what);
    }
    return v[0];
}

char digit(std::uint8_t n) { return static_cast<char>('0' + n); }
bool is_digit(std::uint8_t n) { return n <= 9; }

std::uint32_t be24(ByteView b) { return (std::uint32_t{b[0]} << 16) | (std::uint32_t{b[1]} << 8) | b[2]; }
void put24(Bytes& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

/// Packet filter component value lengths (Table 9.11.4.13.1); -1 variable.
int component_length(std::uint8_t type) {
    switch (type) {
    case 0x01: return 0;
    case 0x10: case 0x11: return 8;
    case 0x21: case 0x23: return 17;
    case 0x30: case 0x85: case 0x86: case 0x8A: case 0x8B: return 1;
    case 0x40: case 0x50: case 0x70: case 0x83: case 0x84: case 0x87: return 2;
    case 0x80: return 3;
    case 0x41: case 0x51: case 0x60: return 4;
    case 0x81: case 0x82: return 6;
    case 0x88: case 0x89: return 12;
    default: return -1;   // (S)RTP multiplexed media identification (0x91) and reserved values
    }
}

} // namespace

// ---- shared ---------------------------------------------------------------------

Result<Plmn> Plmn::decode(ByteView b) {
    if (b.size() != 3) {
        return bad("plmn: three octets");
    }
    const std::uint8_t m1 = b[0] & 0x0F, m2 = b[0] >> 4, m3 = b[1] & 0x0F;
    const std::uint8_t n3 = b[1] >> 4, n1 = b[2] & 0x0F, n2 = b[2] >> 4;
    if (!is_digit(m1) || !is_digit(m2) || !is_digit(m3) || !is_digit(n1) || !is_digit(n2) || (n3 != 0x0F && !is_digit(n3))) {
        return bad("plmn: a digit is not BCD");
    }
    Plmn p;
    p.mcc = {digit(m1), digit(m2), digit(m3)};
    p.mnc = {digit(n1), digit(n2)};
    if (n3 != 0x0F) {
        p.mnc += digit(n3);
    }
    return p;
}

Bytes Plmn::encode() const {
    const auto d = [](const std::string& s, std::size_t i) { return static_cast<std::uint8_t>(i < s.size() ? s[i] - '0' : 0x0F); };
    return {static_cast<std::uint8_t>(d(mcc, 0) | (d(mcc, 1) << 4)), static_cast<std::uint8_t>(d(mcc, 2) | (d(mnc, 2) << 4)),
            static_cast<std::uint8_t>(d(mnc, 0) | (d(mnc, 1) << 4))};
}

// ---- 9.11.2 ---------------------------------------------------------------------------

TimerMs GprsTimer::ms() const noexcept {
    switch (unit) {
    case 0: return std::int64_t{value} * 2'000;
    case 1: return std::int64_t{value} * 60'000;
    case 2: return std::int64_t{value} * 360'000;
    case 7: return std::nullopt;
    default: return std::int64_t{value} * 60'000;   // other units read as 1 minute (TS 24.008 Table 10.5.172)
    }
}

Result<GprsTimer> GprsTimer::decode(ByteView v) {
    auto o = one(v, "gprs timer: one octet");
    if (!o) {
        return o.error();
    }
    return GprsTimer{static_cast<std::uint8_t>(*o >> 5), static_cast<std::uint8_t>(*o & 0x1F)};
}

Bytes GprsTimer::encode() const { return {static_cast<std::uint8_t>((unit << 5) | (value & 0x1F))}; }

Result<GprsTimer2> GprsTimer2::decode(ByteView v) {
    auto t = GprsTimer::decode(v);
    if (!t) {
        return t.error();
    }
    return GprsTimer2{*t};
}

TimerMs GprsTimer3::ms() const noexcept {
    const std::int64_t n = value;
    switch (unit) {
    case 0: return n * 600'000;
    case 1: return n * 3'600'000;
    case 2: return n * 36'000'000;
    case 3: return n * 2'000;
    case 4: return n * 30'000;
    case 5: return n * 60'000;
    case 6: return n * 1'152'000'000;
    default: return std::nullopt;   // 7: deactivated
    }
}

Result<GprsTimer3> GprsTimer3::decode(ByteView v) {
    auto o = one(v, "gprs timer 3: one octet");
    if (!o) {
        return o.error();
    }
    return GprsTimer3{static_cast<std::uint8_t>(*o >> 5), static_cast<std::uint8_t>(*o & 0x1F)};
}

Bytes GprsTimer3::encode() const { return {static_cast<std::uint8_t>((unit << 5) | (value & 0x1F))}; }

Result<Snssai> Snssai::decode(ByteView v) {
    Snssai s;
    switch (v.size()) {
    case 1:
        s.sst = v[0];
        break;
    case 2:
        s.sst = v[0];
        s.mapped_sst = v[1];
        break;
    case 4:
        s.sst = v[0];
        s.sd = be24(v.subspan(1));
        break;
    case 5:
        s.sst = v[0];
        s.sd = be24(v.subspan(1));
        s.mapped_sst = v[4];
        break;
    case 8:
        s.sst = v[0];
        s.sd = be24(v.subspan(1));
        s.mapped_sst = v[4];
        s.mapped_sd = be24(v.subspan(5));
        break;
    default:
        return bad("s-nssai: the contents are 1, 2, 4, 5 or 8 octets");
    }
    return s;
}

Bytes Snssai::encode() const {
    Bytes out{sst};
    if (sd) {
        put24(out, *sd);
    }
    if (mapped_sst) {
        out.push_back(*mapped_sst);
        if (mapped_sd && sd) {
            put24(out, *mapped_sd);
        }
    }
    return out;
}

Result<Dnn> Dnn::decode(ByteView v) {
    if (v.empty() || v.size() > 100) {
        return bad("dnn: 1 to 100 octets (TS 23.003 9.1)");
    }
    Dnn d;
    std::size_t at = 0;
    while (at < v.size()) {
        const std::size_t n = v[at++];
        if (n == 0 || n > 63 || at + n > v.size()) {
            return bad("dnn: a label is 1 to 63 octets within the value");
        }
        if (std::find(v.begin() + static_cast<std::ptrdiff_t>(at), v.begin() + static_cast<std::ptrdiff_t>(at + n), '.') !=
            v.begin() + static_cast<std::ptrdiff_t>(at + n)) {
            return bad("dnn: a label holds a '.'");
        }
        if (!d.name.empty()) {
            d.name += '.';
        }
        d.name.append(reinterpret_cast<const char*>(v.data() + at), n);
        at += n;
    }
    return d;
}

Result<Bytes> Dnn::encode() const {
    Bytes out;
    std::size_t start = 0;
    while (start <= name.size()) {
        const auto dot = name.find('.', start);
        const std::size_t end = dot == std::string::npos ? name.size() : dot;
        if (end == start || end - start > 63) {
            return range("dnn: a label is 1 to 63 characters");
        }
        out.push_back(static_cast<std::uint8_t>(end - start));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start), name.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    return out;
}

Result<AccessType> AccessType::decode(ByteView v) {
    auto o = one(v, "access type: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t a = *o & 0x03;
    if (a == 0 || a == 3) {
        return range("access type: 1 or 2");
    }
    return AccessType{a};
}

Result<EapMessage> EapMessage::decode(ByteView v) {
    if (v.size() < 4) {
        return bad("eap message: shorter than an EAP header");
    }
    return EapMessage{Bytes(v.begin(), v.end())};
}

// ---- 9.11.3 ---------------------------------------------------------------------------

Result<FiveGmmCapability> FiveGmmCapability::decode(ByteView v) {
    if (v.empty() || v.size() > 13) {
        return bad("5gmm capability: 1 to 13 octets");
    }
    return FiveGmmCapability{Bytes(v.begin(), v.end())};
}

Result<Cause> Cause::decode(ByteView v) {
    auto o = one(v, "cause: one octet");
    if (!o) {
        return o.error();
    }
    return Cause{*o};
}

Result<IdentityType> IdentityType::decode(ByteView v) {
    auto o = one(v, "5gs identity type: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t t = *o & 0x07;
    if (t == 0) {
        return range("5gs identity type: 0 is reserved");
    }
    return IdentityType{t};
}

std::string MobileIdentity::null_scheme_msin() const {
    if (type != Type::suci || protection_scheme != 0) {
        return {};
    }
    std::string out;
    for (std::uint8_t b : scheme_output) {
        out += digit(b & 0x0F);
        if ((b >> 4) != 0x0F) {
            out += digit(b >> 4);
        }
    }
    return out;
}

MobileIdentity MobileIdentity::null_suci(const Plmn& plmn, std::string_view msin, std::string_view ri) {
    MobileIdentity m;
    m.type = Type::suci;
    m.plmn = plmn;
    m.routing_indicator = std::string(ri);
    m.protection_scheme = 0;
    m.hn_key_id = 0;
    for (std::size_t i = 0; i < msin.size(); i += 2) {
        const auto lo = static_cast<std::uint8_t>(msin[i] - '0');
        const auto hi = static_cast<std::uint8_t>(i + 1 < msin.size() ? msin[i + 1] - '0' : 0x0F);
        m.scheme_output.push_back(static_cast<std::uint8_t>(lo | (hi << 4)));
    }
    return m;
}

Result<MobileIdentity> MobileIdentity::decode(ByteView v) {
    if (v.empty()) {
        return bad("5gs mobile identity: empty");
    }
    MobileIdentity m;
    const std::uint8_t t = v[0] & 0x07;
    switch (t) {
    case 0:
        m.type = Type::none;
        return m;
    case 1: {   // SUCI
        m.type = Type::suci;
        m.supi_format = (v[0] >> 4) & 0x07;
        if (m.supi_format != 0) {
            return make_error(Errc::unsupported, 0, "5gs mobile identity: a SUCI NAI (P1 reads the IMSI format)");
        }
        if (v.size() < 8) {
            return bad("5gs mobile identity: a SUCI is at least 8 octets");
        }
        auto p = Plmn::decode(v.subspan(1, 3));
        if (!p) {
            return p.error();
        }
        m.plmn = *p;
        m.routing_indicator.clear();
        for (std::uint8_t b : {v[4], v[5]}) {
            for (std::uint8_t n : {static_cast<std::uint8_t>(b & 0x0F), static_cast<std::uint8_t>(b >> 4)}) {
                if (n == 0x0F) {
                    continue;
                }
                if (!is_digit(n)) {
                    return bad("5gs mobile identity: the routing indicator is not BCD");
                }
                m.routing_indicator += digit(n);
            }
        }
        if (m.routing_indicator.empty()) {
            m.routing_indicator = "0";
        }
        m.protection_scheme = v[6] & 0x0F;
        m.hn_key_id = v[7];
        m.scheme_output.assign(v.begin() + 8, v.end());
        return m;
    }
    case 2:   // 5G-GUTI
        if (v.size() != 11) {
            return bad("5gs mobile identity: a 5G-GUTI is 11 octets");
        }
        {
            auto p = Plmn::decode(v.subspan(1, 3));
            if (!p) {
                return p.error();
            }
            m.type = Type::guti;
            m.plmn = *p;
            m.amf_region = v[4];
            m.amf_set = static_cast<std::uint16_t>((v[5] << 2) | (v[6] >> 6));
            m.amf_pointer = v[6] & 0x3F;
            m.tmsi = (std::uint32_t{v[7]} << 24) | (std::uint32_t{v[8]} << 16) | (std::uint32_t{v[9]} << 8) | v[10];
        }
        return m;
    case 3:   // IMEI
    case 5: { // IMEISV
        m.type = t == 3 ? Type::imei : Type::imeisv;
        const bool odd = (v[0] & 0x08) != 0;
        m.digits += digit(v[0] >> 4);
        for (std::size_t i = 1; i < v.size(); ++i) {
            m.digits += digit(v[i] & 0x0F);
            const std::uint8_t hi = v[i] >> 4;
            if (i + 1 == v.size() && !odd) {
                if (hi != 0x0F) {
                    return bad("5gs mobile identity: an even count ends with 'F'");
                }
                break;
            }
            m.digits += digit(hi);
        }
        if (!std::all_of(m.digits.begin(), m.digits.end(), [](char c) { return c >= '0' && c <= '9'; })) {
            return bad("5gs mobile identity: IMEI digits are BCD");
        }
        return m;
    }
    case 4:   // 5G-S-TMSI
        if (v.size() != 7) {
            return bad("5gs mobile identity: a 5G-S-TMSI is 7 octets");
        }
        m.type = Type::s_tmsi;
        m.amf_set = static_cast<std::uint16_t>((v[1] << 2) | (v[2] >> 6));
        m.amf_pointer = v[2] & 0x3F;
        m.tmsi = (std::uint32_t{v[3]} << 24) | (std::uint32_t{v[4]} << 16) | (std::uint32_t{v[5]} << 8) | v[6];
        return m;
    default:
        return make_error(Errc::unsupported, 0, "5gs mobile identity: MAC address and EUI-64 are not P1's");
    }
}

Result<Bytes> MobileIdentity::encode() const {
    Bytes out;
    switch (type) {
    case Type::none:
        return Bytes{0x00};
    case Type::suci: {
        out.push_back(static_cast<std::uint8_t>(((supi_format & 0x07) << 4) | 0x01));
        const Bytes p = plmn.encode();
        out.insert(out.end(), p.begin(), p.end());
        std::string ri = routing_indicator;
        if (ri.empty() || ri.size() > 4) {
            return range("5gs mobile identity: a routing indicator is 1 to 4 digits");
        }
        while (ri.size() < 4) {
            ri += 'F';
        }
        const auto n = [](char c) { return static_cast<std::uint8_t>(c == 'F' ? 0x0F : c - '0'); };
        out.push_back(static_cast<std::uint8_t>(n(ri[0]) | (n(ri[1]) << 4)));
        out.push_back(static_cast<std::uint8_t>(n(ri[2]) | (n(ri[3]) << 4)));
        out.push_back(protection_scheme & 0x0F);
        out.push_back(hn_key_id);
        out.insert(out.end(), scheme_output.begin(), scheme_output.end());
        return out;
    }
    case Type::guti: {
        out.push_back(0xF2);
        const Bytes p = plmn.encode();
        out.insert(out.end(), p.begin(), p.end());
        out.push_back(amf_region);
        out.push_back(static_cast<std::uint8_t>(amf_set >> 2));
        out.push_back(static_cast<std::uint8_t>(((amf_set & 0x03) << 6) | (amf_pointer & 0x3F)));
        for (int s = 24; s >= 0; s -= 8) {
            out.push_back(static_cast<std::uint8_t>((tmsi >> s) & 0xFF));
        }
        return out;
    }
    case Type::s_tmsi:
        out.push_back(0xF4);
        out.push_back(static_cast<std::uint8_t>(amf_set >> 2));
        out.push_back(static_cast<std::uint8_t>(((amf_set & 0x03) << 6) | (amf_pointer & 0x3F)));
        for (int s = 24; s >= 0; s -= 8) {
            out.push_back(static_cast<std::uint8_t>((tmsi >> s) & 0xFF));
        }
        return out;
    case Type::imei:
    case Type::imeisv: {
        if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](char c) { return c >= '0' && c <= '9'; })) {
            return range("5gs mobile identity: IMEI digits");
        }
        const bool odd = digits.size() % 2 == 1;
        out.push_back(static_cast<std::uint8_t>(((digits[0] - '0') << 4) | (odd ? 0x08 : 0x00) | (type == Type::imei ? 3 : 5)));
        for (std::size_t i = 1; i < digits.size(); i += 2) {
            const auto lo = static_cast<std::uint8_t>(digits[i] - '0');
            const auto hi = static_cast<std::uint8_t>(i + 1 < digits.size() ? digits[i + 1] - '0' : 0x0F);
            out.push_back(static_cast<std::uint8_t>(lo | (hi << 4)));
        }
        return out;
    }
    }
    return range("5gs mobile identity: unknown type");
}

Result<NetworkFeatureSupport> NetworkFeatureSupport::decode(ByteView v) {
    if (v.empty() || v.size() > 3) {
        return bad("5gs network feature support: 1 to 3 octets");
    }
    return NetworkFeatureSupport{Bytes(v.begin(), v.end())};
}

Result<RegistrationResult> RegistrationResult::decode(ByteView v) {
    auto o = one(v, "5gs registration result: one octet");
    if (!o) {
        return o.error();
    }
    RegistrationResult r;
    const std::uint8_t a = *o & 0x07;
    r.access = a == 2 || a == 3 ? a : 1;   // all other values read as 3GPP access
    r.sms_allowed = (*o & 0x08) != 0;
    r.nssaa_to_be_performed = (*o & 0x10) != 0;
    r.emergency_registered = (*o & 0x20) != 0;
    r.disaster_roaming = (*o & 0x40) != 0;
    return r;
}

Bytes RegistrationResult::encode() const {
    return {static_cast<std::uint8_t>((access & 0x07) | (sms_allowed ? 0x08 : 0) | (nssaa_to_be_performed ? 0x10 : 0) |
                                      (emergency_registered ? 0x20 : 0) | (disaster_roaming ? 0x40 : 0))};
}

Result<RegistrationType> RegistrationType::decode(ByteView v) {
    auto o = one(v, "5gs registration type: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t t = *o & 0x07;
    if (t == 0 || t == 6 || t == 7) {
        return range("5gs registration type: a reserved value");
    }
    return RegistrationType{t, (*o & 0x08) != 0};
}

Bytes RegistrationType::encode() const {
    return {static_cast<std::uint8_t>((value & 0x07) | (follow_on_request ? 0x08 : 0))};
}

Result<TaiIe> TaiIe::decode(ByteView v) {
    if (v.size() != 6) {
        return bad("5gs tracking area identity: six octets");
    }
    auto p = Plmn::decode(v.first(3));
    if (!p) {
        return p.error();
    }
    return TaiIe{Tai{*p, be24(v.subspan(3))}};
}

Bytes TaiIe::encode() const {
    Bytes out = tai.plmn.encode();
    put24(out, tai.tac);
    return out;
}

bool TaiList::contains(const Tai& t) const { return std::find(tais.begin(), tais.end(), t) != tais.end(); }

Result<TaiList> TaiList::decode(ByteView v) {
    if (v.empty()) {
        return bad("5gs tracking area identity list: empty");
    }
    TaiList l;
    std::size_t at = 0;
    while (at < v.size()) {
        const std::uint8_t head = v[at++];
        const unsigned type = (head >> 5) & 0x03;
        const unsigned n = (head & 0x1F) + 1U;
        if (n > 16) {
            return bad("5gs tracking area identity list: more than 16 elements in a partial list");
        }
        if (type == 0 || type == 1) {
            const std::size_t need = 3 + (type == 0 ? 3 * n : 3);
            if (at + need > v.size()) {
                return bad("5gs tracking area identity list: a partial list overruns the value");
            }
            auto p = Plmn::decode(v.subspan(at, 3));
            if (!p) {
                return p.error();
            }
            at += 3;
            if (type == 0) {
                for (unsigned i = 0; i < n; ++i, at += 3) {
                    l.tais.push_back(Tai{*p, be24(v.subspan(at))});
                }
            } else {
                const std::uint32_t first = be24(v.subspan(at));
                at += 3;
                for (unsigned i = 0; i < n; ++i) {
                    l.tais.push_back(Tai{*p, (first + i) & 0xFFFFFF});
                }
            }
        } else if (type == 2) {
            if (at + std::size_t{6} * n > v.size()) {
                return bad("5gs tracking area identity list: a partial list overruns the value");
            }
            for (unsigned i = 0; i < n; ++i, at += 6) {
                auto p = Plmn::decode(v.subspan(at, 3));
                if (!p) {
                    return p.error();
                }
                l.tais.push_back(Tai{*p, be24(v.subspan(at + 3))});
            }
        } else {
            return range("5gs tracking area identity list: type of list 11 is reserved");
        }
    }
    return l;
}

Result<Bytes> TaiList::encode() const {
    if (tais.empty()) {
        return range("5gs tracking area identity list: at least one TAI");
    }
    Bytes out;
    std::vector<bool> done(tais.size(), false);
    for (std::size_t i = 0; i < tais.size(); ++i) {
        if (done[i]) {
            continue;
        }
        std::vector<std::uint32_t> tacs;
        for (std::size_t j = i; j < tais.size() && tacs.size() < 16; ++j) {
            if (!done[j] && tais[j].plmn == tais[i].plmn) {
                tacs.push_back(tais[j].tac);
                done[j] = true;
            }
        }
        out.push_back(static_cast<std::uint8_t>(tacs.size() - 1));   // type 00
        const Bytes p = tais[i].plmn.encode();
        out.insert(out.end(), p.begin(), p.end());
        for (std::uint32_t t : tacs) {
            put24(out, t);
        }
    }
    return out;
}

Result<UpdateType> UpdateType::decode(ByteView v) {
    auto o = one(v, "5gs update type: one octet");
    if (!o) {
        return o.error();
    }
    return UpdateType{(*o & 0x01) != 0, (*o & 0x02) != 0, static_cast<std::uint8_t>((*o >> 2) & 0x03),
                      static_cast<std::uint8_t>((*o >> 4) & 0x03)};
}

Bytes UpdateType::encode() const {
    return {static_cast<std::uint8_t>((sms_requested ? 0x01 : 0) | (ng_ran_rcu ? 0x02 : 0) | ((pnb_ciot_5gs & 0x03) << 2) |
                                      ((pnb_ciot_eps & 0x03) << 4))};
}

Result<Abba> Abba::decode(ByteView v) {
    if (v.size() < 2) {
        return bad("abba: two octets or more");
    }
    return Abba{Bytes(v.begin(), v.end())};
}

Result<Additional5gSecurityInformation> Additional5gSecurityInformation::decode(ByteView v) {
    auto o = one(v, "additional 5g security information: one octet");
    if (!o) {
        return o.error();
    }
    return Additional5gSecurityInformation{(*o & 0x02) != 0, (*o & 0x01) != 0};
}

Bytes Additional5gSecurityInformation::encode() const {
    return {static_cast<std::uint8_t>((rinmr ? 0x02 : 0) | (hdp ? 0x01 : 0))};
}

void PsiBitmap::set(unsigned psi, bool on) noexcept {
    if (psi < 16) {
        psis = static_cast<std::uint16_t>(on ? (psis | (1U << psi)) : (psis & ~(1U << psi)));
    }
}

Result<PsiBitmap> PsiBitmap::decode(ByteView v) {
    if (v.size() < 2 || v.size() > 32) {
        return bad("psi bitmap: 2 to 32 octets");
    }
    // Octet 3 bit 1 is PSI 0 (spare), bit 8 PSI 7; octet 4 bit 1 PSI 8 … bit 8 PSI 15.
    return PsiBitmap{static_cast<std::uint16_t>(v[0] | (v[1] << 8))};
}

Bytes PsiBitmap::encode() const {
    return {static_cast<std::uint8_t>(psis & 0xFE), static_cast<std::uint8_t>(psis >> 8)};   // PSI 0 is spare
}

Result<ReactivationErrorCause> ReactivationErrorCause::decode(ByteView v) {
    if (v.size() % 2 != 0 || v.empty()) {
        return bad("pdu session reactivation result error cause: (PSI, cause) pairs");
    }
    ReactivationErrorCause r;
    for (std::size_t i = 0; i < v.size(); i += 2) {
        r.entries.emplace_back(v[i], v[i + 1]);
    }
    return r;
}

Bytes ReactivationErrorCause::encode() const {
    Bytes out;
    for (const auto& [psi, cause] : entries) {
        out.push_back(psi);
        out.push_back(cause);
    }
    return out;
}

Result<AuthenticationFailureParameter> AuthenticationFailureParameter::decode(ByteView v) {
    if (v.size() != 14) {
        return bad("authentication failure parameter: AUTS is 14 octets");
    }
    return AuthenticationFailureParameter{Bytes(v.begin(), v.end())};
}

Result<Autn> Autn::decode(ByteView v) {
    if (v.size() != 16) {
        return bad("authentication parameter autn: 16 octets");
    }
    return Autn{Bytes(v.begin(), v.end())};
}

Result<Rand> Rand::decode(ByteView v) {
    if (v.size() != 16) {
        return bad("authentication parameter rand: 16 octets");
    }
    return Rand{Bytes(v.begin(), v.end())};
}

Result<AuthenticationResponseParameter> AuthenticationResponseParameter::decode(ByteView v) {
    if (v.size() != 16) {
        return bad("authentication response parameter: RES* is 16 octets");
    }
    return AuthenticationResponseParameter{Bytes(v.begin(), v.end())};
}

Result<ConfigurationUpdateIndication> ConfigurationUpdateIndication::decode(ByteView v) {
    auto o = one(v, "configuration update indication: one value");
    if (!o) {
        return o.error();
    }
    return ConfigurationUpdateIndication{(*o & 0x01) != 0, (*o & 0x02) != 0};
}

Bytes ConfigurationUpdateIndication::encode() const {
    return {static_cast<std::uint8_t>((ack_requested ? 0x01 : 0) | (registration_requested ? 0x02 : 0))};
}

Result<DeregistrationType> DeregistrationType::decode(ByteView v) {
    auto o = one(v, "de-registration type: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t a = *o & 0x03;
    if (a == 0) {
        return range("de-registration type: access type 00 is reserved");
    }
    return DeregistrationType{(*o & 0x08) != 0, (*o & 0x04) != 0, a};
}

Bytes DeregistrationType::encode() const {
    return {static_cast<std::uint8_t>((switch_off ? 0x08 : 0) | (reregistration_required ? 0x04 : 0) | (access & 0x03))};
}

Result<ImeisvRequest> ImeisvRequest::decode(ByteView v) {
    auto o = one(v, "imeisv request: one value");
    if (!o) {
        return o.error();
    }
    return ImeisvRequest{(*o & 0x07) == 1};   // other values read as "not requested"
}

Result<MicoIndication> MicoIndication::decode(ByteView v) {
    auto o = one(v, "mico indication: one value");
    if (!o) {
        return o.error();
    }
    return MicoIndication{(*o & 0x01) != 0, (*o & 0x02) != 0};
}

Bytes MicoIndication::encode() const { return {static_cast<std::uint8_t>((raai ? 0x01 : 0) | (sprti ? 0x02 : 0))}; }

Result<NgKsi> NgKsi::decode(ByteView v) {
    auto o = one(v, "ngksi: one value");
    if (!o) {
        return o.error();
    }
    return NgKsi{(*o & 0x08) != 0, static_cast<std::uint8_t>(*o & 0x07)};
}

Bytes NgKsi::encode() const { return {static_cast<std::uint8_t>((mapped ? 0x08 : 0) | (value & 0x07))}; }

Result<NasMessageContainer> NasMessageContainer::decode(ByteView v) {
    if (v.empty()) {
        return bad("nas message container: empty");
    }
    return NasMessageContainer{Bytes(v.begin(), v.end())};
}

Result<NasSecurityAlgorithms> NasSecurityAlgorithms::decode(ByteView v) {
    auto o = one(v, "nas security algorithms: one octet");
    if (!o) {
        return o.error();
    }
    const std::uint8_t c = *o >> 4;
    const std::uint8_t i = *o & 0x0F;
    if (c > 7 || i > 7) {
        return range("nas security algorithms: values above 7 are not defined");
    }
    return NasSecurityAlgorithms{c, i};
}

Result<NetworkSlicingIndication> NetworkSlicingIndication::decode(ByteView v) {
    auto o = one(v, "network slicing indication: one value");
    if (!o) {
        return o.error();
    }
    return NetworkSlicingIndication{(*o & 0x01) != 0, (*o & 0x02) != 0};
}

Bytes NetworkSlicingIndication::encode() const { return {static_cast<std::uint8_t>((nssci ? 0x01 : 0) | (dcni ? 0x02 : 0))}; }

Result<Nssai> Nssai::decode(ByteView v) {
    if (v.empty()) {
        return bad("nssai: empty");
    }
    Nssai n;
    std::size_t at = 0;
    while (at < v.size()) {
        const std::size_t len = v[at++];
        if (at + len > v.size()) {
            return bad("nssai: an S-NSSAI overruns the value");
        }
        auto s = Snssai::decode(v.subspan(at, len));
        if (!s) {
            return s.error();
        }
        n.list.push_back(*s);
        at += len;
    }
    return n;
}

Result<Bytes> Nssai::encode() const {
    if (list.empty()) {
        return range("nssai: at least one S-NSSAI");
    }
    Bytes out;
    for (const auto& s : list) {
        const Bytes b = s.encode();
        out.push_back(static_cast<std::uint8_t>(b.size()));
        out.insert(out.end(), b.begin(), b.end());
    }
    return out;
}

Result<PayloadContainer> PayloadContainer::decode(ByteView v) {
    if (v.empty()) {
        return bad("payload container: empty");
    }
    return PayloadContainer{Bytes(v.begin(), v.end())};
}

Result<PayloadContainerType> PayloadContainerType::decode(ByteView v) {
    auto o = one(v, "payload container type: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t t = *o & 0x0F;
    if (t == 0) {
        return range("payload container type: 0 is reserved");
    }
    return PayloadContainerType{t};
}

Result<PduSessionIdentity2> PduSessionIdentity2::decode(ByteView v) {
    auto o = one(v, "pdu session identity 2: one octet");
    if (!o) {
        return o.error();
    }
    return PduSessionIdentity2{*o};
}

Result<PlmnList> PlmnList::decode(ByteView v) {
    if (v.empty() || v.size() % 3 != 0 || v.size() > 45) {
        return bad("plmn list: 1 to 15 PLMNs of three octets");
    }
    PlmnList l;
    for (std::size_t i = 0; i < v.size(); i += 3) {
        auto p = Plmn::decode(v.subspan(i, 3));
        if (!p) {
            return p.error();
        }
        l.plmns.push_back(*p);
    }
    return l;
}

Bytes PlmnList::encode() const {
    Bytes out;
    for (const auto& p : plmns) {
        const Bytes b = p.encode();
        out.insert(out.end(), b.begin(), b.end());
    }
    return out;
}

Result<RejectedNssai> RejectedNssai::decode(ByteView v) {
    if (v.empty()) {
        return bad("rejected nssai: empty");
    }
    RejectedNssai r;
    std::size_t at = 0;
    while (at < v.size()) {
        const std::size_t len = v[at] >> 4;
        Entry e;
        e.cause = v[at] & 0x0F;
        ++at;
        if ((len != 1 && len != 4) || at + len > v.size()) {
            return bad("rejected nssai: an entry is 1 or 4 octets within the value");
        }
        e.sst = v[at];
        if (len == 4) {
            e.sd = be24(v.subspan(at + 1));
        }
        at += len;
        r.list.push_back(e);
    }
    return r;
}

Bytes RejectedNssai::encode() const {
    Bytes out;
    for (const auto& e : list) {
        out.push_back(static_cast<std::uint8_t>(((e.sd ? 4 : 1) << 4) | (e.cause & 0x0F)));
        out.push_back(e.sst);
        if (e.sd) {
            put24(out, *e.sd);
        }
    }
    return out;
}

Result<RequestType> RequestType::decode(ByteView v) {
    auto o = one(v, "request type: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t t = *o & 0x07;
    if (t == 0 || t == 7) {
        return range("request type: a reserved value");
    }
    return RequestType{t};
}

Result<S1UeNetworkCapability> S1UeNetworkCapability::decode(ByteView v) {
    if (v.size() < 2 || v.size() > 13) {
        return bad("s1 ue network capability: 2 to 13 octets");
    }
    return S1UeNetworkCapability{Bytes(v.begin(), v.end())};
}

Result<ServiceType> ServiceType::decode(ByteView v) {
    auto o = one(v, "service type: one value");
    if (!o) {
        return o.error();
    }
    return ServiceType{static_cast<std::uint8_t>(*o & 0x0F)};
}

Result<SmsIndication> SmsIndication::decode(ByteView v) {
    auto o = one(v, "sms indication: one value");
    if (!o) {
        return o.error();
    }
    return SmsIndication{(*o & 0x01) != 0};
}

Result<UeSecurityCapability> UeSecurityCapability::decode(ByteView v) {
    if (v.size() < 2 || v.size() > 8) {
        return bad("ue security capability: 2 to 8 octets");
    }
    UeSecurityCapability c;
    c.ea = v[0];
    c.ia = v[1];
    if (v.size() >= 3) {
        c.eea = v[2];
    }
    if (v.size() >= 4) {
        c.eia = v[3];
    }
    if (v.size() > 4) {
        c.spare.assign(v.begin() + 4, v.end());
    }
    return c;
}

Bytes UeSecurityCapability::encode() const {
    Bytes out{ea, ia};
    if (eea || eia) {
        out.push_back(eea.value_or(0));
        out.push_back(eia.value_or(0));
        out.insert(out.end(), spare.begin(), spare.end());
    }
    return out;
}

Result<UsageSetting> UsageSetting::decode(ByteView v) {
    auto o = one(v, "ue's usage setting: one octet");
    if (!o) {
        return o.error();
    }
    return UsageSetting{(*o & 0x01) != 0};
}

Result<UeStatus> UeStatus::decode(ByteView v) {
    auto o = one(v, "ue status: one octet");
    if (!o) {
        return o.error();
    }
    return UeStatus{(*o & 0x01) != 0, (*o & 0x02) != 0};
}

Bytes UeStatus::encode() const { return {static_cast<std::uint8_t>((s1_registered ? 0x01 : 0) | (n1_registered ? 0x02 : 0))}; }

Result<DrxParameters> DrxParameters::decode(ByteView v) {
    auto o = one(v, "5gs drx parameters: one octet");
    if (!o) {
        return o.error();
    }
    const std::uint8_t d = *o & 0x0F;
    return DrxParameters{d <= 4 ? d : std::uint8_t{0}};   // other values read as "not specified"
}

// ---- 9.11.4 ---------------------------------------------------------------------------

Result<FiveGsmCapability> FiveGsmCapability::decode(ByteView v) {
    if (v.empty() || v.size() > 13) {
        return bad("5gsm capability: 1 to 13 octets");
    }
    return FiveGsmCapability{Bytes(v.begin(), v.end())};
}

Result<AllowedSscMode> AllowedSscMode::decode(ByteView v) {
    auto o = one(v, "allowed ssc mode: one value");
    if (!o) {
        return o.error();
    }
    return AllowedSscMode{(*o & 0x01) != 0, (*o & 0x02) != 0, (*o & 0x04) != 0};
}

Bytes AllowedSscMode::encode() const {
    return {static_cast<std::uint8_t>((ssc1 ? 0x01 : 0) | (ssc2 ? 0x02 : 0) | (ssc3 ? 0x04 : 0))};
}

Result<IntegrityProtectionMaxDataRate> IntegrityProtectionMaxDataRate::decode(ByteView v) {
    if (v.size() != 2) {
        return bad("integrity protection maximum data rate: two octets");
    }
    return IntegrityProtectionMaxDataRate{v[0], v[1]};
}

Result<MaxPacketFilters> MaxPacketFilters::decode(ByteView v) {
    if (v.size() != 2) {
        return bad("maximum number of supported packet filters: two octets");
    }
    const auto n = static_cast<std::uint16_t>((v[0] << 3) | (v[1] >> 5));
    if (n < 17 || n > 1024) {
        return range("maximum number of supported packet filters: 17 to 1024");
    }
    return MaxPacketFilters{n};
}

Bytes MaxPacketFilters::encode() const {
    return {static_cast<std::uint8_t>(value >> 3), static_cast<std::uint8_t>((value & 0x07) << 5)};
}

std::string PduAddress::ipv4_text() const {
    if (!ipv4) {
        return {};
    }
    return std::to_string((*ipv4)[0]) + "." + std::to_string((*ipv4)[1]) + "." + std::to_string((*ipv4)[2]) + "." +
           std::to_string((*ipv4)[3]);
}

Result<PduAddress> PduAddress::decode(ByteView v) {
    if (v.empty()) {
        return bad("pdu address: empty");
    }
    PduAddress a;
    a.type = v[0] & 0x07;
    const bool lla = (v[0] & 0x08) != 0;
    std::size_t need = 0;
    switch (a.type) {
    case 1: need = 4; break;
    case 2: need = 8; break;
    case 3: need = 12; break;
    default: return range("pdu address: the session type is IPv4, IPv6 or IPv4v6");
    }
    if (v.size() != 1 + need + (lla ? 16 : 0)) {
        return bad("pdu address: the length does not fit the type");
    }
    std::size_t at = 1;
    if (a.type == 2 || a.type == 3) {
        std::array<std::uint8_t, 8> iid{};
        std::copy(v.begin() + 1, v.begin() + 9, iid.begin());
        a.ipv6_iid = iid;
        at = 9;
    }
    if (a.type == 1 || a.type == 3) {
        std::array<std::uint8_t, 4> ip{};
        std::copy(v.begin() + static_cast<std::ptrdiff_t>(at), v.begin() + static_cast<std::ptrdiff_t>(at + 4), ip.begin());
        a.ipv4 = ip;
        at += 4;
    }
    if (lla) {
        std::array<std::uint8_t, 16> l{};
        std::copy(v.begin() + static_cast<std::ptrdiff_t>(at), v.end(), l.begin());
        a.smf_ipv6_lla = l;
    }
    return a;
}

Bytes PduAddress::encode() const {
    Bytes out{static_cast<std::uint8_t>((type & 0x07) | (smf_ipv6_lla ? 0x08 : 0))};
    if (ipv6_iid) {
        out.insert(out.end(), ipv6_iid->begin(), ipv6_iid->end());
    }
    if (ipv4) {
        out.insert(out.end(), ipv4->begin(), ipv4->end());
    }
    if (smf_ipv6_lla) {
        out.insert(out.end(), smf_ipv6_lla->begin(), smf_ipv6_lla->end());
    }
    return out;
}

Result<PduSessionType> PduSessionType::decode(ByteView v) {
    auto o = one(v, "pdu session type: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t t = *o & 0x07;
    if (t == 0 || t == 7) {
        return range("pdu session type: a reserved value");
    }
    return PduSessionType{t};
}

std::optional<std::uint8_t> QosFlowDescriptions::Description::five_qi() const {
    for (const auto& p : parameters) {
        if (p.id == 0x01 && p.contents.size() == 1) {
            return p.contents[0];
        }
    }
    return std::nullopt;
}

Result<QosFlowDescriptions> QosFlowDescriptions::decode(ByteView v) {
    if (v.size() < 3) {
        return bad("qos flow descriptions: shorter than one description");
    }
    QosFlowDescriptions q;
    std::size_t at = 0;
    while (at < v.size()) {
        if (at + 3 > v.size()) {
            return bad("qos flow descriptions: a description is cut");
        }
        Description d;
        d.qfi = v[at] & 0x3F;
        d.operation = v[at + 1] >> 5;
        d.e_bit = (v[at + 2] & 0x40) != 0;
        const unsigned n = v[at + 2] & 0x3F;
        at += 3;
        if (d.operation < 1 || d.operation > 3) {
            return range("qos flow descriptions: operation code 1, 2 or 3");
        }
        for (unsigned i = 0; i < n; ++i) {
            if (at + 2 > v.size() || at + 2 + v[at + 1] > v.size()) {
                return bad("qos flow descriptions: a parameter overruns the value");
            }
            Parameter p;
            p.id = v[at];
            const std::size_t len = v[at + 1];
            p.contents.assign(v.begin() + static_cast<std::ptrdiff_t>(at + 2), v.begin() + static_cast<std::ptrdiff_t>(at + 2 + len));
            at += 2 + len;
            d.parameters.push_back(std::move(p));
        }
        q.list.push_back(std::move(d));
    }
    return q;
}

Result<Bytes> QosFlowDescriptions::encode() const {
    Bytes out;
    for (const auto& d : list) {
        if (d.parameters.size() > 63) {
            return range("qos flow descriptions: at most 63 parameters");
        }
        out.push_back(d.qfi & 0x3F);
        out.push_back(static_cast<std::uint8_t>(d.operation << 5));
        out.push_back(static_cast<std::uint8_t>((d.e_bit ? 0x40U : 0U) | static_cast<unsigned>(d.parameters.size())));
        for (const auto& p : d.parameters) {
            if (p.contents.size() > 255) {
                return range("qos flow descriptions: a parameter is at most 255 octets");
            }
            out.push_back(p.id);
            out.push_back(static_cast<std::uint8_t>(p.contents.size()));
            out.insert(out.end(), p.contents.begin(), p.contents.end());
        }
    }
    return out;
}

Result<QosRules> QosRules::decode(ByteView v) {
    if (v.size() < 4) {
        return bad("qos rules: shorter than one rule");
    }
    QosRules q;
    std::size_t at = 0;
    while (at < v.size()) {
        if (at + 3 > v.size()) {
            return bad("qos rules: a rule header is cut");
        }
        Rule r;
        r.id = v[at];
        const std::size_t len = (std::size_t{v[at + 1]} << 8) | v[at + 2];
        at += 3;
        if (len < 1 || at + len > v.size()) {
            return bad("qos rules: a rule overruns the value");
        }
        const ByteView body = v.subspan(at, len);
        at += len;
        r.operation = body[0] >> 5;
        r.default_rule = (body[0] & 0x10) != 0;
        const unsigned nf = body[0] & 0x0F;
        if (r.operation < 1 || r.operation > 6) {
            return range("qos rules: operation code 1 to 6");
        }
        std::size_t p = 1;
        for (unsigned i = 0; i < nf; ++i) {
            if (p >= body.size()) {
                return bad("qos rules: a packet filter is cut");
            }
            PacketFilter f;
            f.direction = (body[p] >> 4) & 0x03;
            f.id = body[p] & 0x0F;
            ++p;
            if (r.operation == 5) {   // modify, delete packet filters: identifiers only
                r.filters.push_back(f);
                continue;
            }
            if (p >= body.size() || p + 1 + body[p] > body.size()) {
                return bad("qos rules: packet filter contents overrun the rule");
            }
            const std::size_t clen = body[p];
            const ByteView contents = body.subspan(p + 1, clen);
            p += 1 + clen;
            std::size_t c = 0;
            while (c < contents.size()) {
                Component comp;
                comp.type = contents[c++];
                const int fixed = component_length(comp.type);
                const std::size_t n = fixed < 0 ? contents.size() - c : static_cast<std::size_t>(fixed);
                if (c + n > contents.size()) {
                    return bad("qos rules: a packet filter component is cut");
                }
                comp.value.assign(contents.begin() + static_cast<std::ptrdiff_t>(c), contents.begin() + static_cast<std::ptrdiff_t>(c + n));
                c += n;
                f.components.push_back(std::move(comp));
            }
            if (f.components.empty()) {
                return bad("qos rules: a packet filter without components");
            }
            r.filters.push_back(std::move(f));
        }
        if (p < body.size()) {
            r.precedence = body[p++];
        }
        if (p < body.size()) {
            r.segregation = (body[p] & 0x40) != 0;
            r.qfi = body[p] & 0x3F;
            ++p;
        }
        if (p != body.size()) {
            return bad("qos rules: octets after the QFI");
        }
        if (r.operation != 2 && r.operation != 5 && r.operation != 6 && (!r.precedence || !r.qfi)) {
            return bad("qos rules: a rule without precedence or QFI");
        }
        q.list.push_back(std::move(r));
    }
    return q;
}

Result<Bytes> QosRules::encode() const {
    Bytes out;
    for (const auto& r : list) {
        if (r.filters.size() > 15) {
            return range("qos rules: at most 15 packet filters");
        }
        Bytes body{static_cast<std::uint8_t>((unsigned{r.operation} << 5U) | (r.default_rule ? 0x10U : 0U) |
                                             static_cast<unsigned>(r.filters.size()))};
        for (const auto& f : r.filters) {
            body.push_back(static_cast<std::uint8_t>(((f.direction & 0x03) << 4) | (f.id & 0x0F)));
            if (r.operation == 5) {
                continue;
            }
            Bytes contents;
            for (const auto& c : f.components) {
                contents.push_back(c.type);
                contents.insert(contents.end(), c.value.begin(), c.value.end());
            }
            if (contents.size() > 255) {
                return range("qos rules: packet filter contents are at most 255 octets");
            }
            body.push_back(static_cast<std::uint8_t>(contents.size()));
            body.insert(body.end(), contents.begin(), contents.end());
        }
        if (const std::optional<std::uint8_t> prec = r.precedence; prec.has_value()) {
            body.push_back(prec.value());
        }
        if (const std::optional<std::uint8_t> qfi = r.qfi; qfi.has_value()) {
            body.push_back(static_cast<std::uint8_t>((r.segregation ? 0x40 : 0) | (qfi.value() & 0x3F)));
        }
        out.push_back(r.id);
        out.push_back(static_cast<std::uint8_t>(body.size() >> 8));
        out.push_back(static_cast<std::uint8_t>(body.size() & 0xFF));
        out.insert(out.end(), body.begin(), body.end());
    }
    return out;
}

namespace {

std::optional<std::uint64_t> ambr_bps(std::uint8_t unit, std::uint16_t value) {
    if (unit < 1 || unit > 25) {
        return std::nullopt;
    }
    const unsigned group = (unit - 1U) / 5U;   // kbps, Mbps, Gbps, Tbps, Pbps
    const unsigned step = (unit - 1U) % 5U;    // ×1, ×4, ×16, ×64, ×256
    std::uint64_t base = 1000;
    for (unsigned i = 0; i < group; ++i) {
        base *= 1000;
    }
    const std::uint64_t factor = std::uint64_t{1} << (2 * step);
    const std::uint64_t per = base * factor;
    if (value != 0 && per > UINT64_MAX / value) {
        return std::nullopt;   // beyond 64 bits
    }
    return per * value;
}

} // namespace

std::optional<std::uint64_t> SessionAmbr::dl_bps() const noexcept { return ambr_bps(dl_unit, dl_value); }
std::optional<std::uint64_t> SessionAmbr::ul_bps() const noexcept { return ambr_bps(ul_unit, ul_value); }

Result<SessionAmbr> SessionAmbr::decode(ByteView v) {
    if (v.size() != 6) {
        return bad("session-ambr: six octets");
    }
    SessionAmbr a;
    a.dl_unit = v[0];
    a.dl_value = static_cast<std::uint16_t>((v[1] << 8) | v[2]);
    a.ul_unit = v[3];
    a.ul_value = static_cast<std::uint16_t>((v[4] << 8) | v[5]);
    if (a.dl_unit == 0 || a.ul_unit == 0) {
        return range("session-ambr: unit 0 is not used");
    }
    return a;
}

Bytes SessionAmbr::encode() const {
    return {dl_unit, static_cast<std::uint8_t>(dl_value >> 8), static_cast<std::uint8_t>(dl_value & 0xFF),
            ul_unit, static_cast<std::uint8_t>(ul_value >> 8), static_cast<std::uint8_t>(ul_value & 0xFF)};
}

Result<SscMode> SscMode::decode(ByteView v) {
    auto o = one(v, "ssc mode: one value");
    if (!o) {
        return o.error();
    }
    const std::uint8_t m = *o & 0x07;
    if (m == 0 || m == 7) {
        return range("ssc mode: a reserved value");
    }
    return SscMode{m > 3 ? std::uint8_t{1} : m};   // 4..6 are unused and read as SSC mode 1
}

Result<ReattemptIndicator> ReattemptIndicator::decode(ByteView v) {
    auto o = one(v, "re-attempt indicator: one octet");
    if (!o) {
        return o.error();
    }
    return ReattemptIndicator{(*o & 0x01) != 0, (*o & 0x02) != 0};
}

Bytes ReattemptIndicator::encode() const { return {static_cast<std::uint8_t>((ratc ? 0x01 : 0) | (eplmnc ? 0x02 : 0))}; }

Result<CongestionReattemptIndicator> CongestionReattemptIndicator::decode(ByteView v) {
    auto o = one(v, "5gsm congestion re-attempt indicator: one octet");
    if (!o) {
        return o.error();
    }
    return CongestionReattemptIndicator{(*o & 0x01) != 0};
}

Result<EpcoIpv4Dns> EpcoIpv4Dns::decode(ByteView v) {
    if (v.size() != 4) {
        return bad("epco dns server ipv4 address: four octets");
    }
    EpcoIpv4Dns d;
    std::copy(v.begin(), v.end(), d.address.begin());
    return d;
}

Result<EpcoIpv4LinkMtu> EpcoIpv4LinkMtu::decode(ByteView v) {
    if (v.size() != 2) {
        return bad("epco ipv4 link mtu: two octets");
    }
    return EpcoIpv4LinkMtu{static_cast<std::uint16_t>((v[0] << 8) | v[1])};
}

} // namespace ksim::nas::ie
