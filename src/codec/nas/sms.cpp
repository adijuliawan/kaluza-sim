// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/nas/sms.hpp"

#include <array>

namespace ksim::sms {

namespace detail {
extern const std::uint32_t kGsm7Default[128];
extern const std::uint32_t kGsm7Extension[][2];
extern const std::size_t kGsm7ExtensionCount;
} // namespace detail

namespace {

constexpr std::uint8_t kPdSms = 0x9;      // TS 24.007 11.2.3.1.1: SMS messages
constexpr std::uint8_t kRpUserDataIei = 0x41;
constexpr std::uint32_t kEsc = 0xFFFFFFFF;

Error err(Errc c, std::size_t off, const char* what) {
    return make_error(c, static_cast<std::uint32_t>(off), what);
}

// ---- a cursor over the input --------------------------------------------------------

struct Cursor {
    ByteView in;
    std::size_t pos = 0;
    bool more() const { return pos < in.size(); }
    std::size_t remaining() const { return in.size() - pos; }
    Result<std::uint8_t> u8(const char* what) {
        if (pos >= in.size()) {
            return err(Errc::truncated, pos, what);
        }
        return in[pos++];
    }
    Result<Bytes> take(std::size_t n, const char* what) {
        if (pos + n > in.size()) {
            return err(Errc::truncated, pos, what);
        }
        Bytes b(in.begin() + static_cast<std::ptrdiff_t>(pos), in.begin() + static_cast<std::ptrdiff_t>(pos + n));
        pos += n;
        return b;
    }
    Result<Bytes> lv(const char* what) {
        auto l = u8(what);
        if (!l) {
            return l.error();
        }
        return take(*l, what);
    }
};

#define TRY_ASSIGN(var, expr)            \
    auto var##_r = (expr);               \
    if (!var##_r) {                      \
        return var##_r.error();          \
    }                                    \
    auto var = std::move(*var##_r)   // NOLINT(bugprone-macro-parentheses): var names a declaration

void put_lv(ByteWriter& w, const Bytes& v) {
    w.u8(static_cast<std::uint8_t>(v.size()));
    w.bytes(v);
}

// ---- TPDU pieces --------------------------------------------------------------------

Result<Address> read_address(Cursor& c) {
    Address a;
    TRY_ASSIGN(len, c.u8("TP address length"));
    TRY_ASSIGN(toa, c.u8("TP address type"));
    a.length = len;
    a.toa = toa;
    TRY_ASSIGN(digits, c.take((std::size_t{len} + 1) / 2, "TP address digits"));
    a.digits = std::move(digits);
    return a;
}

void put_address(ByteWriter& w, const Address& a) {
    w.u8(a.length);
    w.u8(a.toa);
    w.bytes(a.digits);
}

std::size_t vp_length(std::uint8_t first) {
    switch ((first >> 3) & 0x03) {  // TP-VPF, bits 4-3 (9.2.3.3)
    case 0b10: return 1;            // relative
    case 0b01: return 7;            // enhanced
    case 0b11: return 7;            // absolute
    default: return 0;              // not present
    }
}

std::size_t ud_octets(std::uint8_t udl, std::uint8_t dcs, bool has_dcs) {
    // TP-UDL counts septets for the GSM 7-bit alphabet, else octets (9.2.3.16).
    if (!has_dcs || dcs_is_gsm7(dcs)) {
        return (std::size_t{udl} * 7 + 7) / 8;
    }
    return udl;
}

Result<void> read_ud(Cursor& c, Tpdu& t) {
    TRY_ASSIGN(udl, c.u8("TP-UDL"));
    t.udl = udl;
    TRY_ASSIGN(ud, c.take(ud_octets(udl, t.dcs, t.has_dcs), "TP-UD"));
    t.ud = std::move(ud);
    t.has_ud = true;
    return {};
}

/// The optional tail of reports and STATUS-REPORT, after TP-PI (9.2.3.27).
// TS 23.040 9.2.3.27: TP-PI octet 1, and a further octet for as long as bit 8
// (the extension bit) of the one before is set.
Result<void> read_pi(Cursor& c, Tpdu& t) {
    TRY_ASSIGN(pi, c.u8("TP-PI"));
    t.pi = pi;
    for (std::uint8_t last = pi; (last & 0x80) != 0;) {
        TRY_ASSIGN(more, c.u8("TP-PI extension octet"));
        t.pi_more.push_back(more);
        last = more;
    }
    return {};
}

// The parameters TP-PI octet 1 announces (TP-PID, TP-DCS, TP-UDL with TP-UD).
// A reserved bit set means more follows TP-UD, which the receiver discards.
Result<void> read_pi_fields(Cursor& c, Tpdu& t) {
    const std::uint8_t pi = t.pi.value_or(0);
    if ((pi & 0x01) != 0) {
        TRY_ASSIGN(pid, c.u8("TP-PID"));
        t.pid = pid;
        t.has_pid = true;
    }
    if ((pi & 0x02) != 0) {
        TRY_ASSIGN(dcs, c.u8("TP-DCS"));
        t.dcs = dcs;
        t.has_dcs = true;
    }
    if ((pi & 0x04) != 0) {
        if (auto ok = read_ud(c, t); !ok) {
            return ok.error();
        }
    }
    if ((pi & 0x78) != 0 || !t.pi_more.empty()) {
        TRY_ASSIGN(rest, c.take(c.remaining(), "TP: octets after TP-UD"));
        t.discarded = std::move(rest);
    }
    return {};
}

Result<void> read_pi_tail(Cursor& c, Tpdu& t) {
    if (!c.more()) {
        return {};
    }
    if (auto ok = read_pi(c, t); !ok) {
        return ok.error();
    }
    return read_pi_fields(c, t);
}

void put_pi_fields(ByteWriter& w, const Tpdu& t) {
    if (t.has_pid) {
        w.u8(t.pid);
    }
    if (t.has_dcs) {
        w.u8(t.dcs);
    }
    if (t.has_ud) {
        w.u8(t.udl);
        w.bytes(t.ud);
    }
    w.bytes(t.discarded);
}

void put_pi_tail(ByteWriter& w, const Tpdu& t) {
    if (!t.pi) {
        return;
    }
    w.u8(*t.pi);
    w.bytes(t.pi_more);
    put_pi_fields(w, t);
}

// ---- UTF-8 --------------------------------------------------------------------------

void put_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

/// The next code point of UTF-8 text, or 0xFFFFFFFF for a broken sequence.
std::uint32_t next_utf8(std::string_view s, std::size_t& i) {
    const auto b = static_cast<std::uint8_t>(s[i++]);
    if (b < 0x80) {
        return b;
    }
    int n = b >= 0xF0 ? 3 : b >= 0xE0 ? 2 : b >= 0xC0 ? 1 : -1;
    if (n < 0 || i + static_cast<std::size_t>(n) > s.size()) {
        return 0xFFFFFFFF;
    }
    std::uint32_t cp = b & (0x3F >> n);
    for (int k = 0; k < n; ++k) {
        cp = (cp << 6) | (static_cast<std::uint8_t>(s[i++]) & 0x3F);
    }
    return cp;
}

std::uint8_t septet(ByteView packed, std::size_t bit) {
    const std::size_t o = bit / 8;
    const unsigned s = static_cast<unsigned>(bit % 8);
    unsigned v = packed[o] >> s;
    if (s > 1 && o + 1 < packed.size()) {
        v |= static_cast<unsigned>(packed[o + 1]) << (8 - s);
    }
    return static_cast<std::uint8_t>(v & 0x7F);
}

} // namespace

// ---- CP -----------------------------------------------------------------------------

Result<Cp> decode_cp(ByteView in) {
    Cursor c{in};
    TRY_ASSIGN(o1, c.u8("CP: header"));
    if ((o1 & 0x0F) != kPdSms) {
        return err(Errc::malformed, 0, "CP: protocol discriminator is not SMS");
    }
    Cp cp;
    cp.ti = static_cast<std::uint8_t>(o1 >> 4);
    TRY_ASSIGN(mt, c.u8("CP: message type"));
    switch (mt) {
    case 0x01: {
        cp.type = CpType::data;
        TRY_ASSIGN(ud, c.lv("CP-User data"));
        cp.user_data = std::move(ud);
        break;
    }
    case 0x04:
        cp.type = CpType::ack;
        break;
    case 0x10: {
        cp.type = CpType::error;
        TRY_ASSIGN(cause, c.u8("CP-Cause"));
        cp.cause = cause;
        break;
    }
    default:
        return err(Errc::unsupported, 1, "CP: unknown message type");
    }
    if (c.more()) {
        return err(Errc::malformed, c.pos, "CP: trailing octets");
    }
    return cp;
}

Bytes encode_cp(const Cp& cp) {
    ByteWriter w(4 + cp.user_data.size());
    w.u8(static_cast<std::uint8_t>((cp.ti << 4) | kPdSms));
    w.u8(static_cast<std::uint8_t>(cp.type));
    if (cp.type == CpType::data) {
        put_lv(w, cp.user_data);
    } else if (cp.type == CpType::error) {
        w.u8(cp.cause);
    }
    return std::move(w).take();
}

// ---- RP -----------------------------------------------------------------------------

Result<Rp> decode_rp(ByteView in) {
    Cursor c{in};
    TRY_ASSIGN(o1, c.u8("RP: message type"));
    if ((o1 & 0xF8) != 0 || (o1 & 0x07) > 6) {
        return err(Errc::malformed, 0, "RP: unknown message type");
    }
    Rp rp;
    rp.mti = static_cast<RpMti>(o1 & 0x07);
    TRY_ASSIGN(mr, c.u8("RP: message reference"));
    rp.mr = mr;
    switch (rp.mti) {
    case RpMti::data_ms_n:
    case RpMti::data_n_ms: {
        TRY_ASSIGN(oa, c.lv("RP-Originator Address"));
        TRY_ASSIGN(da, c.lv("RP-Destination Address"));
        TRY_ASSIGN(ud, c.lv("RP-User data"));
        rp.originator = std::move(oa);
        rp.destination = std::move(da);
        rp.user_data = std::move(ud);
        break;
    }
    case RpMti::error_ms_n:
    case RpMti::error_n_ms: {
        TRY_ASSIGN(cause, c.lv("RP-Cause"));
        rp.cause = std::move(cause);
        [[fallthrough]];
    }
    case RpMti::ack_ms_n:
    case RpMti::ack_n_ms:
        if (c.more()) {
            TRY_ASSIGN(iei, c.u8("RP-User data IEI"));
            if (iei != kRpUserDataIei) {
                return err(Errc::malformed, c.pos - 1, "RP: unknown IE");
            }
            TRY_ASSIGN(ud, c.lv("RP-User data"));
            rp.user_data = std::move(ud);
        }
        break;
    case RpMti::smma_ms_n:
        break;
    }
    if (c.more()) {
        return err(Errc::malformed, c.pos, "RP: trailing octets");
    }
    return rp;
}

Bytes encode_rp(const Rp& rp) {
    ByteWriter w(16);
    w.u8(static_cast<std::uint8_t>(rp.mti));
    w.u8(rp.mr);
    switch (rp.mti) {
    case RpMti::data_ms_n:
    case RpMti::data_n_ms:
        put_lv(w, rp.originator);
        put_lv(w, rp.destination);
        put_lv(w, rp.user_data.value_or(Bytes{}));
        break;
    case RpMti::error_ms_n:
    case RpMti::error_n_ms:
        put_lv(w, rp.cause);
        [[fallthrough]];
    case RpMti::ack_ms_n:
    case RpMti::ack_n_ms:
        if (rp.user_data) {
            w.u8(kRpUserDataIei);
            put_lv(w, *rp.user_data);
        }
        break;
    case RpMti::smma_ms_n:
        break;
    }
    return std::move(w).take();
}

// ---- TPDU ---------------------------------------------------------------------------

bool dcs_is_gsm7(std::uint8_t dcs) noexcept {
    const unsigned g = dcs >> 4;
    if (g <= 0x7) {
        return (dcs & 0x20) == 0 && ((dcs >> 2) & 0x03) == 0;  // uncompressed, GSM 7-bit
    }
    if (g <= 0xB) {
        return true;  // reserved groups: the default alphabet (TS 23.038 4)
    }
    if (g == 0xC || g == 0xD) {
        return true;  // message waiting, default alphabet
    }
    if (g == 0xE) {
        return false; // message waiting, UCS2
    }
    return (dcs & 0x04) == 0;  // 1111: data coding / message class
}

bool dcs_is_ucs2(std::uint8_t dcs) noexcept {
    const unsigned g = dcs >> 4;
    return (g <= 0x7 && (dcs & 0x20) == 0 && ((dcs >> 2) & 0x03) == 0x02) || g == 0xE;
}

Result<Tpdu> decode_tpdu(ByteView in, TpDir dir, bool rp_error) {
    Cursor c{in};
    TRY_ASSIGN(first, c.u8("TP first octet"));
    Tpdu t;
    t.first = first;
    const unsigned mti = first & 0x03;
    const bool to_sc = dir == TpDir::ms_to_sc;
    if (mti == 0) {
        t.type = to_sc ? TpduType::deliver_report : TpduType::deliver;
    } else if (mti == 1) {
        t.type = to_sc ? TpduType::submit : TpduType::submit_report;
    } else if (mti == 2) {
        t.type = to_sc ? TpduType::command : TpduType::status_report;
    } else {
        return err(Errc::malformed, 0, "TP-MTI reserved");
    }
    switch (t.type) {
    case TpduType::deliver: {
        TRY_ASSIGN(a, read_address(c));
        t.address = std::move(a);
        TRY_ASSIGN(pid, c.u8("TP-PID"));
        TRY_ASSIGN(dcs, c.u8("TP-DCS"));
        t.pid = pid;
        t.dcs = dcs;
        t.has_pid = t.has_dcs = true;
        TRY_ASSIGN(scts, c.take(7, "TP-SCTS"));
        t.scts = std::move(scts);
        if (auto ok = read_ud(c, t); !ok) {
            return ok.error();
        }
        break;
    }
    case TpduType::submit: {
        TRY_ASSIGN(mr, c.u8("TP-MR"));
        t.mr = mr;
        TRY_ASSIGN(a, read_address(c));
        t.address = std::move(a);
        TRY_ASSIGN(pid, c.u8("TP-PID"));
        TRY_ASSIGN(dcs, c.u8("TP-DCS"));
        t.pid = pid;
        t.dcs = dcs;
        t.has_pid = t.has_dcs = true;
        TRY_ASSIGN(vp, c.take(vp_length(first), "TP-VP"));
        t.vp = std::move(vp);
        if (auto ok = read_ud(c, t); !ok) {
            return ok.error();
        }
        break;
    }
    case TpduType::deliver_report:
    case TpduType::submit_report: {
        if (rp_error) {
            TRY_ASSIGN(fcs, c.u8("TP-FCS"));
            t.fcs = fcs;
        }
        if (auto ok = read_pi(c, t); !ok) {
            return ok.error();
        }
        if (t.type == TpduType::submit_report) {
            TRY_ASSIGN(scts, c.take(7, "TP-SCTS"));
            t.scts = std::move(scts);
        }
        if (auto ok = read_pi_fields(c, t); !ok) {
            return ok.error();
        }
        break;
    }
    case TpduType::status_report: {
        TRY_ASSIGN(mr, c.u8("TP-MR"));
        t.mr = mr;
        TRY_ASSIGN(a, read_address(c));
        t.address = std::move(a);
        TRY_ASSIGN(scts, c.take(7, "TP-SCTS"));
        TRY_ASSIGN(dt, c.take(7, "TP-DT"));
        TRY_ASSIGN(st, c.u8("TP-ST"));
        t.scts = std::move(scts);
        t.dt = std::move(dt);
        t.st = st;
        if (auto ok = read_pi_tail(c, t); !ok) {
            return ok.error();
        }
        break;
    }
    case TpduType::command: {
        TRY_ASSIGN(mr, c.u8("TP-MR"));
        TRY_ASSIGN(pid, c.u8("TP-PID"));
        TRY_ASSIGN(ct, c.u8("TP-CT"));
        TRY_ASSIGN(mn, c.u8("TP-MN"));
        t.mr = mr;
        t.pid = pid;
        t.has_pid = true;
        t.ct = ct;
        t.mn = mn;
        TRY_ASSIGN(a, read_address(c));
        t.address = std::move(a);
        TRY_ASSIGN(cdl, c.u8("TP-CDL"));
        t.udl = cdl;
        TRY_ASSIGN(cd, c.take(cdl, "TP-CD"));
        t.ud = std::move(cd);
        t.has_ud = true;
        break;
    }
    }
    if (c.more()) {
        return err(Errc::malformed, c.pos, "TPDU: trailing octets");
    }
    return t;
}

Bytes encode_tpdu(const Tpdu& t) {
    ByteWriter w(32 + t.ud.size());
    w.u8(t.first);
    switch (t.type) {
    case TpduType::deliver:
        put_address(w, t.address);
        w.u8(t.pid);
        w.u8(t.dcs);
        w.bytes(t.scts);
        w.u8(t.udl);
        w.bytes(t.ud);
        break;
    case TpduType::submit:
        w.u8(t.mr);
        put_address(w, t.address);
        w.u8(t.pid);
        w.u8(t.dcs);
        w.bytes(t.vp);
        w.u8(t.udl);
        w.bytes(t.ud);
        break;
    case TpduType::deliver_report:
    case TpduType::submit_report:
        if (t.fcs) {
            w.u8(*t.fcs);
        }
        w.u8(t.pi.value_or(0));
        w.bytes(t.pi_more);
        if (t.type == TpduType::submit_report) {
            w.bytes(t.scts);
        }
        put_pi_fields(w, t);
        break;
    case TpduType::status_report:
        w.u8(t.mr);
        put_address(w, t.address);
        w.bytes(t.scts);
        w.bytes(t.dt);
        w.u8(t.st);
        put_pi_tail(w, t);
        break;
    case TpduType::command:
        w.u8(t.mr);
        w.u8(t.pid);
        w.u8(t.ct);
        w.u8(t.mn);
        put_address(w, t.address);
        w.u8(t.udl);
        w.bytes(t.ud);
        break;
    }
    return std::move(w).take();
}

// ---- GSM 7-bit ----------------------------------------------------------------------

std::string gsm7_to_utf8(ByteView packed, std::size_t septets, unsigned fill_bits) {
    std::string out;
    bool escaped = false;
    for (std::size_t i = 0; i < septets; ++i) {
        const std::size_t bit = fill_bits + 7 * i;
        if (bit / 8 >= packed.size()) {
            break;
        }
        const std::uint8_t s = septet(packed, bit);
        if (escaped) {
            escaped = false;
            std::uint32_t cp = 0xFFFD;
            for (std::size_t k = 0; k < detail::kGsm7ExtensionCount; ++k) {
                if (detail::kGsm7Extension[k][0] == s) {
                    cp = detail::kGsm7Extension[k][1];
                }
            }
            put_utf8(out, cp);
            continue;
        }
        const std::uint32_t cp = detail::kGsm7Default[s];
        if (cp == kEsc) {
            escaped = true;
            continue;
        }
        put_utf8(out, cp);
    }
    return out;
}

Result<std::pair<Bytes, std::size_t>> utf8_to_gsm7(std::string_view text, unsigned fill_bits) {
    std::vector<std::uint8_t> septets;
    for (std::size_t i = 0; i < text.size();) {
        const std::uint32_t cp = next_utf8(text, i);
        int code = -1;
        for (int k = 0; k < 128 && code < 0; ++k) {
            if (detail::kGsm7Default[k] == cp && cp != kEsc) {
                code = k;
            }
        }
        if (code >= 0) {
            septets.push_back(static_cast<std::uint8_t>(code));
            continue;
        }
        for (std::size_t k = 0; k < detail::kGsm7ExtensionCount && code < 0; ++k) {
            if (detail::kGsm7Extension[k][1] == cp) {
                code = static_cast<int>(detail::kGsm7Extension[k][0]);
            }
        }
        if (code < 0) {
            return err(Errc::invalid_argument, i, "GSM 7-bit: a character outside the alphabet");
        }
        septets.push_back(0x1B);
        septets.push_back(static_cast<std::uint8_t>(code));
    }
    const std::size_t bits = fill_bits + 7 * septets.size();
    Bytes out((bits + 7) / 8, 0);
    for (std::size_t i = 0; i < septets.size(); ++i) {
        const std::size_t bit = fill_bits + 7 * i;
        out[bit / 8] |= static_cast<std::uint8_t>(septets[i] << (bit % 8));
        if (bit % 8 > 1) {
            out[bit / 8 + 1] |= static_cast<std::uint8_t>(septets[i] >> (8 - bit % 8));
        }
    }
    return std::make_pair(std::move(out), septets.size());
}

std::string ucs2_to_utf8(ByteView in) {
    std::string out;
    for (std::size_t i = 0; i + 1 < in.size(); i += 2) {
        put_utf8(out, (std::uint32_t{in[i]} << 8) | in[i + 1]);
    }
    return out;
}

Result<Bytes> utf8_to_ucs2(std::string_view text) {
    Bytes out;
    for (std::size_t i = 0; i < text.size();) {
        const std::uint32_t cp = next_utf8(text, i);
        if (cp > 0xFFFF) {
            return err(Errc::invalid_argument, i, "UCS2: a character outside the BMP");
        }
        out.push_back(static_cast<std::uint8_t>(cp >> 8));
        out.push_back(static_cast<std::uint8_t>(cp));
    }
    return out;
}

Result<std::vector<std::string>> split_text(std::string_view text, bool ucs2, std::size_t per_part) {
    std::vector<std::string> parts(1);
    std::size_t used = 0;
    for (std::size_t i = 0; i < text.size();) {
        const std::size_t start = i;
        const std::uint32_t cp = next_utf8(text, i);
        std::size_t cost = 1;
        if (ucs2) {
            if (cp > 0xFFFF) {
                return err(Errc::invalid_argument, start, "UCS2: a character outside the BMP");
            }
        } else {
            auto one = utf8_to_gsm7(text.substr(start, i - start));
            if (!one) {
                return one.error();
            }
            cost = one->second;   // 2 for an escaped character
        }
        if (used + cost > per_part) {
            parts.emplace_back();
            used = 0;
        }
        parts.back().append(text.substr(start, i - start));
        used += cost;
    }
    return parts;
}

// ---- JSON ---------------------------------------------------------------------------

std::string to_json(const Cp& cp) {
    std::string s = "{\"layer\":\"CP\",\"ti\":" + std::to_string(cp.ti) + ",\"type\":" +
                    std::to_string(static_cast<unsigned>(cp.type));
    if (cp.type == CpType::data) {
        s += ",\"user_data\":\"" + to_hex(cp.user_data) + "\"";
    } else if (cp.type == CpType::error) {
        s += ",\"cause\":" + std::to_string(cp.cause);
    }
    return s + "}";
}

std::string to_json(const Rp& rp) {
    std::string s = "{\"layer\":\"RP\",\"mti\":" + std::to_string(static_cast<unsigned>(rp.mti)) +
                    ",\"mr\":" + std::to_string(rp.mr) + ",\"originator\":\"" + to_hex(rp.originator) +
                    "\",\"destination\":\"" + to_hex(rp.destination) + "\",\"cause\":\"" + to_hex(rp.cause) + "\"";
    if (rp.user_data) {
        s += ",\"user_data\":\"" + to_hex(*rp.user_data) + "\"";
    }
    return s + "}";
}

std::string to_json(const Tpdu& t) {
    static constexpr std::array<const char*, 6> kNames = {"SMS-DELIVER", "SMS-DELIVER-REPORT", "SMS-SUBMIT",
                                                         "SMS-SUBMIT-REPORT", "SMS-STATUS-REPORT", "SMS-COMMAND"};
    std::string s = "{\"layer\":\"TPDU\",\"type\":\"";
    s += kNames[static_cast<std::size_t>(t.type)];
    s += "\",\"first\":" + std::to_string(t.first) + ",\"mr\":" + std::to_string(t.mr) +
         ",\"address_len\":" + std::to_string(t.address.length) + ",\"toa\":" + std::to_string(t.address.toa) +
         ",\"address\":\"" + to_hex(t.address.digits) + "\",\"pid\":" + std::to_string(t.pid) +
         ",\"dcs\":" + std::to_string(t.dcs) + ",\"udl\":" + std::to_string(t.udl) + ",\"ud\":\"" + to_hex(t.ud) + "\"" +
         ",\"scts\":\"" + to_hex(t.scts) + "\",\"dt\":\"" + to_hex(t.dt) + "\",\"st\":" + std::to_string(t.st) +
         ",\"vp\":\"" + to_hex(t.vp) + "\",\"ct\":" + std::to_string(t.ct) + ",\"mn\":" + std::to_string(t.mn);
    s += std::string(",\"has_pid\":") + (t.has_pid ? "true" : "false") + ",\"has_dcs\":" +
         (t.has_dcs ? "true" : "false") + ",\"has_ud\":" + (t.has_ud ? "true" : "false");
    if (t.fcs) {
        s += ",\"fcs\":" + std::to_string(*t.fcs);
    }
    if (t.pi) {
        s += ",\"pi\":" + std::to_string(*t.pi);
    }
    if (!t.pi_more.empty()) {
        s += ",\"pi_more\":\"" + to_hex(t.pi_more) + "\"";
    }
    if (!t.discarded.empty()) {
        s += ",\"discarded\":\"" + to_hex(t.discarded) + "\"";
    }
    // 9.2.3.27: TP-UDL present without TP-DCS means the default alphabet (0x00)
    if (t.has_ud && t.type != TpduType::command && (!t.has_dcs || dcs_is_gsm7(t.dcs)) && !t.udhi()) {
        std::string text = gsm7_to_utf8(t.ud, t.udl);
        std::string esc;
        for (char ch : text) {
            if (ch == '"' || ch == '\\') {
                esc += '\\';
            }
            if (static_cast<unsigned char>(ch) < 0x20) {
                esc += ' ';
                continue;
            }
            esc += ch;
        }
        s += ",\"text\":\"" + esc + "\"";
    }
    return s + "}";
}

} // namespace ksim::sms
