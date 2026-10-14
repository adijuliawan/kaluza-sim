// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/uicc/apdu.hpp"

#include <string_view>

namespace ksim::uicc {

namespace {

Error err(Errc c, std::size_t off, const char* what) {
    return make_error(c, static_cast<std::uint32_t>(off), what);
}

std::string hex2(std::uint32_t v) {
    static constexpr char kDigits[] = "0123456789abcdef";
    return {kDigits[(v >> 4) & 0xF], kDigits[v & 0xF]};
}

} // namespace

ApduCase apdu_case(const Command& c) noexcept {
    if (c.data.empty()) {
        return c.le ? ApduCase::two : ApduCase::one;
    }
    return c.le ? ApduCase::four : ApduCase::three;
}

Result<Command> decode_command(ByteView in) {
    if (in.size() < 4) {
        return err(Errc::truncated, in.size(), "APDU: shorter than CLA INS P1 P2");
    }
    Command c{in[0], in[1], in[2], in[3], {}, std::nullopt};
    if (in.size() == 4) {
        return c;   // case 1
    }
    const std::size_t b5 = in[4];
    if (in.size() == 5) {
        c.le = b5 == 0 ? 256 : static_cast<std::uint16_t>(b5);   // case 2
        return c;
    }
    if (b5 == 0) {
        return err(Errc::unsupported, 4, "APDU: extended length (not in TS 102 221)");
    }
    if (in.size() < 5 + b5) {
        return err(Errc::truncated, 4, "APDU: Lc runs past the end");
    }
    c.data.assign(in.begin() + 5, in.begin() + static_cast<std::ptrdiff_t>(5 + b5));
    if (in.size() == 5 + b5) {
        return c;   // case 3
    }
    if (in.size() == 6 + b5) {
        c.le = in[5 + b5] == 0 ? 256 : static_cast<std::uint16_t>(in[5 + b5]);   // case 4
        return c;
    }
    return err(Errc::malformed, 6 + b5, "APDU: octets after Le");
}

Result<Bytes> encode_command(const Command& c) {
    if (c.data.size() > 255) {
        return err(Errc::overflow, 4, "APDU: more than 255 command octets");
    }
    if (c.le && (*c.le == 0 || *c.le > 256)) {
        return err(Errc::invalid_argument, 4, "APDU: Le outside 1-256");
    }
    ByteWriter w(6 + c.data.size());
    w.u8(c.cla);
    w.u8(c.ins);
    w.u8(c.p1);
    w.u8(c.p2);
    if (!c.data.empty()) {
        w.u8(static_cast<std::uint8_t>(c.data.size()));
        w.bytes(c.data);
    }
    if (c.le) {
        w.u8(static_cast<std::uint8_t>(*c.le == 256 ? 0 : *c.le));
    }
    return std::move(w).take();
}

Result<Response> decode_response(ByteView in) {
    if (in.size() < 2) {
        return err(Errc::truncated, in.size(), "R-APDU: no status word");
    }
    Response r;
    r.data.assign(in.begin(), in.end() - 2);
    r.sw1 = in[in.size() - 2];
    r.sw2 = in[in.size() - 1];
    return r;
}

Bytes encode_response(const Response& r) {
    Bytes out = r.data;
    out.push_back(r.sw1);
    out.push_back(r.sw2);
    return out;
}

Result<ClaInfo> decode_cla(std::uint8_t cla) {
    const unsigned hi = cla >> 4;
    if ((cla & 0x10) != 0) {
        return err(Errc::unsupported, 0, "CLA: command chaining (b5) is not supported");
    }
    if (hi == 0x0 || hi == 0x8 || hi == 0xA) {   // table 10.3: channels 0-3
        const auto coding = hi == 0x0 ? ClaInfo::Coding::interindustry
                          : hi == 0x8 ? ClaInfo::Coding::uicc
                                      : ClaInfo::Coding::gsm;
        return ClaInfo{coding, static_cast<std::uint8_t>(cla & 0x03), static_cast<std::uint8_t>((cla >> 2) & 0x03)};
    }
    if ((cla & 0x40) != 0) {   // table 10.4a: '01x0 xxxx' and '11x0 xxxx' (b5 was refused above)
        const auto coding = (cla & 0x80) != 0 ? ClaInfo::Coding::uicc : ClaInfo::Coding::interindustry;
        return ClaInfo{coding, static_cast<std::uint8_t>((cla & 0x0F) + 4), static_cast<std::uint8_t>((cla >> 5) & 0x01)};
    }
    return err(Errc::malformed, 0, "CLA: not a class byte of TS 102 221");
}

const char* command_name(std::uint8_t cla, std::uint8_t ins) noexcept {
    auto info = decode_cla(cla);
    if (!info) {
        return nullptr;
    }
    const bool iso = info->coding == ClaInfo::Coding::interindustry;
    const bool uicc = info->coding == ClaInfo::Coding::uicc;
    switch (ins) {
    case 0xA4: return iso ? "SELECT FILE" : nullptr;
    case 0xF2: return uicc ? "STATUS" : nullptr;
    case 0xB0: return iso ? "READ BINARY" : nullptr;
    case 0xD6: return iso ? "UPDATE BINARY" : nullptr;
    case 0xB2: return iso ? "READ RECORD" : nullptr;
    case 0xDC: return iso ? "UPDATE RECORD" : nullptr;
    case 0xA2: return iso ? "SEARCH RECORD" : nullptr;
    case 0x32: return uicc ? "INCREASE" : nullptr;
    case 0xCB: return uicc ? "RETRIEVE DATA" : nullptr;
    case 0xDB: return uicc ? "SET DATA" : nullptr;
    case 0x20: return iso ? "VERIFY PIN" : nullptr;
    case 0x24: return iso ? "CHANGE PIN" : nullptr;
    case 0x26: return iso ? "DISABLE PIN" : nullptr;
    case 0x28: return iso ? "ENABLE PIN" : nullptr;
    case 0x2C: return iso ? "UNBLOCK PIN" : nullptr;
    case 0x04: return iso ? "DEACTIVATE FILE" : nullptr;
    case 0x44: return iso ? "ACTIVATE FILE" : nullptr;
    case 0x88:
    case 0x89: return iso ? "AUTHENTICATE" : nullptr;
    case 0x84: return iso ? "GET CHALLENGE" : nullptr;
    case 0xAA: return uicc ? "TERMINAL CAPABILITY" : nullptr;
    case 0x10: return cla == 0x80 ? "TERMINAL PROFILE" : nullptr;
    case 0xC2: return cla == 0x80 ? "ENVELOPE" : nullptr;
    case 0x12: return cla == 0x80 ? "FETCH" : nullptr;
    case 0x14: return cla == 0x80 ? "TERMINAL RESPONSE" : nullptr;
    case 0x70: return iso ? "MANAGE CHANNEL" : nullptr;
    case 0x73: return iso ? "MANAGE SECURE CHANNEL" : nullptr;
    case 0x75: return iso ? "TRANSACT DATA" : nullptr;
    case 0x76: return cla == 0x80 ? "SUSPEND UICC" : nullptr;
    case 0x78: return uicc ? "GET IDENTITY" : nullptr;
    case 0x7A: return cla == 0x80 ? "EXCHANGE CAPABILITIES" : nullptr;
    case 0x7C: return cla == 0x80 ? "MANAGE LSI" : nullptr;
    case 0xC0: return iso ? "GET RESPONSE" : nullptr;
    default: return nullptr;
    }
}

const char* status_meaning(std::uint8_t sw1, std::uint8_t sw2) noexcept {
    switch (sw1) {
    case 0x90: return sw2 == 0 ? "normal ending of the command" : nullptr;
    case 0x91: return "normal ending, with extra information from the proactive UICC";
    case 0x92: return "normal ending, with extra information concerning an ongoing data transfer session";
    case 0x93: return "SIM Application Toolkit is busy";
    case 0x61: return "response bytes still available (GET RESPONSE)";
    case 0x62: return "warning: state of non-volatile memory unchanged";
    case 0x63: return (sw2 & 0xF0) == 0xC0 ? "verification failed, retries left in SW2 b4-b1"
                                           : "warning: state of non-volatile memory changed";
    case 0x64: return "execution error: state of non-volatile memory unchanged";
    case 0x65: return "execution error: state of non-volatile memory changed";
    case 0x67: return sw2 == 0 ? "wrong length" : "wrong length (SW2 indicates the length)";
    case 0x68: return "functions in CLA not supported";
    case 0x69: return "command not allowed";
    case 0x6A: return "wrong parameters";
    case 0x6B: return "wrong parameter(s) P1-P2";
    case 0x6C: return "wrong Le field (SW2 is the right length)";
    case 0x6D: return "instruction code not supported or invalid";
    case 0x6E: return "class not supported";
    case 0x6F: return "technical problem, no precise diagnosis";
    case 0x98: return "security management (TS 31.102 application errors)";
    default: return nullptr;
    }
}

// ---- AUTHENTICATE ------------------------------------------------------------------------

Result<AuthChallenge> decode_auth_challenge(ByteView d, AuthContext ctx) {
    ByteReader r(d);
    AuthChallenge a;
    auto l1 = r.u8();
    if (!l1) {
        return err(Errc::truncated, 0, "AUTHENTICATE: no RAND length");
    }
    auto rand = r.take(*l1);
    if (!rand) {
        return err(Errc::truncated, 1, "AUTHENTICATE: RAND runs past the end");
    }
    a.rand.assign(rand->begin(), rand->end());
    if (ctx == AuthContext::umts) {
        auto l2 = r.u8();
        if (!l2) {
            return err(Errc::truncated, r.offset(), "AUTHENTICATE: no AUTN length");
        }
        auto autn = r.take(*l2);
        if (!autn) {
            return err(Errc::truncated, r.offset(), "AUTHENTICATE: AUTN runs past the end");
        }
        a.autn.assign(autn->begin(), autn->end());
    }
    if (!r.empty()) {
        return err(Errc::malformed, r.offset(), "AUTHENTICATE: octets after the challenge");
    }
    return a;
}

Bytes encode_auth_challenge(const AuthChallenge& a, AuthContext ctx) {
    Bytes out{static_cast<std::uint8_t>(a.rand.size())};
    out.insert(out.end(), a.rand.begin(), a.rand.end());
    if (ctx == AuthContext::umts) {
        out.push_back(static_cast<std::uint8_t>(a.autn.size()));
        out.insert(out.end(), a.autn.begin(), a.autn.end());
    }
    return out;
}

namespace {
Result<Span> lv(ByteReader& r, const char* what) {
    auto l = r.u8();
    if (!l) {
        return err(Errc::truncated, r.offset(), what);
    }
    const std::size_t at = r.offset();
    if (!r.take(*l)) {
        return err(Errc::truncated, r.offset(), what);
    }
    return Span{at, *l};
}

Bytes copy(ByteView d, Span s) {
    const ByteView v = s.in(d);
    return {v.begin(), v.end()};
}

void put_lv(Bytes& out, ByteView v) {
    out.push_back(static_cast<std::uint8_t>(v.size()));
    out.insert(out.end(), v.begin(), v.end());
}
} // namespace

Result<AuthResult> decode_auth_result(ByteView d, AuthContext ctx) {
    ByteReader r(d);
    AuthResult a;
    if (ctx == AuthContext::gsm) {
        a.kind = AuthResult::Kind::gsm;
        auto sres = lv(r, "AUTHENTICATE: SRES");
        auto kc = sres ? lv(r, "AUTHENTICATE: Kc") : Result<Span>(sres.error());
        if (!kc) {
            return kc.error();
        }
        a.res = copy(d, *sres);
        a.kc = *kc;
    } else {
        auto tag = r.u8();
        if (!tag) {
            return err(Errc::truncated, 0, "AUTHENTICATE: empty response");
        }
        if (*tag == 0xDC) {
            a.kind = AuthResult::Kind::sync_failure;
            auto auts = lv(r, "AUTHENTICATE: AUTS");
            if (!auts) {
                return auts.error();
            }
            a.auts = copy(d, *auts);
        } else if (*tag == 0xDB) {
            auto res = lv(r, "AUTHENTICATE: RES");
            auto ck = res ? lv(r, "AUTHENTICATE: CK") : Result<Span>(res.error());
            auto ik = ck ? lv(r, "AUTHENTICATE: IK") : Result<Span>(ck.error());
            if (!ik) {
                return ik.error();
            }
            a.res = copy(d, *res);
            a.ck = *ck;
            a.ik = *ik;
            if (!r.empty()) {   // Kc, when service n°27 is available
                auto kc = lv(r, "AUTHENTICATE: Kc");
                if (!kc) {
                    return kc.error();
                }
                a.kc = *kc;
            }
        } else {
            return err(Errc::malformed, 0, "AUTHENTICATE: response tag is neither 'DB' nor 'DC'");
        }
    }
    if (!r.empty()) {
        return err(Errc::malformed, r.offset(), "AUTHENTICATE: octets after the response");
    }
    return a;
}

Bytes encode_auth_success(ByteView res, ByteView ck, ByteView ik, ByteView kc) {
    Bytes out{0xDB};
    put_lv(out, res);
    put_lv(out, ck);
    put_lv(out, ik);
    if (!kc.empty()) {
        put_lv(out, kc);
    }
    return out;
}

Bytes encode_auth_sync_failure(ByteView auts) {
    Bytes out{0xDC};
    put_lv(out, auts);
    return out;
}

Bytes encode_auth_gsm(ByteView sres, ByteView kc) {
    Bytes out;
    put_lv(out, sres);
    put_lv(out, kc);
    return out;
}

// ---- JSON ------------------------------------------------------------------------------

namespace {

std::string params(const Command& c, std::string_view name) {
    std::string s;
    const auto num = [&s](const char* k, unsigned v) { s += std::string(",\"") + k + "\":" + std::to_string(v); };
    if (name == "SELECT FILE") {
        num("selection", c.p1);   // table 11.1
        s += std::string(",\"return\":\"") +
             ((c.p2 & 0x0C) == 0x04 ? "fcp" : (c.p2 & 0x0C) == 0x0C ? "none" : "other") + "\"";
        if (c.p1 == 0x04) {
            num("occurrence", c.p2 & 0x03);
        }
    } else if (name == "READ BINARY" || name == "UPDATE BINARY") {
        if ((c.p1 & 0x80) != 0) {   // table 11.10
            num("sfi", c.p1 & 0x1F);
            num("offset", c.p2);
        } else {
            num("offset", ((c.p1 & 0x7Fu) << 8) | c.p2);
        }
    } else if (name == "READ RECORD" || name == "UPDATE RECORD" || name == "SEARCH RECORD") {
        num("record", c.p1);   // tables 11.11, 11.12
        num("sfi", c.p2 >> 3);
        num("mode", c.p2 & 0x07);
    } else if (name == "VERIFY PIN" || name == "CHANGE PIN" || name == "DISABLE PIN" || name == "ENABLE PIN" ||
               name == "UNBLOCK PIN") {
        num("key_reference", c.p2);   // table 11.15: the data are PIN values, shown by length only
    } else if (name == "MANAGE CHANNEL") {
        s += std::string(",\"operation\":\"") + (c.p1 == 0x00 ? "open" : c.p1 == 0x80 ? "close" : "rfu") + "\"";
        num("channel", c.p2);
    } else if (name == "STATUS") {
        num("application_status", c.p1);
        num("return", c.p2);
    } else if (name == "AUTHENTICATE") {
        num("context", c.p2 & 0x07);
        num("specific", c.p2 >> 7);
    } else if (name == "GET IDENTITY") {
        num("identity_context", c.p2 & 0x7F);
    }
    return s;
}

bool secret_data(std::string_view name) {
    return name == "VERIFY PIN" || name == "CHANGE PIN" || name == "DISABLE PIN" || name == "ENABLE PIN" ||
           name == "UNBLOCK PIN";
}

} // namespace

std::string to_json(const Command& c, const Response* r) {
    const char* nm = command_name(c.cla, c.ins);
    const std::string_view name = nm != nullptr ? nm : "";
    std::string s = "{\"protocol\":\"apdu\",\"command\":\"" + std::string(name) + "\",\"cla\":" +
                    std::to_string(c.cla) + ",\"ins\":" + std::to_string(c.ins) + ",\"p1\":" + std::to_string(c.p1) +
                    ",\"p2\":" + std::to_string(c.p2) + ",\"case\":" +
                    std::to_string(static_cast<unsigned>(apdu_case(c)));
    if (auto info = decode_cla(c.cla); info) {
        s += ",\"channel\":" + std::to_string(info->channel) + ",\"sm\":" + std::to_string(info->secure_messaging);
    }
    s += params(c, name);
    if (secret_data(name)) {
        s += ",\"data_len\":" + std::to_string(c.data.size());
    } else {
        s += ",\"data\":\"" + to_hex(c.data) + "\"";
    }
    if (c.le) {
        s += ",\"le\":" + std::to_string(*c.le);
    }
    const AuthContext ctx = (c.p2 & 0x07) == 0 ? AuthContext::gsm : AuthContext::umts;
    if (name == "AUTHENTICATE" && c.ins == 0x88) {
        if (auto a = decode_auth_challenge(c.data, ctx); a) {
            s += ",\"rand\":\"" + to_hex(a->rand) + "\",\"autn\":\"" + to_hex(a->autn) + "\"";
        }
    }
    if (r != nullptr) {
        s += ",\"sw\":\"" + hex2(r->sw1) + hex2(r->sw2) + "\"";
        if (name == "AUTHENTICATE" && c.ins == 0x88 && r->sw1 == 0x90) {
            if (auto a = decode_auth_result(r->data, ctx); a) {
                s += std::string(",\"auth\":\"") +
                     (a->kind == AuthResult::Kind::success ? "success"
                      : a->kind == AuthResult::Kind::sync_failure ? "sync_failure" : "gsm") +
                     "\",\"res\":\"" + to_hex(a->res) + "\",\"auts\":\"" + to_hex(a->auts) +
                     "\",\"ck_len\":" + std::to_string(a->ck.len) + ",\"ik_len\":" + std::to_string(a->ik.len) +
                     ",\"kc_len\":" + std::to_string(a->kc.len);
            } else {
                s += ",\"auth_error\":\"" + std::string(a.error().what) + "\"";
            }
            s += ",\"rsp_len\":" + std::to_string(r->data.size());
        } else if (name == "GET RESPONSE" && !r->data.empty() && r->data[0] == 0xDB) {
            s += ",\"rsp_len\":" + std::to_string(r->data.size());   // an AUTHENTICATE result fetched under T=0
        } else {
            s += ",\"rsp\":\"" + to_hex(r->data) + "\"";
        }
    }
    return s + "}";
}

} // namespace ksim::uicc
