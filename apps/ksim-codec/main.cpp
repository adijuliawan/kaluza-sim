// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-codec: our asn1c codecs from the command line (plan M10).
//
//   ksim-codec decode <proto> <type> <hex>    JER (pretty) of a PER encoding
//   ksim-codec encode <proto> <type> <jer>    PER hex of a JER value
//   ksim-codec types  <proto>                 every type name the registry knows
//   ksim-codec batch                          the oracle harness's protocol:
//
// batch reads one request per line, tab-separated, and answers one line each:
//
//   dec <proto> <type> <hex>  ->  OK <re-encoded hex> <minified JER>
//   enc <proto> <type> <jer>  ->  OK <hex> <minified JER of the decoded hex>
//   (failure)                 ->  ERR <stage> <message>
//
// <proto> is rrc (UPER) or ngap, f1ap, e1ap, xnap (APER), or for dec only nas,
// sms-cp, sms-rp, sms-tpdu-mo, sms-tpdu-mt (plan M11), gtpu, psc, nru, apdu
// (<payload> is the command, then '/' and the response) and fcp (plan M12). ASN.1 encoding is
// asn1::Check::relay: what decodes re-encodes, extension values included.

#include <cstdio>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "codec/asn1/asn1.hpp"
#include "codec/asn1/registry.hpp"
#include "codec/nas/nas.hpp"
#include "codec/nas/sms.hpp"
#include "codec/uicc/apdu.hpp"
#include "codec/uicc/fcp.hpp"
#include "codec/up/frames.hpp"
#include "codec/up/gtpu.hpp"
#include "platform/buf.hpp"

using namespace ksim;

namespace {

std::vector<std::string> split_tabs(const std::string& line, std::size_t max_fields) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (out.size() + 1 < max_fields) {
        const std::size_t tab = line.find('\t', start);
        if (tab == std::string::npos) {
            break;
        }
        out.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }
    out.push_back(line.substr(start));
    return out;
}

std::string error_text(const Error& e, std::string_view stage) {
    return "ERR\t" + std::string(stage) + "\t" + errc_name(e.code) + " at " + std::to_string(e.offset) + ": " +
           e.what;
}

/// dec: PER -> value -> PER again and JER.
std::string do_decode(std::string_view proto, std::string_view type, std::string_view hex) {
    const asn_TYPE_descriptor_t* td = asn1::find_type(proto, type);
    if (td == nullptr) {
        return "ERR\ttype\tunknown " + std::string(proto) + " type " + std::string(type);
    }
    auto bytes = from_hex(hex);
    if (!bytes) {
        return error_text(bytes.error(), "hex");
    }
    const asn1::Rules rules = asn1::rules_for(proto);
    auto v = asn1::decode(*td, rules, *bytes);
    if (!v) {
        return error_text(v.error(), "decode");
    }
    auto again = asn1::encode(*v, rules, asn1::Check::relay);
    if (!again) {
        std::string why;
        (void)asn1::check_constraints(v->type(), v->get(), &why);
        return error_text(again.error(), "reencode") + (why.empty() ? "" : " (" + why + ")");
    }
    auto jer = asn1::to_jer(*v, true);
    if (!jer) {
        return error_text(jer.error(), "jer");
    }
    return "OK\t" + to_hex(*again) + "\t" + *jer;
}

/// enc: JER -> value -> PER, and the JER of that PER read back.
std::string do_encode(std::string_view proto, std::string_view type, std::string_view jer) {
    const asn_TYPE_descriptor_t* td = asn1::find_type(proto, type);
    if (td == nullptr) {
        return "ERR\ttype\tunknown " + std::string(proto) + " type " + std::string(type);
    }
    auto v = asn1::from_jer(*td, jer);
    if (!v) {
        return error_text(v.error(), "jer-decode");
    }
    const asn1::Rules rules = asn1::rules_for(proto);
    auto bytes = asn1::encode(*v, rules, asn1::Check::relay);
    if (!bytes) {
        std::string why;
        (void)asn1::check_constraints(v->type(), v->get(), &why);
        return error_text(bytes.error(), "encode") + (why.empty() ? "" : " (" + why + ")");
    }
    auto back = asn1::decode(*td, rules, *bytes);
    if (!back) {
        return error_text(back.error(), "decode-back");
    }
    auto jer2 = asn1::to_jer(*back, true);
    if (!jer2) {
        return error_text(jer2.error(), "jer");
    }
    return "OK\t" + to_hex(*bytes) + "\t" + *jer2;
}

/// dec for the hand-written codecs: <proto> is nas, sms-cp, sms-rp, sms-tpdu-mo
/// (MS to SC) or sms-tpdu-mt (SC to MS); <type> is ignored ("-") except that
/// "rp-error" marks a TPDU carried in an RP-ERROR.
std::string do_decode_l3(std::string_view proto, std::string_view type, std::string_view hex) {
    auto bytes = from_hex(hex);
    if (!bytes) {
        return error_text(bytes.error(), "hex");
    }
    if (proto == "nas") {
        if (nas::is_protected(*bytes)) {
            auto p = nas::decode_protected(*bytes);
            if (!p) {
                return error_text(p.error(), "decode");
            }
            const Bytes again = nas::encode_protected(*p);
            return "OK\t" + to_hex(again) + "\t{\"message\":\"SECURITY PROTECTED 5GS NAS MESSAGE\",\"sht\":" +
                   std::to_string(p->security_header_type) + ",\"sqn\":" + std::to_string(p->sequence_number) +
                   ",\"payload\":\"" + to_hex(p->payload) + "\"}";
        }
        auto m = nas::decode(*bytes);
        if (!m) {
            return error_text(m.error(), "decode");
        }
        auto again = nas::encode(*m);
        if (!again) {
            return error_text(again.error(), "reencode");
        }
        return "OK\t" + to_hex(*again) + "\t" + nas::to_json(*m);
    }
    if (proto == "sms-cp") {
        auto cp = sms::decode_cp(*bytes);
        return cp ? "OK\t" + to_hex(sms::encode_cp(*cp)) + "\t" + sms::to_json(*cp) : error_text(cp.error(), "decode");
    }
    if (proto == "sms-rp") {
        auto rp = sms::decode_rp(*bytes);
        return rp ? "OK\t" + to_hex(sms::encode_rp(*rp)) + "\t" + sms::to_json(*rp) : error_text(rp.error(), "decode");
    }
    const auto dir = proto == "sms-tpdu-mo" ? sms::TpDir::ms_to_sc : sms::TpDir::sc_to_ms;
    auto t = sms::decode_tpdu(*bytes, dir, type == "rp-error");
    return t ? "OK\t" + to_hex(sms::encode_tpdu(*t)) + "\t" + sms::to_json(*t) : error_text(t.error(), "decode");
}

/// dec for the M12 codecs: gtpu, psc, nru, apdu ("<command hex>/<response hex>",
/// the response optional) and fcp.
std::string do_decode_m12(std::string_view proto, std::string_view hex) {
    if (proto == "apdu") {
        const auto slash = hex.find('/');
        auto cmd = from_hex(hex.substr(0, slash));
        if (!cmd) {
            return error_text(cmd.error(), "hex");
        }
        auto c = uicc::decode_command(*cmd);
        if (!c) {
            return error_text(c.error(), "decode");
        }
        auto again = uicc::encode_command(*c);
        if (!again) {
            return error_text(again.error(), "reencode");
        }
        std::string out = "OK\t" + to_hex(*again);
        if (slash == std::string_view::npos) {
            return out + "\t" + uicc::to_json(*c, nullptr);
        }
        auto rsp = from_hex(hex.substr(slash + 1));
        if (!rsp) {
            return error_text(rsp.error(), "hex");
        }
        auto r = uicc::decode_response(*rsp);
        if (!r) {
            return error_text(r.error(), "decode");
        }
        return out + "/" + to_hex(uicc::encode_response(*r)) + "\t" + uicc::to_json(*c, &*r);
    }
    auto bytes = from_hex(hex);
    if (!bytes) {
        return error_text(bytes.error(), "hex");
    }
    if (proto == "gtpu") {
        auto p = gtpu::decode(*bytes);
        if (!p) {
            return error_text(p.error(), "decode");
        }
        auto again = gtpu::encode(*p);
        return again ? "OK\t" + to_hex(*again) + "\t" + gtpu::to_json(*p) : error_text(again.error(), "reencode");
    }
    if (proto == "fcp") {
        auto f = uicc::decode_fcp(*bytes);
        if (!f) {
            return error_text(f.error(), "decode");
        }
        auto again = uicc::encode_fcp(*f);
        return again ? "OK\t" + to_hex(*again) + "\t" + uicc::to_json(*f) : error_text(again.error(), "reencode");
    }
    const auto p = proto == "psc" ? up::Protocol::psc : up::Protocol::nru;
    auto f = up::decode(p, *bytes);
    if (!f) {
        return error_text(f.error(), "decode");
    }
    auto again = up::encode(*f);
    return again ? "OK\t" + to_hex(*again) + "\t" + up::to_json(*f) : error_text(again.error(), "reencode");
}

bool l3_protocol(std::string_view proto) {
    return proto == "nas" || proto == "sms-cp" || proto == "sms-rp" || proto == "sms-tpdu-mo" ||
           proto == "sms-tpdu-mt";
}

bool m12_protocol(std::string_view proto) {
    return proto == "gtpu" || proto == "psc" || proto == "nru" || proto == "apdu" || proto == "fcp";
}

/// A reply on one line of valid UTF-8: asn1c's JER copies a character
/// string's octets as they are, so on hostile input a control character is
/// escaped and an octet that is not UTF-8 becomes U+FFFD (found by M14's
/// fuzz corpora). The two tabs that separate the fields stay.
std::string one_line(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    int tabs = 0;
    for (std::size_t i = 0; i < in.size();) {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c == '\t' && tabs < 2) {
            out += '\t';
            ++tabs;
            ++i;
        } else if (c < 0x20) {
            static constexpr char kHex[] = "0123456789abcdef";
            out += "\\u00";
            out += kHex[c >> 4];
            out += kHex[c & 0xF];
            ++i;
        } else if (c < 0x80) {
            out += static_cast<char>(c);
            ++i;
        } else {
            const std::size_t n = c >= 0xF0 && c < 0xF5 ? 4 : c >= 0xE0 ? 3 : c >= 0xC2 && c < 0xE0 ? 2 : 0;
            bool ok = n != 0 && i + n <= in.size();
            for (std::size_t k = 1; ok && k < n; ++k) {
                ok = (static_cast<unsigned char>(in[i + k]) & 0xC0) == 0x80;
            }
            if (ok) {
                out.append(in, i, n);
                i += n;
            } else {
                out += "\xEF\xBF\xBD";
                ++i;
            }
        }
    }
    return out;
}

int batch() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }
        const auto f = split_tabs(line, 4);
        std::string out;
        if (f.size() != 4) {
            out = "ERR\trequest\texpected <op> <proto> <type> <payload>";
        } else if (l3_protocol(f[1])) {
            out = f[0] == "dec" ? do_decode_l3(f[1], f[2], f[3]) : "ERR\trequest\tonly dec for " + f[1];
        } else if (m12_protocol(f[1])) {
            out = f[0] == "dec" ? do_decode_m12(f[1], f[3]) : "ERR\trequest\tonly dec for " + f[1];
        } else if (!asn1::known_protocol(f[1])) {
            out = "ERR\trequest\tunknown protocol " + f[1];
        } else if (f[0] == "dec") {
            out = do_decode(f[1], f[2], f[3]);
        } else if (f[0] == "enc") {
            out = do_encode(f[1], f[2], f[3]);
        } else {
            out = "ERR\trequest\tunknown op " + f[0];
        }
        std::cout << one_line(out) << '\n' << std::flush;
    }
    return 0;
}

int usage() {
    std::cerr << "usage: ksim-codec decode|encode <proto> <type> <hex|jer>\n"
                 "       ksim-codec types <proto>\n"
                 "       ksim-codec batch\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    const std::vector<std::string_view> a(argv + 1, argv + argc);
    if (a.size() == 1 && a[0] == "batch") {
        return batch();
    }
    if (a.size() == 2 && a[0] == "types") {
        if (!asn1::known_protocol(a[1])) {
            return usage();
        }
        for (const auto& e : asn1::types(a[1])) {
            std::cout << e.name << '\n';
        }
        return 0;
    }
    if (a.size() != 4 || !asn1::known_protocol(a[1])) {
        return usage();
    }
    if (a[0] == "decode") {
        const std::string r = do_decode(a[1], a[2], a[3]);
        if (!r.starts_with("OK")) {
            std::cerr << r << '\n';
            return 1;
        }
        const asn_TYPE_descriptor_t* td = asn1::find_type(a[1], a[2]);
        auto v = asn1::decode(*td, asn1::rules_for(a[1]), *from_hex(a[3]));
        std::cout << *asn1::to_jer(*v, false) << '\n';
        return 0;
    }
    if (a[0] == "encode") {
        const std::string r = do_encode(a[1], a[2], a[3]);
        if (!r.starts_with("OK")) {
            std::cerr << r << '\n';
            return 1;
        }
        std::cout << split_tabs(r, 3)[1] << '\n';
        return 0;
    }
    return usage();
}
