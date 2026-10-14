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
// <proto> is rrc (UPER) or ngap, f1ap, e1ap, xnap (APER). Encoding is
// asn1::Check::relay: what decodes re-encodes, extension values included.

#include <cstdio>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "codec/asn1/asn1.hpp"
#include "codec/asn1/registry.hpp"
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
        } else if (!asn1::known_protocol(f[1])) {
            out = "ERR\trequest\tunknown protocol " + f[1];
        } else if (f[0] == "dec") {
            out = do_decode(f[1], f[2], f[3]);
        } else if (f[0] == "enc") {
            out = do_encode(f[1], f[2], f[3]);
        } else {
            out = "ERR\trequest\tunknown op " + f[0];
        }
        std::cout << out << '\n' << std::flush;
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
