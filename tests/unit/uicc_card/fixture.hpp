// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A personalised soft card from cards/usim-5g.yaml, for the card tests (P1 N3).
// Test-only secrets: PIN1 1234, PUK1 12345678, PIN2 5678, PUK2 87654321,
// ADM1 11111111; K and OPc as each test gives them.

#pragma once

#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>
#include <string>

#include "platform/yaml.hpp"
#include "uicc/image/image.hpp"
#include "uicc/os/card.hpp"
#include "uicc/secrets/secrets.hpp"

namespace ksim::uicc::test {

inline std::string template_path() { return std::string(KSIM_SOURCE_DIR) + "/cards/usim-5g.yaml"; }

inline SecretBytes digits(const char* d) {
    return SecretBytes::copy_of(ByteView(reinterpret_cast<const std::uint8_t*>(d), std::char_traits<char>::length(d)));
}

/// A SecretBytes from hex (test values only).
inline SecretBytes sb(const char* hex) {
    auto r = SecretBytes::from_hex(hex);
    EXPECT_TRUE(r) << hex;
    return r ? std::move(*r) : SecretBytes{};
}

inline secrets::SecretMap test_secrets(const SecretBytes& k, const SecretBytes& opc) {
    secrets::SecretMap s;
    s.set("k", k.clone());
    s.set("opc", opc.clone());
    s.set("pin1", digits("1234"));
    s.set("puk1", digits("12345678"));
    s.set("pin2", digits("5678"));
    s.set("puk2", digits("87654321"));
    s.set("adm1", digits("11111111"));
    return s;
}

inline const image::Subscriber kSub{"001010000300001", "8988211000000300001", "99900300001", 2};

inline std::unique_ptr<os::Card> make_card(const secrets::SecretMap& s) {
    auto card = image::load(Yaml::load_file(template_path()), s);
    EXPECT_TRUE(image::personalise(*card, kSub));
    return card;
}

inline std::unique_ptr<os::Card> make_card() {
    return make_card(test_secrets(sb("465b5ce8b199b49faa5f0a2ee238a6bc"), sb("cd63cb71954a9f4e48a5994e37a02baf")));
}

/// The USIM ADF and a file under a DF, as references: a missing one throws.
inline os::File& usim(os::Card& card) {
    os::File* a = image::usim_adf(card);
    if (a == nullptr) {
        throw std::runtime_error("the card has no USIM");
    }
    return *a;
}
inline os::File& at(os::File& df, std::uint16_t fid) {
    os::File* f = df.child(fid);
    if (f == nullptr) {
        throw std::runtime_error("no file " + std::to_string(fid));
    }
    return *f;
}

/// One APDU in hex, the response in hex (data then SW1 SW2), upper case.
inline std::string apdu(os::Card& card, const std::string& hex) {
    auto in = from_hex(hex);
    EXPECT_TRUE(in) << hex;
    std::string out = to_hex(card.process(*in));
    for (auto& c : out) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return out;
}

inline std::string sw_of(const std::string& rapdu) { return rapdu.substr(rapdu.size() - 4); }
inline std::string data_of(const std::string& rapdu) { return rapdu.substr(0, rapdu.size() - 4); }

/// The PIN block of ASCII digits, as hex: "1234" -> "31323334FFFFFFFF".
inline std::string pin_hex(const std::string& d) {
    std::string h;
    for (char c : d) {
        static const char* hx = "0123456789ABCDEF";
        h += hx[static_cast<unsigned char>(c) >> 4];
        h += hx[static_cast<unsigned char>(c) & 0xF];
    }
    while (h.size() < 16) {
        h += "FF";
    }
    return h;
}

} // namespace ksim::uicc::test
