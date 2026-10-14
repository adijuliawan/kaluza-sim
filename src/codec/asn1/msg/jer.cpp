// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/msg/jer.hpp"

namespace ksim::jer {

std::string hex(ByteView v) { return to_hex(v); }

std::string bits(std::uint64_t value, unsigned n) {
    const unsigned octets = (n + 7) / 8;
    const std::uint64_t v = value << (octets * 8 - n);
    Bytes b(octets);
    for (unsigned i = 0; i < octets; ++i) {
        b[i] = static_cast<std::uint8_t>(v >> (8 * (octets - 1 - i)));
    }
    return hex(b);
}

json var_bits(std::uint64_t value, unsigned n) { return {{"value", bits(value, n)}, {"length", n}}; }

unsigned bits_length(const json& j) { return j.is_object() ? j.at("length").get<unsigned>() : 0; }

std::uint64_t read_bits(const json& j, unsigned n) {
    const std::string s = j.is_object() ? j.at("value").get<std::string>() : j.get<std::string>();
    if (n == 0) {
        n = bits_length(j);
    }
    auto b = from_hex(s);
    if (!b || b->size() > 8 || b->size() * 8 < n) {
        throw json::other_error::create(501, "bad bit string", &j);
    }
    std::uint64_t v = 0;
    for (std::uint8_t o : *b) {
        v = (v << 8) | o;
    }
    return v >> (b->size() * 8 - n);
}

Bytes read_octets(const json& j) {
    auto b = from_hex(j.get<std::string>());
    if (!b) {
        throw json::other_error::create(501, "bad octet string", &j);
    }
    return std::move(*b);
}

void wipe(std::string& s) noexcept {
    volatile char* p = s.data();
    for (std::size_t i = 0; i < s.size(); ++i) {
        p[i] = 0;
    }
}

void scrub(json& j) {
    if (j.is_string()) {
        wipe(j.get_ref<std::string&>());
    } else if (j.is_structured()) {
        for (auto& v : j) {
            scrub(v);
        }
    }
}

Result<Bytes> encode(const asn_TYPE_descriptor_t& td, json j, asn1::Rules rules) {
    std::string text = j.dump();
    scrub(j);
    auto v = asn1::from_jer(td, text);
    wipe(text);
    if (!v) {
        return v.error();
    }
    return asn1::encode(v.value(), rules, asn1::Check::strict);
}

Result<json> decode(const asn_TYPE_descriptor_t& td, ByteView in, asn1::Rules rules) {
    auto v = asn1::decode(td, rules, in);
    if (!v) {
        return v.error();
    }
    auto s = asn1::to_jer(v.value());
    if (!s) {
        return s.error();
    }
    json j = json::parse(*s, nullptr, false);
    wipe(*s);
    if (j.is_discarded()) {
        return unread("the JER of a decoded value did not parse");
    }
    return j;
}

std::pair<std::string, const json*> arm(const json& choice) {
    if (!choice.is_object() || choice.size() != 1) {
        throw json::other_error::create(501, "not a CHOICE", &choice);
    }
    return {choice.begin().key(), &choice.begin().value()};
}

Error bad(const char* what) { return Error{Errc::invalid_argument, 0, what}; }
Error unread(const char* what) { return Error{Errc::malformed, 0, what}; }

} // namespace ksim::jer
