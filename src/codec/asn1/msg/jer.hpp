// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// What the typed builders and readers of msg/ share (P1 N6, N7): X.697 JSON
// values in the shape asn1c's JER reads and writes, encoded and decoded by
// the generated code. Internal to codec/asn1/msg.
//
// Objects keep their insertion order (asn1c's JER decoder wants SEQUENCE
// members in definition order). Every string a value held is overwritten
// before it is freed, so octets such as K_gNB do not linger in the JER text
// (row KS-NGAP-B2).

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include "codec/asn1/asn1.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::jer {

using json = nlohmann::ordered_json;

std::string hex(ByteView v);
/// A fixed-size BIT STRING: the hex of its octets, the value left-aligned.
std::string bits(std::uint64_t value, unsigned n);
/// A BIT STRING of variable or extensible size: {"value", "length"}.
json var_bits(std::uint64_t value, unsigned n);
/// The value of a BIT STRING in either form, `n` bits (the variable form's own length when n is 0).
std::uint64_t read_bits(const json& j, unsigned n = 0);
unsigned bits_length(const json& j);
Bytes read_octets(const json& j);

/// Overwrite a string, or every string in a value, in place.
void wipe(std::string& s) noexcept;
void scrub(json& j);

/// The value encoded by the generated code (strict), then scrubbed.
Result<Bytes> encode(const asn_TYPE_descriptor_t& td, json j, asn1::Rules rules);
/// Decoded by the generated code and read back as JSON (its text scrubbed).
Result<json> decode(const asn_TYPE_descriptor_t& td, ByteView in, asn1::Rules rules);

/// The single arm of a CHOICE.
std::pair<std::string, const json*> arm(const json& choice);

Error bad(const char* what);      // Errc::invalid_argument: an input the builder refuses
Error unread(const char* what);   // Errc::malformed: a field P1 reads is missing or wrong

/// Runs a reader, turning a missing or mistyped field into Errc::malformed.
/// A value the readers understand but P1 does not take (an IPv6 transport
/// address, a dynamic 5QI, …): Errc::unsupported, not malformed.
struct NotP1 : std::runtime_error {
    using std::runtime_error::runtime_error;
};

template <class F>
auto guarded(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const NotP1&) {
        return Error{Errc::unsupported, 0, "a value P1 does not take"};
    } catch (const json::exception&) {
        return unread("a field P1 reads is missing or of the wrong type");
    } catch (const std::exception&) {
        return unread("a field P1 reads is out of range");
    }
}

} // namespace ksim::jer
