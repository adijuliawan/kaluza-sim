// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// EAP packets as 5GS carries them in the EAP message IE (TS 24.501 9.11.2.2):
// the RFC 3748 header and, for EAP-AKA' (type 50, RFC 5448 / RFC 9048), the
// subtype and the attributes of RFC 4187 §8 and RFC 9048 §3.1-3.2 (P1 N12).
// Keys stay out of here: AT_MAC is computed and checked in proc/ue, which
// holds K_aut; this layer only finds where the MAC goes.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::eap {

enum class Code : std::uint8_t { request = 1, response = 2, success = 3, failure = 4 };

constexpr std::uint8_t kTypeAkaPrime = 50;   // RFC 5448 §6

/// EAP-AKA' subtypes (RFC 4187 §11, the values EAP-AKA' shares).
enum class Subtype : std::uint8_t {
    challenge = 1,
    authentication_reject = 2,
    synchronization_failure = 4,
    identity = 5,
    notification = 12,
    reauthentication = 13,
    client_error = 14,
};

/// Attribute types (RFC 4187 §11, RFC 5448 §6).
enum class Attr : std::uint8_t {
    rand = 1,
    autn = 2,
    res = 3,
    auts = 4,
    mac = 11,
    notification = 12,
    client_error_code = 22,
    kdf_input = 23,
    kdf = 24,
    checkcode = 134,
    result_ind = 135,
};

/// One attribute: its type and value, the octets after the length octet (the
/// reserved or length fields of RFC 4187 §8.1 included, padding included).
struct Attribute {
    std::uint8_t type = 0;
    Bytes value;
};

struct Packet {
    Code code = Code::request;
    std::uint8_t id = 0;
    // For request and response packets of EAP-AKA' (absent for success and failure).
    std::uint8_t type = kTypeAkaPrime;
    Subtype subtype = Subtype::challenge;
    std::vector<Attribute> attrs;

    const Attribute* find(Attr a) const;
};

/// A packet from the IE; Errc::malformed for a bad length, an attribute that
/// overruns, or a zero attribute length. Packets of other EAP types decode
/// with their type and no attributes.
Result<Packet> decode(ByteView in);
Result<Bytes> encode(const Packet& p);

// ---- attribute values (RFC 4187 §10, RFC 5448 §3.1-3.2) -----------------------------

Attribute at_rand(ByteView rand);                 // 16 octets
Attribute at_autn(ByteView autn);                 // 16 octets
Attribute at_res(ByteView res);                   // the RES, its length in bits first
Attribute at_auts(ByteView auts);                 // 14 octets
Attribute at_mac_zero();                          // 16 zero octets, filled by the caller
Attribute at_kdf(std::uint16_t kdf);
Attribute at_kdf_input(const std::string& network_name);
Attribute at_client_error_code(std::uint16_t code);

/// The 16-octet value of AT_RAND, AT_AUTN or AT_MAC; nullopt when the length is wrong.
std::optional<Bytes> value16(const Attribute& a);
std::optional<Bytes> res_of(const Attribute& a);  // the RES, cut to its bit length (whole octets)
std::optional<Bytes> auts_of(const Attribute& a);
std::optional<std::uint16_t> kdf_of(const Attribute& a);
std::optional<std::string> network_name_of(const Attribute& a);

/// Where AT_MAC's 16 value octets are in an encoded packet, if it has one.
std::optional<std::size_t> mac_offset(ByteView packet);

} // namespace ksim::eap
