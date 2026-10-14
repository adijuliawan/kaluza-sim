// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// 5GS NAS messages (TS 24.501, framing per TS 24.007 clause 11), driven by the
// generated tables (nas_tables.hpp).
//
// decode() reads a plain 5GMM or 5GSM message: the imperative part in table
// order (half-octet IEs paired low nibble first), then the non-imperative part
// by IEI. An IE whose IEI the message does not know is skipped by the TS 24.007
// 11.2.4 rules (bit 8 set: one octet; 0x70-0x7F: TLV-E; else TLV), unless it is
// "comprehension required" (TLV 0x00-0x0F, TLV-E 0x7E-0x7F), which is an error
// (TS 24.501 7.5.1). A repeated IE is marked, and only the first counts (7.6.3).
// Unknown and repeated IEs are kept as received, so encode() of a decoded
// message gives back the same octets.
//
// IE contents are octets here; typed IE accessors come with the entities (P1).

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "codec/nas/nas_tables.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::nas {

struct Ie {
    const IeDesc* desc = nullptr;  // nullptr: an IE the message does not know
    std::uint8_t iei = 0;          // as received (0 in the imperative part)
    Bytes value;                   // contents; a half-octet value or type 1 value in the low 4 bits
    Bytes raw;                     // an unknown IE, whole as received
    bool repeated = false;         // a later occurrence of an IE already seen (ignored, 7.6.3)
    bool out_of_range = false;     // an optional IE whose length the table does not allow (ignored, 7.7)
    std::size_t offset = 0;        // where the IE starts in the message (a half-octet IE: its octet)
};

struct Message {
    const MsgDesc* desc = nullptr;
    std::vector<Ie> ies;           // in received order

    /// The first occurrence of an IE by its table name, if present.
    const Ie* find(std::string_view ie_name) const noexcept;
    std::size_t unknown_count() const noexcept;
};

/// The message a plain NAS PDU's header names, or nullptr.
const MsgDesc* find_message(Epd epd, std::uint8_t type) noexcept;

/// Decode a plain 5GMM or 5GSM message.
Result<Message> decode(ByteView in);

/// Encode a message (IEs in their order in `ies`).
Result<Bytes> encode(const Message& m);

/// A security protected 5GS NAS message (TS 24.501 8.2.28, 9.1.1): the header
/// and the octets it protects (a plain NAS message when not ciphered).
struct Protected {
    std::uint8_t security_header_type = 0;  // 1..4
    std::uint8_t spare = 0;                 // bits 8-5 of octet 2, kept as received (9.3)
    std::uint32_t mac = 0;
    std::uint8_t sequence_number = 0;
    Bytes payload;
};

/// True if the octets start a security protected 5GMM message.
bool is_protected(ByteView in) noexcept;
Result<Protected> decode_protected(ByteView in);
Bytes encode_protected(const Protected& p);

/// Extended protocol configuration options contents (TS 24.501 9.11.4.6), coded
/// as the PCO of TS 24.008 10.5.6.3 from octet 3: the configuration protocol
/// octet, then protocol and container identifiers, each with its contents as
/// octets (P0 reads the container level only). A container whose identifier
/// the NOTE to figure 10.5.136 names for the direction has a two-octet length.
struct EpcoUnit {
    std::uint16_t id = 0;
    Bytes contents;
    std::size_t offset = 0;   // where the unit starts in the ePCO contents
};

struct Epco {
    std::uint8_t octet3 = 0x80;   // ext bit 8, spare, configuration protocol (bits 3-1)
    std::vector<EpcoUnit> units;
};

/// The container identifier's entry for the direction, or nullptr (a protocol
/// identifier such as 8021H IPCP, or an identifier the table does not list).
const EpcoDesc* find_epco(std::uint16_t id, Direction dir) noexcept;
Result<Epco> decode_epco(ByteView contents, Direction dir);
Result<Bytes> encode_epco(const Epco& e, Direction dir);

/// A one-line JSON summary of a message (name, then each IE with its IEI and
/// contents in hex), for ksim-codec and the oracle harness.
std::string to_json(const Message& m);

} // namespace ksim::nas
