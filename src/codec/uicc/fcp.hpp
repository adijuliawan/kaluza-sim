// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// BER-TLV (as ETSI TS 102 221 and ISO/IEC 7816-4 use it) and the FCP template
// a SELECT returns (TS 102 221 11.1.1.3, 11.1.1.4), plan M12. Tags and length
// forms are kept as received, so encode(decode(x)) == x; the typed readers
// below cover the data objects of 11.1.1.4.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::uicc {

struct Tlv {
    std::uint32_t tag = 0;        // one to three octets, as received
    std::uint8_t tag_octets = 1;
    std::uint8_t length_octets = 1;   // 1 (short form), 2 ('81' xx), 3 ('82' xx xx)
    Bytes value;                  // a primitive object's value
    std::vector<Tlv> children;    // a constructed object's (tag bit b6 set)
    std::size_t offset = 0;       // where the object starts in the input

    bool constructed() const noexcept;
    const Tlv* find(std::uint32_t t) const noexcept;
};

/// A sequence of BER-TLV objects, constructed ones read recursively.
Result<std::vector<Tlv>> decode_ber(ByteView in);
Result<Bytes> encode_ber(const std::vector<Tlv>& objects);

struct FileDescriptor {
    std::uint8_t descriptor = 0;   // table 11.5
    std::uint8_t data_coding = 0x21;
    std::optional<std::uint16_t> record_length;   // linear fixed and cyclic EFs
    std::optional<std::uint8_t> records;

    bool shareable() const noexcept { return (descriptor & 0x40) != 0; }
    /// "df", "working_ef", "internal_ef", "rfu"
    const char* file_type() const noexcept;
    /// "none", "transparent", "linear_fixed", "cyclic", "ber_tlv", "rfu" (an EF only)
    const char* structure() const noexcept;
};

struct Fcp {
    Tlv root;   // tag '62'

    std::optional<FileDescriptor> file_descriptor() const;
    std::optional<std::uint16_t> file_id() const;
    std::optional<Bytes> df_name() const;
    std::optional<std::uint8_t> life_cycle() const;
    std::optional<std::uint64_t> file_size() const;
    std::optional<std::uint64_t> total_file_size() const;
    /// 11.1.1.4.8: tag '88' absent (the FID's low five bits), empty (no SFI:
    /// nullopt) or one octet (bits b8-b4).
    std::optional<std::uint8_t> sfi() const;
    /// Key references ('83') in the PIN status template DO ('C6').
    std::vector<std::uint8_t> pin_key_references() const;
};

Result<Fcp> decode_fcp(ByteView in);
Result<Bytes> encode_fcp(const Fcp& f);

std::string to_json(const Fcp& f);

} // namespace ksim::uicc
