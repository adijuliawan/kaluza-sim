// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The flag-driven user plane frames that ride in GTP-U extension headers
// (plan M12): the PDU Session Container of TS 38.415 (5.5.2, type 0x85) and
// the NR RAN Container of TS 38.425 (5.5.2, type 0x84).
//
// Both are a first octet (PDU type in bits 7-4, flags in bits 3-0), a second
// flag octet, then fields in a fixed order, each present when a flag bit is
// set; some fields are themselves further flag octets, and some are a count
// followed by that many blocks. A table per PDU type drives one decoder and
// one encoder. Fields are octets (big-endian numbers); what follows the last
// field (Future Extension and padding to 4n-2 octets) is kept as received.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::up {

enum class Protocol : std::uint8_t { psc, nru };   // TS 38.415, TS 38.425

struct FieldSpec {
    const char* name;           // as the frame figure names it
    std::uint8_t flag_octet;    // index into the frame's flag octets; kAlways: no flag
    std::uint8_t flag_bit;      // 0..7
    std::uint8_t size;          // octets; for a block list, the size of its count
    std::uint8_t block = 0;     // a block list: octets per block after the count
    bool flags = false;         // the field is itself a further flag octet

    static constexpr std::uint8_t kAlways = 0xFF;
};

struct FrameSpec {
    Protocol protocol;
    std::uint8_t pdu_type;
    const char* name;
    std::span<const FieldSpec> fields;
};

/// The frame layout for a protocol and PDU type, or nullptr.
const FrameSpec* find_frame(Protocol p, std::uint8_t pdu_type) noexcept;

struct Field {
    const FieldSpec* spec = nullptr;
    Bytes octets;               // a block list: the count octet(s) then the blocks
    std::size_t offset = 0;     // where it starts in the frame
};

struct Frame {
    const FrameSpec* spec = nullptr;
    std::vector<std::uint8_t> flags;   // octet 1, octet 2, then each flag octet field, as received
    std::vector<Field> fields;         // present fields in frame order (flag octet fields excluded)
    std::optional<Bytes> tail;         // after the last field; nullopt: encode() pads to 4n-2

    /// A present field by its figure name.
    const Field* find(std::string_view name) const noexcept;
    /// A present field's value as a number (fields of 8 octets or fewer).
    std::optional<std::uint64_t> value(std::string_view name) const noexcept;
};

Result<Frame> decode(Protocol p, ByteView in);
Result<Bytes> encode(const Frame& f);

/// A frame to build: flag octets zero but for the PDU type, no fields.
Result<Frame> make(Protocol p, std::uint8_t pdu_type);
/// Set a field (numeric, or a block list given as octets after the count) and
/// the flag bit that announces it. Flag-only bits are set with set_flag.
Result<void> set(Frame& f, std::string_view name, std::uint64_t value);
Result<void> set_blocks(Frame& f, std::string_view name, ByteView blocks);
Result<void> set_flag(Frame& f, std::uint8_t octet, std::uint8_t bit, bool on = true);

std::string to_json(const Frame& f);

} // namespace ksim::up
