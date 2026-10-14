// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Byte and bit buffers for codecs (architecture.md §3, rule R3: codecs are pure
// functions over spans).
//
//   ByteReader / ByteWriter: network byte order, bounds-checked; every read
//     returns Result, so truncated input is an error, never a crash.
//   BitReader / BitWriter:   MSB-first bit fields (NAS half-octets, the PDU
//     Session Container, NR-U, PDCP/SDAP headers).
//   to_hex / from_hex:       for vectors and logs of non-secret data. Secrets
//     are SecretBytes, which never converts to a ByteView implicitly.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "platform/result.hpp"

namespace ksim {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

class ByteReader {
public:
    explicit ByteReader(ByteView data) noexcept : data_(data) {}

    std::size_t offset() const noexcept { return pos_; }
    std::size_t remaining() const noexcept { return data_.size() - pos_; }
    bool empty() const noexcept { return pos_ == data_.size(); }

    Result<std::uint8_t> u8();
    Result<std::uint16_t> u16();
    Result<std::uint32_t> u24();
    Result<std::uint32_t> u32();
    Result<std::uint64_t> u64();
    /// The next n bytes as a view into the input (no copy).
    Result<ByteView> take(std::size_t n);
    /// Everything left.
    ByteView rest() noexcept;
    Result<void> skip(std::size_t n);
    /// The next byte without consuming it.
    Result<std::uint8_t> peek() const;

private:
    Error short_read(const char* what) const noexcept;

    ByteView data_;
    std::size_t pos_ = 0;
};

class ByteWriter {
public:
    ByteWriter() = default;
    explicit ByteWriter(std::size_t reserve) { out_.reserve(reserve); }

    void u8(std::uint8_t v) { out_.push_back(v); }
    void u16(std::uint16_t v);
    void u24(std::uint32_t v);  // the top byte of v must be zero
    void u32(std::uint32_t v);
    void u64(std::uint64_t v);
    void bytes(ByteView v) { out_.insert(out_.end(), v.begin(), v.end()); }
    void zeros(std::size_t n) { out_.insert(out_.end(), n, 0); }

    /// Current length, e.g. to remember where a length field goes.
    std::size_t size() const noexcept { return out_.size(); }
    /// Overwrite an earlier position (length back-patching). Returns an error if out of range.
    Result<void> patch_u8(std::size_t at, std::uint8_t v);
    Result<void> patch_u16(std::size_t at, std::uint16_t v);

    const Bytes& data() const& noexcept { return out_; }
    Bytes take() && noexcept { return std::move(out_); }

private:
    Bytes out_;
};

/// MSB-first bit reader. Offsets in its Errors are bit offsets.
class BitReader {
public:
    explicit BitReader(ByteView data) noexcept : data_(data) {}

    std::size_t bit_offset() const noexcept { return bit_; }
    std::size_t bits_left() const noexcept { return data_.size() * 8 - bit_; }
    bool byte_aligned() const noexcept { return bit_ % 8 == 0; }

    /// Read n bits (0..64) as an unsigned value.
    Result<std::uint64_t> bits(unsigned n);
    Result<bool> bit();
    /// Skip to the next byte boundary.
    void align() noexcept { bit_ = (bit_ + 7) / 8 * 8; }

private:
    ByteView data_;
    std::size_t bit_ = 0;
};

/// MSB-first bit writer. The last byte is zero-padded.
class BitWriter {
public:
    /// Write the low n bits of v (0..64). Bits of v above n must be zero.
    Result<void> bits(std::uint64_t v, unsigned n);
    void bit(bool b);
    void align() noexcept;

    std::size_t bit_size() const noexcept { return bits_; }
    const Bytes& data() const& noexcept { return out_; }
    Bytes take() && noexcept { return std::move(out_); }

private:
    Bytes out_;
    std::size_t bits_ = 0;
};

/// Lower-case hex, no separators.
std::string to_hex(ByteView v);
/// Accepts upper or lower case; whitespace, ':' and '_' are ignored. Odd digit counts fail.
Result<Bytes> from_hex(std::string_view hex);

} // namespace ksim
