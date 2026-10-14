// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/buf.hpp"

#include <limits>

namespace ksim {

namespace {

std::uint32_t off32(std::size_t v) noexcept {
    return v > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                         : static_cast<std::uint32_t>(v);
}

} // namespace

// ---- ByteReader -------------------------------------------------------------

Error ByteReader::short_read(const char* what) const noexcept {
    return make_error(Errc::truncated, off32(pos_), what);
}

Result<std::uint8_t> ByteReader::u8() {
    if (remaining() < 1) {
        return short_read("u8 past end");
    }
    return data_[pos_++];
}

Result<std::uint16_t> ByteReader::u16() {
    if (remaining() < 2) {
        return short_read("u16 past end");
    }
    const auto v = static_cast<std::uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
    pos_ += 2;
    return v;
}

Result<std::uint32_t> ByteReader::u24() {
    if (remaining() < 3) {
        return short_read("u24 past end");
    }
    const std::uint32_t v = (std::uint32_t{data_[pos_]} << 16) | (std::uint32_t{data_[pos_ + 1]} << 8) |
                            std::uint32_t{data_[pos_ + 2]};
    pos_ += 3;
    return v;
}

Result<std::uint32_t> ByteReader::u32() {
    if (remaining() < 4) {
        return short_read("u32 past end");
    }
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        v = (v << 8) | data_[pos_++];
    }
    return v;
}

Result<std::uint64_t> ByteReader::u64() {
    if (remaining() < 8) {
        return short_read("u64 past end");
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | data_[pos_++];
    }
    return v;
}

Result<ByteView> ByteReader::take(std::size_t n) {
    if (remaining() < n) {
        return short_read("take past end");
    }
    ByteView v = data_.subspan(pos_, n);
    pos_ += n;
    return v;
}

ByteView ByteReader::rest() noexcept {
    ByteView v = data_.subspan(pos_);
    pos_ = data_.size();
    return v;
}

Result<void> ByteReader::skip(std::size_t n) {
    if (remaining() < n) {
        return short_read("skip past end");
    }
    pos_ += n;
    return {};
}

Result<std::uint8_t> ByteReader::peek() const {
    if (remaining() < 1) {
        return short_read("peek past end");
    }
    return data_[pos_];
}

// ---- ByteWriter -------------------------------------------------------------

void ByteWriter::u16(std::uint16_t v) {
    out_.push_back(static_cast<std::uint8_t>(v >> 8));
    out_.push_back(static_cast<std::uint8_t>(v));
}

void ByteWriter::u24(std::uint32_t v) {
    out_.push_back(static_cast<std::uint8_t>(v >> 16));
    out_.push_back(static_cast<std::uint8_t>(v >> 8));
    out_.push_back(static_cast<std::uint8_t>(v));
}

void ByteWriter::u32(std::uint32_t v) {
    for (int s = 24; s >= 0; s -= 8) {
        out_.push_back(static_cast<std::uint8_t>(v >> s));
    }
}

void ByteWriter::u64(std::uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) {
        out_.push_back(static_cast<std::uint8_t>(v >> s));
    }
}

Result<void> ByteWriter::patch_u8(std::size_t at, std::uint8_t v) {
    if (at >= out_.size()) {
        return make_error(Errc::invalid_argument, off32(at), "patch_u8 past end");
    }
    out_[at] = v;
    return {};
}

Result<void> ByteWriter::patch_u16(std::size_t at, std::uint16_t v) {
    if (out_.size() < 2 || at > out_.size() - 2) {
        return make_error(Errc::invalid_argument, off32(at), "patch_u16 past end");
    }
    out_[at] = static_cast<std::uint8_t>(v >> 8);
    out_[at + 1] = static_cast<std::uint8_t>(v);
    return {};
}

// ---- BitReader / BitWriter --------------------------------------------------

Result<std::uint64_t> BitReader::bits(unsigned n) {
    if (n > 64) {
        return make_error(Errc::invalid_argument, off32(bit_), "bits: n > 64");
    }
    if (n > bits_left()) {
        return make_error(Errc::truncated, off32(bit_), "bits past end");
    }
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) {
        const std::uint8_t byte = data_[bit_ / 8];
        const unsigned shift = 7U - static_cast<unsigned>(bit_ % 8);
        v = (v << 1) | ((byte >> shift) & 1U);
        ++bit_;
    }
    return v;
}

Result<bool> BitReader::bit() {
    auto r = bits(1);
    if (!r) {
        return r.error();
    }
    return *r != 0;
}

Result<void> BitWriter::bits(std::uint64_t v, unsigned n) {
    if (n > 64) {
        return make_error(Errc::invalid_argument, off32(bits_), "bits: n > 64");
    }
    if (n < 64 && (v >> n) != 0) {
        return make_error(Errc::out_of_range, off32(bits_), "value does not fit in n bits");
    }
    for (unsigned i = n; i-- > 0;) {
        bit(((v >> i) & 1U) != 0);
    }
    return {};
}

void BitWriter::bit(bool b) {
    if (bits_ % 8 == 0) {
        out_.push_back(0);
    }
    if (b) {
        out_.back() = static_cast<std::uint8_t>(out_.back() | (0x80U >> (bits_ % 8)));
    }
    ++bits_;
}

void BitWriter::align() noexcept {
    bits_ = (bits_ + 7) / 8 * 8;
}

// ---- hex ----------------------------------------------------------------------

std::string to_hex(ByteView v) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (std::uint8_t b : v) {
        s.push_back(kDigits[b >> 4]);
        s.push_back(kDigits[b & 0x0F]);
    }
    return s;
}

Result<Bytes> from_hex(std::string_view hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    int hi = -1;
    for (std::size_t i = 0; i < hex.size(); ++i) {
        const char c = hex[i];
        int d;
        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            d = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            d = c - 'A' + 10;
        } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':' || c == '_') {
            continue;
        } else {
            return make_error(Errc::malformed, off32(i), "non-hex character");
        }
        if (hi < 0) {
            hi = d;
        } else {
            out.push_back(static_cast<std::uint8_t>((hi << 4) | d));
            hi = -1;
        }
    }
    if (hi >= 0) {
        return make_error(Errc::malformed, off32(hex.size()), "odd number of hex digits");
    }
    return out;
}

} // namespace ksim
