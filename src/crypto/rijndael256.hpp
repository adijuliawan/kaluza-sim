// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Rijndael with a 256-bit block and a 256-bit key, encryption only: the
// MILENAGE-256 kernel PRF_K (TS 35.235 §8.4.1, §11). Not AES (whose block is
// 128 bits), so OpenSSL cannot supply it.

#pragma once

#include <array>
#include <cstdint>

#include "platform/buf.hpp"

namespace ksim::crypto {

using Block32 = std::array<std::uint8_t, 32>;

class Rijndael256 {
public:
    /// key: 32 octets, or 16 octets extended with 16 zero octets (§11.9).
    explicit Rijndael256(ByteView key);
    ~Rijndael256();
    Rijndael256(const Rijndael256&) = delete;
    Rijndael256& operator=(const Rijndael256&) = delete;

    Block32 encrypt(const Block32& in) const;

private:
    std::array<Block32, 15> round_keys_{};  // octet n of a round key is (row n % 4, column n / 4)
};

} // namespace ksim::crypto
