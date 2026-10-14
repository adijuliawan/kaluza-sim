// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Written from TS 35.235 §11 (the original Rijndael submission's 256-bit block
// variant). The state is a 4 x 8 array of octets; octet n of a block is row
// n % 4, column n / 4 (§11.1). Two misprints in §11 are read as the cipher
// defines them (row KS-SEC-S1): the key schedule's first S-box input for row 0
// is rk[r-1] at (row 1, column 7), i.e. the "shifted order" of NOTE 2, not
// "rk[r-1, 7, 7]"; and MixColumns uses 3 * a3 for b2 and runs over all eight
// columns. The S-box is computed (inverse in GF(2^8), then the affine map)
// rather than transcribed from §11.8; the 25 cases of TS 35.236 exercise it.

#include "crypto/rijndael256.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstdlib>

namespace ksim::crypto {

namespace {

constexpr std::uint8_t xtime(std::uint8_t a) {
    return static_cast<std::uint8_t>((a << 1) ^ ((a & 0x80) != 0 ? 0x1B : 0x00));  // T02 mod 0x11B
}

struct Sbox {
    std::uint8_t v[256]{};
};

constexpr Sbox make_sbox() {
    // Inverses through powers of the generator 3: inv(3^i) = 3^(255 - i).
    std::uint8_t exp[256]{};
    std::uint8_t log[256]{};
    std::uint8_t g = 1;
    for (unsigned i = 0; i < 255; ++i) {
        exp[i] = g;
        log[g] = static_cast<std::uint8_t>(i);
        g = static_cast<std::uint8_t>(xtime(g) ^ g);  // g * 3
    }
    Sbox s;
    for (unsigned x = 0; x < 256; ++x) {
        const std::uint8_t inv = x == 0 ? 0 : exp[(255 - log[x]) % 255];
        // b'_i = b_i + b_(i+4) + b_(i+5) + b_(i+6) + b_(i+7) + c_i, c = 0x63
        std::uint8_t r = 0x63;
        for (unsigned i = 0; i < 8; ++i) {
            const unsigned bit = ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8)) ^
                                  (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8))) &
                                 1U;
            r = static_cast<std::uint8_t>(r ^ (bit << i));
        }
        s.v[x] = r;
    }
    return s;
}

constexpr Sbox kSbox = make_sbox();

constexpr std::uint8_t at(const Block32& b, unsigned row, unsigned col) {
    return b[row + 4 * col];
}

} // namespace

Rijndael256::Rijndael256(ByteView key) {
    if (key.size() != 32 && key.size() != 16) {
        std::abort();  // a programming error, never network input
    }
    std::copy(key.begin(), key.end(), round_keys_[0].begin());  // 16-octet keys: zero-extended
    std::uint8_t rcon = 1;
    for (unsigned r = 1; r <= 14; ++r) {
        const Block32& p = round_keys_[r - 1];
        Block32& k = round_keys_[r];
        // column 0: previous column 0, xor S-box of the previous column 7 rotated up one row, xor rcon
        for (unsigned i = 0; i < 4; ++i) {
            k[i] = static_cast<std::uint8_t>(at(p, i, 0) ^ kSbox.v[at(p, (i + 1) % 4, 7)] ^ (i == 0 ? rcon : 0));
        }
        for (unsigned j = 1; j < 8; ++j) {
            for (unsigned i = 0; i < 4; ++i) {
                const std::uint8_t prev = k[i + 4 * (j - 1)];
                k[i + 4 * j] = static_cast<std::uint8_t>(at(p, i, j) ^ (j == 4 ? kSbox.v[prev] : prev));
            }
        }
        rcon = xtime(rcon);
    }
}

Rijndael256::~Rijndael256() {
    OPENSSL_cleanse(round_keys_.data(), sizeof round_keys_);
}

Block32 Rijndael256::encrypt(const Block32& in) const {
    static constexpr unsigned kShift[4] = {0, 1, 3, 4};  // §11.4, for 8 columns
    Block32 a = in;
    for (unsigned n = 0; n < 32; ++n) {
        a[n] ^= round_keys_[0][n];
    }
    for (unsigned r = 1; r <= 14; ++r) {
        Block32 b{};
        // SubBytes and ShiftRows: row i moves left by kShift[i]
        for (unsigned i = 0; i < 4; ++i) {
            for (unsigned j = 0; j < 8; ++j) {
                b[i + 4 * j] = kSbox.v[at(a, i, (j + kShift[i]) % 8)];
            }
        }
        if (r != 14) {
            for (unsigned j = 0; j < 8; ++j) {
                const std::uint8_t a0 = b[4 * j];
                const std::uint8_t a1 = b[4 * j + 1];
                const std::uint8_t a2 = b[4 * j + 2];
                const std::uint8_t a3 = b[4 * j + 3];
                b[4 * j] = static_cast<std::uint8_t>(xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3);
                b[4 * j + 1] = static_cast<std::uint8_t>(a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3);
                b[4 * j + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3);
                b[4 * j + 3] = static_cast<std::uint8_t>(xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3));
            }
        }
        for (unsigned n = 0; n < 32; ++n) {
            b[n] ^= round_keys_[r][n];
        }
        a = b;
        OPENSSL_cleanse(b.data(), b.size());
    }
    return a;
}

} // namespace ksim::crypto
