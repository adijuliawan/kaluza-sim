// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Written from TS 35.231 Annex C. The round constants and rotation offsets are
// computed from their definitions there (the LFSR rc[t] and the (t+1)(t+2)/2
// walk) rather than transcribed.

#include "crypto/keccak.hpp"

#include <openssl/crypto.h>

namespace ksim::crypto {

namespace {

/// rc[t] = (x^t mod x^8 + x^6 + x^5 + x^4 + 1) mod x, in GF(2)[x].
constexpr bool rc(unsigned t) {
    unsigned r = 1;  // x^0
    for (unsigned i = 0; i < t % 255; ++i) {
        r <<= 1;
        if ((r & 0x100U) != 0) {
            r ^= 0x171U;  // x^8 = x^6 + x^5 + x^4 + 1
        }
    }
    return (r & 1U) != 0;
}

struct Tables {
    std::uint64_t round_constant[24]{};
    unsigned rho[5][5]{};  // [x][y]
};

constexpr Tables make_tables() {
    Tables t;
    for (unsigned ir = 0; ir < 24; ++ir) {
        std::uint64_t c = 0;
        for (unsigned j = 0; j <= 6; ++j) {
            if (rc(j + 7 * ir)) {
                c |= std::uint64_t{1} << ((1U << j) - 1);  // RC[ir][0][0][2^j - 1] = rc[j + 7ir]
            }
        }
        t.round_constant[ir] = c;
    }
    // (x, y) starts at (1, 0); each step (x, y) <- (y, 2x + 3y), offset (t+1)(t+2)/2 mod 64.
    unsigned x = 1;
    unsigned y = 0;
    for (unsigned s = 0; s < 24; ++s) {
        t.rho[x][y] = ((s + 1) * (s + 2) / 2) % 64;
        const unsigned nx = y;
        const unsigned ny = (2 * x + 3 * y) % 5;
        x = nx;
        y = ny;
    }
    return t;
}

constexpr Tables kTables = make_tables();

constexpr std::uint64_t rotl(std::uint64_t v, unsigned n) {
    return n == 0 ? v : (v << n) | (v >> (64 - n));
}

} // namespace

void keccak_f1600(KeccakState& s) {
    std::uint64_t a[5][5];  // [x][y]
    for (unsigned y = 0; y < 5; ++y) {
        for (unsigned x = 0; x < 5; ++x) {
            std::uint64_t lane = 0;
            for (unsigned b = 0; b < 8; ++b) {
                lane |= std::uint64_t{s[8 * (5 * y + x) + b]} << (8 * b);
            }
            a[x][y] = lane;
        }
    }
    for (unsigned ir = 0; ir < 24; ++ir) {
        // theta
        std::uint64_t c[5];
        for (unsigned x = 0; x < 5; ++x) {
            c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
        }
        for (unsigned x = 0; x < 5; ++x) {
            const std::uint64_t d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
            for (unsigned y = 0; y < 5; ++y) {
                a[x][y] ^= d;
            }
        }
        // rho and pi: b[y][2x + 3y] = rot(a[x][y])
        std::uint64_t b[5][5];
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned y = 0; y < 5; ++y) {
                b[y][(2 * x + 3 * y) % 5] = rotl(a[x][y], kTables.rho[x][y]);
            }
        }
        // chi
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned y = 0; y < 5; ++y) {
                a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]);
            }
        }
        // iota
        a[0][0] ^= kTables.round_constant[ir];
    }
    for (unsigned y = 0; y < 5; ++y) {
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned b = 0; b < 8; ++b) {
                s[8 * (5 * y + x) + b] = static_cast<std::uint8_t>(a[x][y] >> (8 * b));
            }
        }
    }
    OPENSSL_cleanse(a, sizeof a);
}

} // namespace ksim::crypto
