// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The permutation Keccak-f[1600] as TS 35.231 Annex C defines it, for TUAK.
// The state is 200 octets: bit i of the 1600-bit string is bit i % 8 (counted
// from the least significant) of octet i / 8, so that a lane, s[64(5y+x) ..
// 64(5y+x)+63], is eight octets in little-endian order (TS 35.231 §5.2: inputs
// are mapped so that no bit reversal within octets is needed).

#pragma once

#include <array>
#include <cstdint>

namespace ksim::crypto {

using KeccakState = std::array<std::uint8_t, 200>;

/// Apply Keccak-f[1600] (24 rounds) in place.
void keccak_f1600(KeccakState& s);

} // namespace ksim::crypto
