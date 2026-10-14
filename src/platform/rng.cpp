// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/rng.hpp"

#include <cstring>

namespace ksim {

namespace {

constexpr std::uint64_t kGolden = 0x9E3779B97F4A7C15ULL;

// The SplitMix64 finaliser (Steele, Lea and Flood, "Fast splittable
// pseudorandom number generators", OOPSLA 2014): a bijection with full
// avalanche, applied to a counter it gives SplitMix64's output sequence.
constexpr std::uint64_t mix(std::uint64_t z) noexcept {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

std::uint64_t derive(std::uint64_t base, std::initializer_list<std::uint64_t> key) noexcept {
    std::uint64_t k = base;
    for (std::uint64_t part : key) {
        k = mix(k ^ mix(part + kGolden));
    }
    return k;
}

} // namespace

Rng::Rng(std::uint64_t seed, std::initializer_list<std::uint64_t> key) noexcept
    : key_(derive(mix(seed ^ 0x6B73696D2D726E67ULL /* "ksim-rng" */), key)) {}

Rng Rng::stream(std::initializer_list<std::uint64_t> key) const noexcept {
    return Rng(derive(key_, key), 0);
}

std::uint64_t Rng::next() noexcept {
    ++counter_;
    return mix(key_ + counter_ * kGolden);
}

std::uint64_t Rng::below(std::uint64_t n) noexcept {
    if (n <= 1) {
        return 0;
    }
    // Rejection of the low remainder band keeps the result unbiased.
    const std::uint64_t threshold = (0 - n) % n;
    for (;;) {
        const std::uint64_t r = next();
        if (r >= threshold) {
            return r % n;
        }
    }
}

std::int64_t Rng::uniform(std::int64_t lo, std::int64_t hi) noexcept {
    if (hi <= lo) {
        return lo;
    }
    const std::uint64_t span = static_cast<std::uint64_t>(hi) - static_cast<std::uint64_t>(lo);
    const std::uint64_t r = span == UINT64_MAX ? next() : below(span + 1);
    return static_cast<std::int64_t>(static_cast<std::uint64_t>(lo) + r);
}

double Rng::unit() noexcept {
    return static_cast<double>(next() >> 11) * 0x1.0p-53;
}

void Rng::fill(std::span<std::uint8_t> out) noexcept {
    std::size_t i = 0;
    while (i < out.size()) {
        const std::uint64_t v = next();
        const std::size_t n = out.size() - i < 8 ? out.size() - i : 8;
        std::memcpy(out.data() + i, &v, n);
        i += n;
    }
}

} // namespace ksim
