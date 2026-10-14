// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The simulation's pseudo-random source (P1 N1; requirements §3.3: one seed per
// run, replayable). It is counter-based and keyed: a stream is named by the run
// seed and a key path (node, UE, purpose), and its n-th value is a pure
// function of (seed, key, n). Streams therefore do not perturb each other, and
// adding a UE or a draw in one place does not shift every other choice of the
// run. Not for keys, nonces or RAND: those come from crypto.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <span>
#include <string_view>

namespace ksim {

class Rng {
public:
    /// The stream `key` of the run seeded with `seed`.
    explicit Rng(std::uint64_t seed, std::initializer_list<std::uint64_t> key = {}) noexcept;

    /// A sub-stream of this stream, named by `key`. It does not consume a draw.
    Rng stream(std::initializer_list<std::uint64_t> key) const noexcept;

    std::uint64_t next() noexcept;
    /// Uniform in [0, n); n must be at least 1. Unbiased.
    std::uint64_t below(std::uint64_t n) noexcept;
    /// Uniform in [lo, hi], inclusive; lo <= hi.
    std::int64_t uniform(std::int64_t lo, std::int64_t hi) noexcept;
    /// Uniform in [0, 1).
    double unit() noexcept;
    bool chance(double p) noexcept { return unit() < p; }
    void fill(std::span<std::uint8_t> out) noexcept;

    std::uint64_t key() const noexcept { return key_; }
    std::uint64_t draws() const noexcept { return counter_; }

    /// A stable 64-bit label for a purpose name (FNV-1a), for key paths such
    /// as {node_id, ue_index, Rng::label("kair.jitter")}.
    static constexpr std::uint64_t label(std::string_view name) noexcept {
        std::uint64_t h = 0xcbf29ce484222325ULL;
        for (char c : name) {
            h ^= static_cast<std::uint8_t>(c);
            h *= 0x100000001b3ULL;
        }
        return h;
    }

private:
    Rng(std::uint64_t key, int /*derived*/) noexcept : key_(key) {}

    std::uint64_t key_;
    std::uint64_t counter_ = 0;
};

} // namespace ksim
