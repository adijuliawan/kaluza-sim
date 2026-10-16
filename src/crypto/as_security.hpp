// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The AS algorithms with their key set once (P2 Q8, the PDCP fast path; plan
// Q8): a PDCP entity keeps one context per key for every PDU it protects,
// instead of setting the key up again per PDU. The same algorithms as
// crypto/nea.hpp, which runs its one-shot nea() and nia() through these, so the
// known-answer sets of TS 33.401 and SAGE check them both. Whole octets only
// (PDCP's PDUs are octet strings); the bit-string forms stay in nea.hpp.
//
//  - NEA2: one EVP AES-128-CTR context, its IV (T1) reset per PDU.
//  - NIA2: OpenSSL's CMAC, keyed once and re-initialised per message; the
//    message is fed in parts (COUNT || BEARER || DIRECTION || 0^26, then the
//    PDU's octets) without joining them.
//  - NEA1/NIA1: SNOW 3G (UEA2 f8, UIA2 f9 with FRESH = BEARER || 0^27).
//  - NEA0/NIA0: nothing and a zero MAC (TS 33.501 D.1), behind the bisect switch.
//  - NEA3/NIA3 (ZUC): a declared gap (KS-SEC-G1), refused at make().
#pragma once

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <span>

#include "crypto/nea.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto {

class NeaContext {
public:
    static Result<NeaContext> make(Nea alg, const SecretBytes& key);
    NeaContext(NeaContext&&) noexcept;
    NeaContext& operator=(NeaContext&&) noexcept;
    ~NeaContext();

    Nea alg() const noexcept { return alg_; }
    /// En- or deciphers the first `bits` bits of `data` in place (the same operation);
    /// the rest of the last octet is zeroed, as the bit-string forms leave it.
    Result<void> apply(SecInput in, std::span<std::uint8_t> data, std::size_t bits);
    Result<void> apply(SecInput in, std::span<std::uint8_t> data) { return apply(in, data, data.size() * 8); }

private:
    NeaContext(Nea alg, SecretBytes key);
    struct Impl;
    Nea alg_;
    SecretBytes key_;                // NEA1's; NEA2 holds its key in the EVP context
    std::unique_ptr<Impl> impl_;
};

class NiaContext {
public:
    static Result<NiaContext> make(Nia alg, const SecretBytes& key);
    NiaContext(NiaContext&&) noexcept;
    NiaContext& operator=(NiaContext&&) noexcept;
    ~NiaContext();

    Nia alg() const noexcept { return alg_; }
    /// The 32-bit MAC over the octets of `parts`, in order, as one message.
    Result<Mac> mac(SecInput in, std::initializer_list<ByteView> parts);

private:
    NiaContext(Nia alg, SecretBytes key);
    struct Impl;
    Nia alg_;
    SecretBytes key_;                // NIA1's; NIA2 holds its key in the MAC context
    std::unique_ptr<Impl> impl_;
};

} // namespace ksim::crypto
