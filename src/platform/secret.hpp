// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// SecretBytes: the only home for key material (architecture.md tenet 5,
// requirements.md §3.6). K, OPc, ADM, PINs, K_AUSF and every key below it,
// CK/IK, RES/XRES and NH live here.
//
//  - Move-only. A copy is a deliberate clone().
//  - Zeroized (OPENSSL_cleanse) on destruction and when moved from.
//  - No printing: operator<< is deleted, and there is no conversion to a view
//    or string. redacted() gives "<redacted:len=N:fpr=xxxxxxxx>", where the
//    fingerprint is an HMAC under a per-process random key. It correlates
//    within a run and means nothing outside it.
//  - Comparison is constant-time (ct_equal).
//  - expose() / expose_mut() hand the bytes to crypto code. Every call site is
//    on the allowlist in tools/guards/secret_expose_allowlist.txt, which a CI
//    guard enforces.

#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <span>
#include <string>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim {

class SecretBytes {
public:
    SecretBytes() noexcept = default;
    /// n zero bytes, to be filled through expose_mut() by a key derivation.
    explicit SecretBytes(std::size_t n);
    /// Copy key material in from a buffer the caller then wipes or discards.
    static SecretBytes copy_of(ByteView v);
    /// For KAT vectors and sealed-file loading. The input string is not wiped;
    /// callers that read secrets from files keep them out of std::string.
    static Result<SecretBytes> from_hex(std::string_view hex);

    SecretBytes(SecretBytes&& o) noexcept;
    SecretBytes& operator=(SecretBytes&& o) noexcept;
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    ~SecretBytes();

    SecretBytes clone() const;

    std::size_t size() const noexcept { return n_; }
    bool empty() const noexcept { return n_ == 0; }

    ByteView expose() const noexcept { return {p_, n_}; }
    std::span<std::uint8_t> expose_mut() noexcept { return {p_, n_}; }

    std::string redacted() const;

    friend bool ct_equal(const SecretBytes& a, const SecretBytes& b) noexcept;
    friend bool ct_equal(const SecretBytes& a, ByteView b) noexcept;
    friend std::ostream& operator<<(std::ostream&, const SecretBytes&) = delete;

private:
    void wipe() noexcept;

    std::uint8_t* p_ = nullptr;
    std::size_t n_ = 0;
};

} // namespace ksim
