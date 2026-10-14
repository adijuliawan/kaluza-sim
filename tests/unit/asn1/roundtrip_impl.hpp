// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Encode/decode/re-encode helper shared by the per-protocol translation units.
// Test-only: the codec wrappers of M10 replace this with asn::Owned<T>.

#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "platform/buf.hpp"
#include "roundtrip.hpp"

#include <asn_application.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

namespace ksim::test {

enum class Per { aligned, unaligned };

inline RoundTrip roundtrip(const asn_TYPE_descriptor_t* td, void* value, Per per) {
    RoundTrip r;
    std::array<std::uint8_t, 4096> a{}, b{};
    const asn_enc_rval_t e1 = per == Per::aligned
                                  ? aper_encode_to_buffer(td, nullptr, value, a.data(), a.size())
                                  : uper_encode_to_buffer(td, nullptr, value, a.data(), a.size());
    if (e1.encoded < 0) {
        return r;
    }
    r.encoded = true;
    r.bits = static_cast<std::size_t>(e1.encoded);
    const std::size_t n = (r.bits + 7) / 8;
    r.hex = ksim::to_hex(ksim::ByteView(a.data(), n));
    void* decoded = nullptr;
    const asn_dec_rval_t d = per == Per::aligned
                                 ? aper_decode_complete(nullptr, td, &decoded, a.data(), n)
                                 : uper_decode_complete(nullptr, td, &decoded, a.data(), n);
    if (d.code == RC_OK) {
        r.decoded = true;
        const asn_enc_rval_t e2 = per == Per::aligned
                                      ? aper_encode_to_buffer(td, nullptr, decoded, b.data(), b.size())
                                      : uper_encode_to_buffer(td, nullptr, decoded, b.data(), b.size());
        r.identical = e2.encoded == e1.encoded && std::memcmp(a.data(), b.data(), n) == 0;
    }
    ASN_STRUCT_FREE(*td, decoded);
    ASN_STRUCT_FREE(*td, value);
    return r;
}

template <class T>
T* make() {
    return static_cast<T*>(std::calloc(1, sizeof(T)));
}

} // namespace ksim::test
