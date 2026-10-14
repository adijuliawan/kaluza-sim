// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The typed NAS IEs and the NAS security context under arbitrary input (P1 N4).
// The first octet picks a target: one of the typed IEs (the rest of the input
// is its contents) or the security context's downlink check (the rest is a
// downlink message). A value that decodes must encode, and decode again to the
// same encoding; nothing may crash.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "codec/nas/ie/ie.hpp"
#include "proc/ue/nas_sec/nas_sec.hpp"

namespace {

using ksim::Bytes;
using ksim::ByteView;

void same(const Bytes& a, const Bytes& b) {
    if (a != b) {
        std::abort();
    }
}

Bytes bytes_of(const Bytes& b) { return b; }
template <class R>
Bytes bytes_of(const R& r) {
    if (!r) {
        std::abort();   // a value that decoded must encode
    }
    return *r;
}

template <class T>
void round_trip(ByteView in) {
    auto a = T::decode(in);
    if (!a) {
        return;
    }
    const Bytes e1 = bytes_of(a->encode());
    auto b = T::decode(e1);
    if (!b) {
        std::abort();
    }
    same(bytes_of(b->encode()), e1);
}

ksim::proc::ue::NasSecurityContext& context() {
    static ksim::proc::ue::NasSecurityContext c = [] {
        auto r = ksim::proc::ue::NasSecurityContext::derive(ksim::nas::ie::NgKsi{false, 1},
                                                            ksim::SecretBytes(32), 2, 2);
        if (!r) {
            std::abort();
        }
        return std::move(r).value();
    }();
    return c;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    namespace ie = ksim::nas::ie;
    const ByteView in(data + 1, size - 1);
    switch (data[0] % 24) {
    case 0: round_trip<ie::MobileIdentity>(in); break;
    case 1: round_trip<ie::TaiList>(in); break;
    case 2: round_trip<ie::Nssai>(in); break;
    case 3: round_trip<ie::Snssai>(in); break;
    case 4: round_trip<ie::QosRules>(in); break;
    case 5: round_trip<ie::QosFlowDescriptions>(in); break;
    case 6: round_trip<ie::PduAddress>(in); break;
    case 7: round_trip<ie::SessionAmbr>(in); break;
    case 8: round_trip<ie::RejectedNssai>(in); break;
    case 9: round_trip<ie::PlmnList>(in); break;
    case 10: round_trip<ie::Dnn>(in); break;
    case 11: round_trip<ie::UeSecurityCapability>(in); break;
    case 12: round_trip<ie::PsiBitmap>(in); break;
    case 13: round_trip<ie::ReactivationErrorCause>(in); break;
    case 14: round_trip<ie::RegistrationResult>(in); break;
    case 15: round_trip<ie::GprsTimer3>(in); break;
    case 16: round_trip<ie::DeregistrationType>(in); break;
    case 17: round_trip<ie::MaxPacketFilters>(in); break;
    case 18: round_trip<ie::TaiIe>(in); break;
    case 19: round_trip<ie::NasSecurityAlgorithms>(in); break;
    case 20: round_trip<ie::Abba>(in); break;
    case 21: round_trip<ie::EapMessage>(in); break;
    default: {
        // The downlink check: a fresh copy of the context each time, so one
        // input's COUNT does not shape the next.
        auto c = ksim::proc::ue::NasSecurityContext::derive(ie::NgKsi{false, 1}, context().kamf().clone(), 2, 2);
        if (c) {
            (void)c->unprotect(in);
        }
        break;
    }
    }
    return 0;
}
