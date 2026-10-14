// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Fuzz target (plan M14): an asn1c decoder of one protocol, KSIM_FUZZ_PROTO
// (ngap, f1ap, e1ap, xnap; rrc picks the channel message class from the
// first octet). Property: what decodes re-encodes in relay mode, and that
// encoding decodes and encodes again to the same octets.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "codec/asn1/asn1.hpp"
#include "codec/asn1/registry.hpp"

namespace {

#ifndef KSIM_FUZZ_PROTO
#error "KSIM_FUZZ_PROTO names the protocol"
#endif

constexpr std::string_view kProto = KSIM_FUZZ_PROTO;

constexpr std::string_view kRrcTypes[] = {"UL_CCCH_Message", "UL_CCCH1_Message", "DL_CCCH_Message",
                                          "UL_DCCH_Message", "DL_DCCH_Message", "PCCH_Message",
                                          "BCCH_BCH_Message", "BCCH_DL_SCH_Message"};

std::string_view top_type(const std::uint8_t*& data, std::size_t& size) {
    if (kProto == "ngap") {
        return "NGAP_PDU";
    }
    if (kProto == "f1ap") {
        return "F1AP_PDU";
    }
    if (kProto == "e1ap") {
        return "E1AP_PDU";
    }
    if (kProto == "xnap") {
        return "XnAP_PDU";
    }
    const std::uint8_t pick = size > 0 ? data[0] : 0;
    if (size > 0) {
        ++data;
        --size;
    }
    return kRrcTypes[pick % (sizeof kRrcTypes / sizeof kRrcTypes[0])];
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace ksim;
    const std::string_view type = top_type(data, size);
    const asn_TYPE_descriptor_t* td = asn1::find_type(kProto, type);
    if (td == nullptr) {
        std::abort();
    }
    const auto rules = asn1::rules_for(kProto);
    auto v = asn1::decode(*td, rules, ByteView(data, size));
    if (!v) {
        return 0;
    }
    (void)asn1::to_jer(*v);
    auto once = asn1::encode(*v, rules, asn1::Check::relay);
    if (!once) {
        return 0;   // values the decoder takes that the encoder refuses: KS-PLAT-G3
    }
    auto back = asn1::decode(*td, rules, *once);
    if (!back) {
        std::abort();   // our own encoding must decode
    }
    auto twice = asn1::encode(*back, rules, asn1::Check::relay);
    if (!twice || *twice != *once) {
        std::abort();   // and encode the same again
    }
    return 0;
}
