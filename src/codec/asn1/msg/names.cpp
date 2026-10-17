// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/msg/names.hpp"

#include <cstring>

#include "codec/asn1/asn1.hpp"

extern "C" {
#include "E1AP_E1AP-PDU.h"
#include "F1AP_F1AP-PDU.h"
#include "NGAP_NGAP-PDU.h"
#include "XNAP_XnAP-PDU.h"
#include "constr_CHOICE.h"
}

namespace ksim::asn1 {

std::string message_name(std::string_view proto, ByteView pdu) {
    const asn_TYPE_descriptor_t* td = proto == "ngap"   ? &asn_DEF_NGAP_NGAP_PDU
                                      : proto == "f1ap" ? &asn_DEF_F1AP_F1AP_PDU
                                      : proto == "e1ap" ? &asn_DEF_E1AP_E1AP_PDU
                                      : proto == "xnap" ? &asn_DEF_XNAP_XnAP_PDU
                                                        : nullptr;
    if (td == nullptr) {
        return {};
    }
    auto v = decode(*td, Rules::aper, pdu);
    if (!v) {
        return {};
    }
    const unsigned kind = CHOICE_variant_get_presence(td, v->get());
    if (kind == 0 || kind > td->elements_count) {
        return {};
    }
    const asn_TYPE_member_t& m = td->elements[kind - 1];
    const void* msg = static_cast<const char*>(v->get()) + m.memb_offset;
    if ((m.flags & ATF_POINTER) != 0) {
        msg = *static_cast<const void* const*>(msg);
    }
    for (unsigned i = 0; msg != nullptr && i < m.type->elements_count; ++i) {
        const asn_TYPE_member_t& f = m.type->elements[i];
        if (std::strcmp(f.name, "value") != 0) {
            continue;
        }
        const void* value = static_cast<const char*>(msg) + f.memb_offset;
        const unsigned alt = CHOICE_variant_get_presence(f.type, value);
        return alt == 0 || alt > f.type->elements_count ? std::string() : std::string(f.type->elements[alt - 1].name);
    }
    return {};
}

} // namespace ksim::asn1
