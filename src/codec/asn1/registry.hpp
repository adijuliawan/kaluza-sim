// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Every generated ASN.1 type of the five protocols, by name (plan M10): for
// ksim-codec and the oracle harness, which pick types at run time. Entity code
// names its types at compile time and does not need this.

#pragma once

#include <cstddef>
#include <span>
#include <string_view>

#include "codec/asn1/asn1.hpp"

namespace ksim::asn1 {

struct RegistryEntry {
    const char* name;  // the ASN.1 type name with '-' written '_'
    const asn_TYPE_descriptor_t* td;
};

/// The protocols: rrc, ngap, f1ap, e1ap, xnap.
bool known_protocol(std::string_view proto);

/// The encoding rules a protocol uses: UPER for RRC, APER for the rest.
Rules rules_for(std::string_view proto);

/// A type by its ASN.1 name ('-' or '_' both accepted), or nullptr.
const asn_TYPE_descriptor_t* find_type(std::string_view proto, std::string_view name);

/// All of a protocol's types, sorted by name.
std::span<const RegistryEntry> types(std::string_view proto);

} // namespace ksim::asn1
