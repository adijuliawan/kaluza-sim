// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/registry.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace ksim::asn1 {

namespace detail {
extern const RegistryEntry kRegistry_rrc[];
extern const std::size_t kRegistrySize_rrc;
extern const RegistryEntry kRegistry_ngap[];
extern const std::size_t kRegistrySize_ngap;
extern const RegistryEntry kRegistry_f1ap[];
extern const std::size_t kRegistrySize_f1ap;
extern const RegistryEntry kRegistry_e1ap[];
extern const std::size_t kRegistrySize_e1ap;
extern const RegistryEntry kRegistry_xnap[];
extern const std::size_t kRegistrySize_xnap;
} // namespace detail

std::span<const RegistryEntry> types(std::string_view proto) {
    using namespace detail;
    if (proto == "rrc") {
        return {kRegistry_rrc, kRegistrySize_rrc};
    }
    if (proto == "ngap") {
        return {kRegistry_ngap, kRegistrySize_ngap};
    }
    if (proto == "f1ap") {
        return {kRegistry_f1ap, kRegistrySize_f1ap};
    }
    if (proto == "e1ap") {
        return {kRegistry_e1ap, kRegistrySize_e1ap};
    }
    if (proto == "xnap") {
        return {kRegistry_xnap, kRegistrySize_xnap};
    }
    return {};
}

bool known_protocol(std::string_view proto) {
    return !types(proto).empty();
}

Rules rules_for(std::string_view proto) {
    return proto == "rrc" ? Rules::uper : Rules::aper;
}

const asn_TYPE_descriptor_t* find_type(std::string_view proto, std::string_view name) {
    std::string key(name);
    std::replace(key.begin(), key.end(), '-', '_');
    const auto all = types(proto);
    const auto it = std::lower_bound(all.begin(), all.end(), key, [](const RegistryEntry& e, const std::string& k) {
        return std::strcmp(e.name, k.c_str()) < 0;
    });
    if (it == all.end() || key != it->name) {
        return nullptr;
    }
    return it->td;
}

} // namespace ksim::asn1
