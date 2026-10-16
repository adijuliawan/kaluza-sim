// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/ue/persona.hpp"

#include <algorithm>

#include "codec/asn1/msg/rrc.hpp"
#include "platform/yaml.hpp"

namespace ksim::node {

namespace {

// What kaluza-sim implements at NAS (MmConfig's default): 5G-EA0, 128-5G-EA1,
// 128-5G-EA2 and 128-5G-IA1, 128-5G-IA2.
constexpr std::uint8_t kEa = 0xE0;
constexpr std::uint8_t kIa = 0x60;

bool digits(const std::string& s, std::size_t n) {
    return s.size() == n && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

} // namespace

std::optional<Bytes> Persona::nr_capability() const {
    for (const auto& [rat, b] : containers) {
        if (rat == "nr") {
            return b;
        }
    }
    return std::nullopt;
}

nas::ie::UeSecurityCapability Persona::security() const {
    nas::ie::UeSecurityCapability s{kEa, kIa, std::nullopt, std::nullopt, {}};
    if (!ue_security_capability) {
        return s;
    }
    auto phone = nas::ie::UeSecurityCapability::decode(*ue_security_capability);
    if (!phone) {
        return s;
    }
    s.ea = static_cast<std::uint8_t>(phone->ea & kEa);
    s.ia = static_cast<std::uint8_t>(phone->ia & kIa);
    if (s.ea == 0) {
        s.ea = 0x80;   // 5G-EA0 at least: a UE supports the null algorithm
    }
    return s;
}

std::optional<Bytes> Persona::mm_capability_sent() const {
    if (!mm_capability || mm_capability->empty()) {
        return std::nullopt;
    }
    return Bytes(mm_capability->size(), 0x00);   // P1: none of its features is implemented
}

Result<Persona> load_persona(const std::string& file, std::string& why) {
    Persona p;
    try {
        const Yaml y = Yaml::load_file(file);
        y.only({"name", "device", "sources", "imeisv", "nas", "rrc"});
        p.name = y.at("name").as<std::string>();
        p.device = y.get<std::string>("device", "");
        if (y.has("imeisv")) {
            const Yaml i = y.at("imeisv");
            i.only({"tac", "svn"});
            p.tac = i.at("tac").as<std::string>();
            p.svn = i.get<std::string>("svn", "01");
            if (!digits(*p.tac, 8) || !digits(*p.svn, 2)) {
                i.fail("tac is 8 digits and svn 2");
            }
        }
        auto hex = [](const Yaml& v) {
            auto b = from_hex(v.as<std::string>());
            if (!b) {
                v.fail("not hex");
            }
            return *b;
        };
        if (y.has("nas")) {
            const Yaml n = y.at("nas");
            n.only({"mm_capability", "ue_security_capability", "s1_ue_network_capability", "ue_usage_setting",
                    "requested_nssai", "integrity_max_data_rate"});
            for (auto [key, out] : {std::pair{"mm_capability", &p.mm_capability},
                                    std::pair{"ue_security_capability", &p.ue_security_capability},
                                    std::pair{"s1_ue_network_capability", &p.s1_ue_network_capability},
                                    std::pair{"ue_usage_setting", &p.ue_usage_setting},
                                    std::pair{"requested_nssai", &p.requested_nssai},
                                    std::pair{"integrity_max_data_rate", &p.integrity_max_data_rate}}) {
                if (n.has(key)) {
                    *out = hex(n.at(key));
                }
            }
        }
        if (p.integrity_max_data_rate && p.integrity_max_data_rate->size() != 2) {
            y.at("nas").at("integrity_max_data_rate").fail("the IE's two octets, UL then DL (TS 24.501 9.11.4.7)");
        }
        if (y.has("rrc")) {
            const Yaml r = y.at("rrc");
            r.only({"ue_capability_rat_containers"});
            const Yaml list = r.at("ue_capability_rat_containers");
            for (std::size_t i = 0; i < list.size(); ++i) {
                const Yaml c = list.at(i);
                c.only({"rat", "uper"});
                p.containers.emplace_back(c.at("rat").as<std::string>(), hex(c.at("uper")));
            }
        }
    } catch (const YamlError& e) {
        why = std::string("the persona: ") + e.what();
        return make_error(Errc::invalid_argument, 0, "persona: not valid");
    }
    if (auto nr = p.nr_capability()) {
        if (!rrc::to_jer("UE-NR-Capability", *nr)) {
            why = "the persona's UE-NR-Capability does not decode";
            return make_error(Errc::malformed, 0, "persona: the NR capability does not decode");
        }
    }
    if (p.ue_security_capability && !nas::ie::UeSecurityCapability::decode(*p.ue_security_capability)) {
        why = "the persona's UE security capability does not decode";
        return make_error(Errc::malformed, 0, "persona: the UE security capability does not decode");
    }
    return p;
}

std::string imeisv_for(const Persona* p, const std::string& tac, const std::string& imsi) {
    const std::string snr = imsi.size() >= 6 ? imsi.substr(imsi.size() - 6) : std::string(6, '0');
    if (p != nullptr && p->tac) {
        return *p->tac + snr + p->svn.value_or("01");
    }
    return tac + snr + "01";
}

} // namespace ksim::node
