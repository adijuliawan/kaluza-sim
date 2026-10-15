// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The SubscriberBundle for kaluza-core's UDR provisioning API (P1 N9; ADR 0008,
// sim-uicc.md 8): one PUT body per subscriber, {ueId, documents[]}, each
// document a resource name, its body (the TS 29.505, 29.503 and 29.519 types)
// and, where the resource is scoped, memberId. Built from the specs' types and
// our profile, never from kaluza-core's code or seeds (ADR 0005); the API's
// own conventions come from the core session's review of a --dry-run (2026-10-15:
// no servingPlmn, so every document is the base one the UDR serves for any
// serving PLMN; the empty UE policy set every seed UE carries). The profile follows the W0 sub-blocks by the IMSI's last three
// digits: 000-049 default, 050-059 SMS, 060-069 subsRegTimer 120 s, 070-079
// EAP-AKA', 080-099 spare (default).

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace ksim::sim {

struct SubscriberProfile {
    std::string name = "default";
    std::string auth_method = "5G_AKA";   // AuthMethod of TS 29.503
    bool sms = false;
    int subs_reg_timer_s = 3600;
};

SubscriberProfile profile_for(std::string_view imsi);

/// The bundle. k_hex and opc_hex go into the authentication subscription as
/// they are given (a dry run passes placeholders).
nlohmann::ordered_json bundle(std::string_view imsi, std::string_view msisdn, std::string_view k_hex,
                              std::string_view opc_hex, const SubscriberProfile& p);

} // namespace ksim::sim
