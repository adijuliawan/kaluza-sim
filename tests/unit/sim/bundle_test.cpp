// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The SubscriberBundle for kaluza-core's provisioning API (P1 N9; ADR 0008,
// sim-uicc.md 8): the W0 sub-block profiles, the documents each one carries,
// keys only in the authentication subscription and never with a
// protectionParameterId (the UDR refuses that beside key values).

#include <gtest/gtest.h>

#include <algorithm>

#include "bundle.hpp"

namespace ksim::sim {
namespace {

std::vector<std::string> resources(const nlohmann::ordered_json& b) {
    std::vector<std::string> out;
    for (const auto& d : b["documents"]) {
        out.push_back(d["resource"].get<std::string>());
    }
    return out;
}

TEST(Bundle, TheSubBlocksHaveTheirProfiles) {
    EXPECT_EQ(profile_for("001010000300000").name, "default");
    EXPECT_EQ(profile_for("001010000300049").name, "default");
    EXPECT_TRUE(profile_for("001010000300050").sms);
    EXPECT_EQ(profile_for("001010000300065").subs_reg_timer_s, 120);
    EXPECT_EQ(profile_for("001010000300079").auth_method, "EAP_AKA_PRIME");
    EXPECT_EQ(profile_for("001010000300080").name, "default");
    EXPECT_EQ(profile_for("001010000300150").name, "default");
}

TEST(Bundle, ADefaultSubscriberCarriesTheCoreDocuments) {
    const auto b = bundle("001010000300001", "99900300001", "kk", "oo", profile_for("001010000300001"));
    EXPECT_EQ(b["ueId"], "imsi-001010000300001");
    const auto r = resources(b);
    for (const char* want : {"subscription-data:identity-data",
                             "subscription-data:authentication-data:authentication-subscription",
                             "subscription-data:provisioned-data:am-data", "subscription-data:provisioned-data:sm-data",
                             "subscription-data:provisioned-data:smf-selection-subscription-data",
                             "policy-data:ues:am-data", "policy-data:ues:sm-data"}) {
        EXPECT_NE(std::find(r.begin(), r.end(), want), r.end()) << want;
    }
    EXPECT_EQ(std::count_if(r.begin(), r.end(), [](const std::string& s) { return s.find("sms") != std::string::npos; }), 0);
    // Keys in the authentication subscription only, never protected.
    const std::string text = b.dump();
    EXPECT_EQ(text.find("protectionParameterId"), std::string::npos);
    std::size_t keys = 0;
    for (const auto& d : b["documents"]) {
        const std::string body = d["body"].dump();
        keys += body.find("\"kk\"") != std::string::npos ? 1 : 0;
        if (d["resource"] == "subscription-data:authentication-data:authentication-subscription") {
            EXPECT_EQ(d["body"]["encPermanentKey"], "kk");
            EXPECT_EQ(d["body"]["encOpcKey"], "oo");
            EXPECT_EQ(d["body"]["authenticationMethod"], "5G_AKA");
            EXPECT_EQ(d["body"]["authenticationManagementField"], "8000");
        }
    }
    EXPECT_EQ(keys, 1u);
}

TEST(Bundle, AnSmsSubscriberAddsItsSmsDocuments) {
    const auto b = bundle("001010000300055", "99900300055", "kk", "oo", profile_for("001010000300055"));
    const auto r = resources(b);
    EXPECT_NE(std::find(r.begin(), r.end(), "subscription-data:provisioned-data:sms-data"), r.end());
    EXPECT_NE(std::find(r.begin(), r.end(), "subscription-data:provisioned-data:sms-mng-data"), r.end());
    for (const auto& d : b["documents"]) {
        if (d["resource"] == "subscription-data:provisioned-data:sms-data") {
            EXPECT_EQ(d["body"]["smsSubscribed"], true);
        }
        if (d["resource"] == "subscription-data:provisioned-data:am-data") {
            EXPECT_EQ(d["body"]["subsRegTimer"], 3600);
            EXPECT_EQ(d["body"]["nssai"]["defaultSingleNssais"][0]["sd"], "000001");
        }
    }
}

} // namespace
} // namespace ksim::sim
