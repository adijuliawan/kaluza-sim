// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "bundle.hpp"

namespace ksim::sim {

namespace {

using json = nlohmann::ordered_json;

// No servingPlmn on any document (kaluza-core-1e, 2026-10-15): the UDR keeps a
// document without one as the base it serves for whatever serving PLMN the UDM
// asks about, as for every seed UE; "00101" would make PLMN-specific copies
// found only under that exact form.
constexpr const char* kSlice = "1-000001";   // SST 1, SD 000001: memberId and the map keys of TS 29.503

json snssai() { return {{"sst", 1}, {"sd", "000001"}}; }
json ambr() { return {{"uplink", "1 Gbps"}, {"downlink", "1 Gbps"}}; }

json dnn_config(const char* default_type, std::initializer_list<const char*> allowed, int five_qi) {
    json types = json::array();
    for (const char* t : allowed) {
        types.push_back(t);
    }
    return {{"pduSessionTypes", {{"defaultSessionType", default_type}, {"allowedSessionTypes", types}}},
            {"sscModes", {{"defaultSscMode", "SSC_MODE_1"}, {"allowedSscModes", json::array({"SSC_MODE_1"})}}},
            {"5gQosProfile",
             {{"5qi", five_qi}, {"arp", {{"priorityLevel", 8}, {"preemptCap", "NOT_PREEMPT"}, {"preemptVuln", "PREEMPTABLE"}}}}},
            {"sessionAmbr", ambr()}};
}

json doc(const char* resource, json body) { return {{"resource", resource}, {"body", std::move(body)}}; }

} // namespace

SubscriberProfile profile_for(std::string_view imsi) {
    SubscriberProfile p;
    if (imsi.size() != 15 || imsi.substr(0, 12) != "001010000300") {
        return p;
    }
    const int n = std::stoi(std::string(imsi.substr(12)));
    if (n >= 50 && n <= 59) {
        p.name = "sms";
        p.sms = true;
    } else if (n >= 60 && n <= 69) {
        p.name = "short-reg";
        p.subs_reg_timer_s = 120;
    } else if (n >= 70 && n <= 79) {
        p.name = "eap-aka-prime";
        p.auth_method = "EAP_AKA_PRIME";
    }
    return p;
}

json bundle(std::string_view imsi, std::string_view msisdn, std::string_view k_hex, std::string_view opc_hex,
            const SubscriberProfile& p) {
    const std::string supi = "imsi-" + std::string(imsi);
    const std::string gpsi = "msisdn-" + std::string(msisdn);
    json docs = json::array();
    docs.push_back(doc("subscription-data:identity-data",
                       {{"supiList", json::array({supi})}, {"gpsiList", json::array({gpsi})}}));
    docs.push_back(doc("subscription-data:authentication-data:authentication-subscription",
                       {{"authenticationMethod", p.auth_method},
                        {"encPermanentKey", std::string(k_hex)},
                        {"encOpcKey", std::string(opc_hex)},
                        {"authenticationManagementField", "8000"},
                        {"sequenceNumber", {{"sqn", "000000000000"}, {"sqnScheme", "NON_TIME_BASED"}}}}));
    json am = doc("subscription-data:provisioned-data:am-data",
                  {{"gpsis", json::array({gpsi})},
                   {"subscribedUeAmbr", ambr()},
                   {"nssai", {{"defaultSingleNssais", json::array({snssai()})}}},
                   {"subsRegTimer", p.subs_reg_timer_s}});
    docs.push_back(am);
    json sm = doc("subscription-data:provisioned-data:sm-data",
                  {{"singleNssai", snssai()},
                   {"dnnConfigurations",
                    {{"internet", dnn_config("IPV4V6", {"IPV4", "IPV6", "IPV4V6"}, 9)},
                     {"ims", dnn_config("IPV4", {"IPV4"}, 5)}}}});
    sm["memberId"] = kSlice;
    docs.push_back(sm);
    json smf = doc("subscription-data:provisioned-data:smf-selection-subscription-data",
                   {{"subscribedSnssaiInfos",
                     {{kSlice, {{"dnnInfos", json::array({{{"dnn", "internet"}, {"defaultDnnIndicator", true}}, {{"dnn", "ims"}}})}}}}}});
    docs.push_back(smf);
    docs.push_back(doc("policy-data:ues:am-data", json::object()));
    docs.push_back(doc("policy-data:ues:ue-policy-set", json::object()));   // as every full seed UE has it
    docs.push_back(doc("policy-data:ues:sm-data",
                       {{"smPolicySnssaiData",
                         {{kSlice,
                           {{"snssai", snssai()},
                            {"smPolicyDnnData", {{"internet", {{"dnn", "internet"}}}, {"ims", {{"dnn", "ims"}}}}}}}}}}));
    if (p.sms) {
        json sms = doc("subscription-data:provisioned-data:sms-data", {{"smsSubscribed", true}});
            docs.push_back(sms);
        json mng = doc("subscription-data:provisioned-data:sms-mng-data",
                       {{"mtSmsSubscribed", true}, {"moSmsSubscribed", true}, {"mtSmsBarringAll", false}, {"moSmsBarringAll", false},
                        {"mtSmsBarringRoaming", false}, {"moSmsBarringRoaming", false}});
            docs.push_back(mng);
    }
    return {{"ueId", supi}, {"documents", docs}};
}

} // namespace ksim::sim
