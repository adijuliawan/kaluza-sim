// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A UE with a device persona (P1 N15; architecture §6) over the whole network:
// the phone's UE-NR-Capability goes to the CU-CP in UECapabilityInformation
// and on to the AMF in UE Radio Capability Info Indication byte for byte; the
// NAS capabilities go intersected with what kaluza-sim implements (row
// KS-SCN-B1); the IMEISV carries the phone's TAC.

#include <gtest/gtest.h>

#include <string>

#include "codec/asn1/msg/rrc.hpp"
#include "codec/nas/build.hpp"
#include "net_rig.hpp"

namespace ksim::proctest {
namespace {

node::Persona persona(const char* name) {
    std::string why;
    auto p = node::load_persona(std::string(KSIM_SOURCE_DIR) + "/personas/" + name + ".yaml", why);
    EXPECT_TRUE(p) << why;
    return p ? *p : node::Persona{};
}

TEST(Persona, TheS22PlusCapabilityReachesTheAmfAsThePhoneSentIt) {
    const node::Persona p = persona("s22plus");
    const Bytes nr = p.nr_capability().value_or(Bytes{});
    ASSERT_EQ(nr.size(), 799u);
    Net n({}, nullptr, std::nullopt, p);
    n.register_ue();
    const auto ids = n.amf.ids(0);
    ASSERT_TRUE(ids.has_value());
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.radio_capability(ids->amf).has_value(); }, n.loop.now() + 2'000));
    auto inside = rrc::nr_capability_of(*n.amf.radio_capability(ids->amf));
    ASSERT_TRUE(inside);
    EXPECT_EQ(to_hex(*inside), to_hex(nr));   // byte for byte
    EXPECT_EQ(n.failures(), "");
}

TEST(Persona, NasCapabilitiesGoIntersectedWithWhatTheSimImplements) {
    const node::Persona p = persona("s22plus");
    Net n({}, nullptr, std::nullopt, p);
    n.register_ue();
    // The phone's f070f070 (EA0-3, IA1-3, EEA, EIA): only EA0-2 and IA1-2, no EPS algorithms.
    EXPECT_EQ(to_hex(p.security().encode()), "e060");
    // The full REGISTRATION REQUEST the stub took (in the SMC COMPLETE's container).
    const auto* m = n.amf.nas()->last_registration_request();
    ASSERT_NE(m, nullptr);
    const Bytes* cap = nas::get(*m, "5GMM capability");
    ASSERT_NE(cap, nullptr);
    EXPECT_EQ(to_hex(*cap), "00");   // the phone's 03 (S1 mode, HO attach): neither implemented
    EXPECT_EQ(nas::get(*m, "S1 UE network capability"), nullptr);
    const Bytes* sec = nas::get(*m, "UE security capability");
    ASSERT_NE(sec, nullptr);
    EXPECT_EQ(to_hex(*sec), "e060");
    EXPECT_EQ(n.failures(), "");
}

TEST(Persona, TheImeisvCarriesThePhonesTacAndSvn) {
    const node::Persona p = persona("s22plus");
    EXPECT_EQ(node::imeisv_for(&p, "86000000", kSupi), "3550145230000101");
    const node::Persona op = persona("oneplus9pro");   // no IMEISV in its captures: the topology's TAC
    EXPECT_EQ(node::imeisv_for(&op, "86000000", kSupi), "8600000030000101");
    EXPECT_EQ(node::imeisv_for(nullptr, "86000000", kSupi), "8600000030000101");
}

} // namespace
} // namespace ksim::proctest
