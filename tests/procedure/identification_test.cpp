// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Identification after a context the AMF no longer holds (P1 N18; KS-NAS-D4):
// a UE switched off re-registers with its 5G-GUTI, integrity-protected with
// the context it stored (§4.4.6 b). An AMF that dropped the UE at its
// de-registration (kaluza-core in W2) cannot verify that and asks for the SUCI
// with a plain IDENTITY REQUEST. Secure exchange is not established on that
// connection yet, so the UE processes it (§4.4.4.2) and registers again.

#include <gtest/gtest.h>


#include "net_rig.hpp"

namespace ksim::proctest {
namespace {

TEST(Identification, Ts24501_4_4_4_2_APlainIdentityRequestForTheSuciIsAnsweredWhenTheAmfForgotTheUe) {
    corestub::Profile p;
    p.forget_on_deregistration = true;
    Net n(p);
    n.register_ue();
    ASSERT_TRUE(n.ue->deregister(true));   // switch-off: the context and 5G-GUTI go to the card
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    auto on = n.ue->power_on();
    ASSERT_TRUE(on) << on.error().what;
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.accept").size() >= 2; }, n.loop.now() + 10'000))
        << n.failures();
    const auto ids = n.named("nas.mm.identity");   // a copy: the events outlive this line
    ASSERT_EQ(ids.size(), 1u);                     // asked once, answered with the SUCI
    const std::string* type = ids.front().find("type");
    EXPECT_EQ(type != nullptr ? *type : "", "1");
    EXPECT_TRUE(n.named("nas.sec.discard").empty());
    EXPECT_EQ(n.failures(), "");
}

TEST(Identification, Ts24501_4_4_4_2_OnceSecureExchangeIsUpAPlainIdentityRequestIsNotProcessed) {
    Net n;
    n.register_ue();   // the SMC established secure exchange on this connection
    const auto before = n.named("nas.sec.discard").size();
    n.amf.nas()->send_plain_identity_request();
    n.loop.run_until([] { return false; }, n.loop.now() + 500);
    EXPECT_EQ(n.named("nas.sec.discard").size(), before + 1);
}

} // namespace
} // namespace ksim::proctest
