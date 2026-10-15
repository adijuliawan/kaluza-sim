// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The card seen from a run (P1 N14; sim-uicc.md §3, §6): sim info and sim
// read on the UE's card, and its APDU trace during a registration, with what
// redaction masks there: CK and IK in the AUTHENTICATE answer, the NAS
// security context and EF.5GAUTHKEYS as the ME writes them.

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

#include "net_rig.hpp"
#include "uicc/trace/trace.hpp"

namespace ksim::proctest {
namespace {

TEST(Card, SimInfoShowsTheIdentityAndServicesAndNoKey) {
    Net n;
    const node::SimInfo i = n.ue->sim_info();
    EXPECT_TRUE(i.present);
    EXPECT_EQ(i.imsi, kSupi);
    EXPECT_EQ(i.iccid, "8988211000000300001");
    EXPECT_EQ(i.msisdn, "99900300001");
    EXPECT_EQ(i.suci_schemes, "0");   // the null scheme (D6)
    EXPECT_EQ(i.routing_indicator, "0000");
    for (unsigned s : {10u, 12u, 122u, 123u, 124u, 126u, 129u, 133u}) {
        EXPECT_NE(std::find(i.ust.begin(), i.ust.end(), s), i.ust.end()) << s;
    }
    EXPECT_EQ(std::find(i.ust.begin(), i.ust.end(), 125u), i.ust.end());   // SUCI by the ME
}

TEST(Card, SimReadTakesNamesFidsAndPathsAndRefusesKeys) {
    Net n;
    auto imsi = n.ue->sim_read("IMSI");
    ASSERT_TRUE(imsi);
    EXPECT_EQ(imsi->name, "EF.IMSI");
    EXPECT_EQ(imsi->path, "3F00/7FF0/6F07");
    EXPECT_EQ(to_hex(imsi->contents.at(0)), "080910100000030010");
    auto loci = n.ue->sim_read("5fc0/4f01");
    ASSERT_TRUE(loci);
    EXPECT_EQ(loci->name, "EF.5GS3GPPLOCI");
    auto sms = n.ue->sim_read("ef.sms");
    ASSERT_TRUE(sms);
    EXPECT_TRUE(sms->records);
    EXPECT_EQ(sms->contents.size(), 10u);
    for (const char* key : {"4F03", "4F04", "EF.5GAUTHKEYS", "AF20", "EF.USIM_SQN", "EF.KEYS", "6F09"}) {
        EXPECT_FALSE(n.ue->sim_read(key)) << key;
    }
    EXPECT_FALSE(n.ue->sim_read("6FFF"));
}

TEST(Card, TheTraceOfARegistrationKeepsTheKeysOut) {
    Net n;
    ASSERT_TRUE(n.ue->sim_trace(true));
    EXPECT_FALSE(n.ue->sim_trace(true));   // on already
    n.register_ue();
    // §4.4.2.1.3: entering deregistered, the ME writes its context and keys to the card.
    ASSERT_TRUE(n.ue->deregister(false));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.dereg.accept").empty(); }, n.loop.now() + 3'000));
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    ASSERT_FALSE(n.sim_records.empty());
    bool auth = false;
    std::size_t key_writes = 0;
    for (const auto& [sub, p] : n.sim_records) {
        if (sub != uicc::trace::kSubApdu || p.size() < 5) {
            continue;
        }
        if (p[1] == 0x88) {   // AUTHENTICATE: the command, then DB L RES 10 CK 10 IK
            auth = true;
            const std::size_t at = 5 + p[4];
            ASSERT_GT(p.size(), at + 36);
            ASSERT_EQ(p[at], 0xDB);
            const std::size_t ck = at + 2 + p[at + 1];
            ASSERT_EQ(p[ck], 0x10);
            EXPECT_EQ(std::count(p.begin() + static_cast<std::ptrdiff_t>(ck + 1), p.begin() + static_cast<std::ptrdiff_t>(ck + 17), 0), 16);
            ASSERT_EQ(p[ck + 17], 0x10);
            EXPECT_EQ(std::count(p.begin() + static_cast<std::ptrdiff_t>(ck + 18), p.begin() + static_cast<std::ptrdiff_t>(ck + 34), 0), 16);
        }
        // The NAS security context (a record) and EF.5GAUTHKEYS as the ME writes them: all zero.
        if ((p[1] == 0xD6 || p[1] == 0xDC) && p[4] >= 57) {
            ++key_writes;
            EXPECT_EQ(std::count(p.begin() + 5, p.begin() + 5 + p[4], 0), p[4]) << to_hex(p);
        }
    }
    EXPECT_TRUE(auth);
    EXPECT_GE(key_writes, 2u);   // 4F03 and 4F05
    const auto before = n.sim_records.size();
    ASSERT_TRUE(n.ue->sim_trace(false));
    ASSERT_TRUE(n.ue->register_initial());
    n.loop.run_until([&] { return n.named("nas.reg.accept").size() >= 2; }, n.loop.now() + 3'000);
    EXPECT_EQ(n.sim_records.size(), before);   // off: nothing more
    EXPECT_EQ(n.failures(), "");
}

} // namespace
} // namespace ksim::proctest
