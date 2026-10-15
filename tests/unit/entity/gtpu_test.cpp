// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The GTP-U endpoint (P1 N10; TS 29.281 j00 7.2, 7.3; TS 38.415; TS 38.425):
// G-PDUs with the PDU Session Container both ways and with the NR-U DL user
// data header, Echo answered, Error Indication for an unknown TEID sent and
// reported at the other end.

#include <gtest/gtest.h>

#include "entity/gtpu/gtpu.hpp"
#include "platform/memlink.hpp"
#include "platform/sim_loop.hpp"

namespace ksim::entity::gtpu {
namespace {

TEST(Gtpu, UserDataRoundTripsWithEachExtension) {
    UserData dl{0x10000001, 5, std::nullopt, std::nullopt, Bytes{0x45, 0x00, 0x00, 0x14}};
    auto w = encode(dl);
    ASSERT_TRUE(w);
    auto back = decode_gpdu(*w);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->dl_qfi, std::optional<std::uint8_t>(5));
    EXPECT_FALSE(back->ul_qfi);
    EXPECT_EQ(back->payload, dl.payload);
    UserData ul{0x10000002, std::nullopt, 9, std::nullopt, Bytes{1, 2, 3}};
    back = decode_gpdu(*encode(ul));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->ul_qfi, std::optional<std::uint8_t>(9));
    UserData nru{0x20000001, std::nullopt, std::nullopt, 0x123456, Bytes{9}};
    back = decode_gpdu(*encode(nru));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->nru_sn, std::optional<std::uint32_t>(0x123456));
    UserData plain{0x30000001, std::nullopt, std::nullopt, std::nullopt, Bytes{7, 7}};
    w = encode(plain);
    ASSERT_TRUE(w);
    EXPECT_EQ(w->size(), 8u + 2u);   // no optional part: the mandatory header and the T-PDU
}

std::unique_ptr<IDatagram> bound(MemNet& net, Executor& ex, const ksim::Endpoint& at) {
    auto r = net.bind(ex, at);
    EXPECT_TRUE(r);
    return r ? std::move(*r) : nullptr;
}

struct Pair {
    SimLoop loop{0};
    MemNet net;
    std::unique_ptr<IDatagram> a_port = bound(net, loop, ksim::Endpoint::v4(127, 0, 0, 3, 2152));
    std::unique_ptr<IDatagram> b_port = bound(net, loop, ksim::Endpoint::v4(127, 0, 0, 4, 2152));
    gtpu::Endpoint a{*a_port, 0x10};
    gtpu::Endpoint b{*b_port, 0x20};
};

TEST(Gtpu, TunnelsDeliverByTeidAndAnUnknownTeidGetsAnErrorIndication) {
    Pair p;
    std::vector<Bytes> got;
    const std::uint32_t teid = p.b.bind([&](const UserData& d, const ksim::Endpoint&) { got.push_back(d.payload); });
    EXPECT_EQ(teid >> 24, 0x20u);
    std::uint32_t reported = 0;
    p.a.on_error_indication([&](std::uint32_t t, const ksim::Endpoint&) { reported = t; });
    ASSERT_TRUE(p.a.send(p.b.local(), UserData{teid, std::nullopt, 1, std::nullopt, Bytes{1}}));
    ASSERT_TRUE(p.a.send(p.b.local(), UserData{teid + 1, std::nullopt, 1, std::nullopt, Bytes{2}}));   // nobody there
    p.loop.run_for(10);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], Bytes{1});
    EXPECT_EQ(p.b.stats().unknown_teid, 1u);
    EXPECT_EQ(p.a.stats().error_indications, 1u);
    EXPECT_EQ(reported, teid + 1);
    p.b.unbind(teid);
    ASSERT_TRUE(p.a.send(p.b.local(), UserData{teid, std::nullopt, 1, std::nullopt, Bytes{3}}));
    p.loop.run_for(10);
    EXPECT_EQ(got.size(), 1u);
    EXPECT_EQ(p.b.stats().unknown_teid, 2u);
}

TEST(Gtpu, EchoIsAnswered) {
    Pair p;
    int answers = 0;
    ASSERT_TRUE(p.a.echo(p.b.local(), [&] { ++answers; }));
    p.loop.run_for(10);
    EXPECT_EQ(answers, 1);
    EXPECT_EQ(p.b.stats().echo_requests, 1u);
    EXPECT_EQ(p.a.stats().echo_responses, 1u);
}

} // namespace
} // namespace ksim::entity::gtpu
