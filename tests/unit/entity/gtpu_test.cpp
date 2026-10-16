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
    const auto dl = UserData::dl_psc(0x10000001, 5, Bytes{0x45, 0x00, 0x00, 0x14});
    auto w = encode(dl);
    ASSERT_TRUE(w);
    auto back = decode_gpdu(*w);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->dl_qfi, std::optional<std::uint8_t>(5));
    EXPECT_FALSE(back->ul_qfi);
    EXPECT_EQ(back->payload, dl.payload);
    back = decode_gpdu(*encode(UserData::ul_psc(0x10000002, 9, Bytes{1, 2, 3})));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->ul_qfi, std::optional<std::uint8_t>(9));
    back = decode_gpdu(*encode(UserData::nru(0x20000001, 0x123456, Bytes{9})));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->nru_sn, std::optional<std::uint32_t>(0x123456));
    EXPECT_FALSE(back->report_polling);
    w = encode(UserData::plain(0x30000001, Bytes{7, 7}));
    ASSERT_TRUE(w);
    EXPECT_EQ(w->size(), 8u + 2u);   // no optional part: the mandatory header and the T-PDU
}

// P2 Q11 (TS 38.415 5.5.2.1, 5.5.3.4): the DL PDU SESSION INFORMATION's RQI, bit 6 of the
// octet with the QFI; a frame without it reads as no RQI.
TEST(Gtpu, Ts38415_5_5_3_4_TheDlFrameCarriesTheRqi) {
    auto w = encode(UserData::dl_psc(0x10000001, 5, Bytes{0x45}, true));
    ASSERT_TRUE(w);
    auto back = decode_gpdu(*w);
    ASSERT_TRUE(back);
    EXPECT_TRUE(back->rqi);
    EXPECT_EQ(back->dl_qfi, std::optional<std::uint8_t>(5));
    // G-PDU header (8), sequence/N-PDU/next-type (4), the container: length, octets 1 and 2.
    ASSERT_GT(w->size(), 14u);
    EXPECT_EQ((*w)[14], 0x40 | 5);
    back = decode_gpdu(*encode(UserData::dl_psc(0x10000001, 5, Bytes{0x45})));
    ASSERT_TRUE(back);
    EXPECT_FALSE(back->rqi);
}

// P2 Q4 (TS 38.425 5.5.2.1, 5.5.2.2): the DL USER DATA's Report Polling flag, and a
// DL DATA DELIVERY STATUS alone in a G-PDU (no T-PDU) with its SNs and the polled frame.
TEST(Gtpu, ReportPollingAndDeliveryStatusRoundTrip) {
    auto polled = UserData::nru(0x20000001, 77, Bytes{0x80, 0x00, 0x05});
    polled.report_polling = true;
    auto back = decode_gpdu(*encode(polled));
    ASSERT_TRUE(back);
    EXPECT_TRUE(back->report_polling);
    EXPECT_EQ(back->nru_sn, std::optional<std::uint32_t>(77));

    DeliveryStatus s;
    s.desired_buffer = 8U << 20;
    s.highest_delivered = 0x2ABCD;
    s.highest_transmitted = 0x2ABCD;
    s.polling_nru_sn = 77;
    auto status = UserData::plain(0x10000009, Bytes{});
    status.ddds = s;
    auto w = encode(status);
    ASSERT_TRUE(w);
    back = decode_gpdu(*w);
    ASSERT_TRUE(back);
    ASSERT_TRUE(back->ddds);
    EXPECT_EQ(*back->ddds, s);
    EXPECT_TRUE(back->payload.empty());
    EXPECT_FALSE(back->nru_sn);

    DeliveryStatus initial;   // before any PDU: the buffer size alone (5.4.2.1)
    initial.desired_buffer = 1000;
    status.ddds = initial;
    back = decode_gpdu(*encode(status));
    ASSERT_TRUE(back && back->ddds);
    EXPECT_EQ(*back->ddds, initial);
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
    ASSERT_TRUE(p.a.send(p.b.local(), UserData::ul_psc(teid, 1, Bytes{1})));
    ASSERT_TRUE(p.a.send(p.b.local(), UserData::ul_psc(teid + 1, 1, Bytes{2})));   // nobody there
    p.loop.run_for(10);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], Bytes{1});
    EXPECT_EQ(p.b.stats().unknown_teid, 1u);
    EXPECT_EQ(p.a.stats().error_indications, 1u);
    EXPECT_EQ(reported, teid + 1);
    p.b.unbind(teid);
    ASSERT_TRUE(p.a.send(p.b.local(), UserData::ul_psc(teid, 1, Bytes{3})));
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
