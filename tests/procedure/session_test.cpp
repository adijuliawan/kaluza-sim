// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// PDU sessions end to end in virtual time (P1 N10): a UE device (5GMM, 5GSM,
// RRC and its soft card) over KAIR to the DU; F1-C and E1 over memlink as
// encoded F1AP and E1AP; F1-U and N3 as GTP-U datagrams over a MemNet; NG-C
// to the core stub's AMF, its SMF and its UPF with the DN reflector. A ping
// from the UE crosses SDAP, PDCP with 128-NEA2 on the DRB, F1-U with NR-U, the
// CU-UP, N3 with the PDU Session Container, and comes back.

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "../unit/uicc_card/fixture.hpp"
#include "codec/asn1/msg/e1ap.hpp"
#include "ngap_amf.hpp"
#include "node/ue/device.hpp"
#include "platform/memlink.hpp"
#include "platform/mutation.hpp"
#include "platform/sim_loop.hpp"
#include "proc/ran/cucp.hpp"
#include "proc/ran/cuup.hpp"
#include "proc/ran/du.hpp"

namespace ksim::proctest {
namespace {

const char* kSupi = "001010000300001";
const nas::ie::Plmn kPlmn{"001", "01"};
const std::string kUe = std::string("ue:imsi-") + kSupi;

std::unique_ptr<IDatagram> port(MemNet& net, SimLoop& loop, std::uint8_t host) {
    auto p = net.bind(loop, Endpoint::v4(127, 0, 0, host, 2152));
    return p ? std::move(*p) : nullptr;
}

proc::ran::CuUpConfig cuup_config() {
    proc::ran::CuUpConfig c;
    c.n3_addr = {127, 0, 0, 31};
    c.f1u_addr = {127, 0, 0, 32};
    return c;
}

proc::ran::DuConfig du_config() {
    proc::ran::DuConfig c;
    c.f1u_addr = {127, 0, 0, 33};
    return c;
}

struct Net {
    explicit Net(corestub::Profile p = {})
        : amf(loop, home, kPlmn, std::move(p), ng.b(), upf_port.get(), {127, 0, 0, 9}) {
        home.add(kSupi, uicc::test::sb("465b5ce8b199b49faa5f0a2ee238a6bc"), uicc::test::sb("cd63cb71954a9f4e48a5994e37a02baf"));
        node::UeDeviceConfig uc;
        uc.supi = kSupi;
        uc.radio_id = 7;
        uc.plmn = kPlmn;
        uc.nssai = {nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}};
        uc.imeisv = "8600000000000101";
        uc.seed = 5;
        ue = std::make_unique<node::UeDevice>(loop, events, uc, uicc::test::make_card(), [this](const air::Frame& f) {
            loop.start_timer(1, [this, f] { du.on_frame(f); });
        }, node::UeTaps{});
    }

    void start() {
        f1.connect();
        e1.connect();
        ng.connect();
        ASSERT_TRUE(loop.run_until([&] { return cucp.ng_ready() && du.cell_active() && cucp.e1_ready(); }, loop.now() + 1'000));
    }
    void register_ue() {
        start();
        ASSERT_TRUE(ue->power_on());
        ASSERT_TRUE(loop.run_until([&] { return !named("nas.reg.complete").empty(); }, loop.now() + 15'000));
        ASSERT_TRUE(loop.run_until([&] { return amf.count("InitialContextSetupResponse") == 1; }, loop.now() + 1'000));
    }
    /// Asks for a session and waits for the accept and the gNB's resources.
    void establish(const std::string& dnn = "internet") {
        const auto before = named("nas.sm.est.accept").size();
        const auto setups = named("ran.session.setup").size();
        ASSERT_TRUE(ue->ps_establish(proc::ue::SessionRequest{0, dnn, nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}}));
        ASSERT_TRUE(loop.run_until([&] {
            return named("nas.sm.est.accept").size() > before && named("ran.session.setup").size() > setups &&
                   amf.count("PDUSessionResourceSetupResponse") > setups;
        }, loop.now() + 5'000)) << failures();
    }
    std::vector<Event> named(std::string_view name) const {
        std::vector<Event> out;
        for (auto& e : events.since(0, 65536)) {
            if (e.name == name) {
                out.push_back(e);
            }
        }
        return out;
    }
    std::string failures() const {
        std::string out;
        for (const auto& v : amf.failures()) {
            out += "[" + v.clause + "] " + v.what + (v.detail.empty() ? "" : " (" + v.detail + ")") + "\n";
        }
        return out;
    }
    const Event* last(std::string_view name) const {
        static thread_local std::vector<Event> keep;
        keep = named(name);
        return keep.empty() ? nullptr : &keep.back();
    }

    SimLoop loop{0};
    EventRing events{65536, loop.clock()};
    corestub::Home home{Rng(7, {1})};
    MemAssocPair f1{loop, Endpoint::v4(127, 0, 0, 3, 0), loop, Endpoint::v4(127, 0, 0, 2, 38472), 2};
    MemAssocPair e1{loop, Endpoint::v4(127, 0, 0, 31, 0), loop, Endpoint::v4(127, 0, 0, 2, 38462), 2};
    MemAssocPair ng{loop, Endpoint::v4(127, 0, 0, 2, 0), loop, Endpoint::v4(127, 0, 0, 1, 38412), 3};
    MemNet net;
    std::unique_ptr<IDatagram> upf_port = port(net, loop, 9);
    std::unique_ptr<IDatagram> cuup_n3 = port(net, loop, 31);
    std::unique_ptr<IDatagram> cuup_f1u = port(net, loop, 32);
    std::unique_ptr<IDatagram> du_f1u = port(net, loop, 33);
    corestub::NgapAmf amf;
    proc::ran::CuCp cucp{loop, events, proc::ran::CuCpConfig{}, ng.a(), f1.b(), &e1.b()};
    proc::ran::CuUp cuup{loop, events, cuup_config(), e1.a(), *cuup_n3, *cuup_f1u};
    proc::ran::Du du{loop, events, du_config(), f1.a(),
                     [this](const air::Frame& f) {
                         loop.start_timer(1, [this, f] {
                             if (f.radio_id == 0 || f.radio_id == 7) {
                                 ue->on_frame(f);
                             }
                         });
                     },
                     du_f1u.get()};
    std::unique_ptr<node::UeDevice> ue;
};

TEST(Session, E1_8_2_1_TheCuUpSetsUpE1WithTheCuCp) {
    Net n;
    n.start();
    EXPECT_EQ(n.named("ran.e1.setup").size(), 2u);   // the CU-CP's and the CU-UP's
}

TEST(Session, Ts24501_6_4_1_AnIpv4SessionIsEstablishedWithAddressDnsAndMtu) {
    Net n;
    n.register_ue();
    n.establish();
    const Event* a = n.last("nas.sm.est.accept");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(*a->find("psi"), "1");
    EXPECT_EQ(*a->find("ip"), "10.60.0.2");
    EXPECT_EQ(*a->find("dns"), "10.60.0.1");
    EXPECT_EQ(*a->find("mtu"), "1400");
    EXPECT_EQ(*a->find("qfi"), "1");
    EXPECT_EQ(*a->find("dnn"), "internet");
    const auto list = n.ue->sessions();
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].state, proc::ue::SmState::active);
    EXPECT_EQ(n.cucp.sessions_of(n.amf.ids(0)->ran), std::vector<std::uint8_t>{1});
    EXPECT_EQ(n.cuup.stats().contexts_setup, 1u);
    EXPECT_EQ(n.failures(), "");
    EXPECT_TRUE(n.named("core.anomaly").empty());
}

TEST(Session, APingCrossesTheWholeUserPlaneWithNea2OnTheDrb) {
    Net n;
    n.register_ue();
    n.establish();
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 3;
    p.interval = 200;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 5'000));
    const Event* d = n.last("ue.ping.done");
    EXPECT_EQ(*d->find("sent"), "3");
    EXPECT_EQ(*d->find("received"), "3");
    EXPECT_EQ(*d->find("loss_pct"), "0");
    EXPECT_EQ(n.named("ue.ping.reply").size(), 3u);
    ASSERT_NE(n.amf.upf(), nullptr);
    EXPECT_EQ(n.amf.upf()->stats().echo_replies, 3u);
    EXPECT_EQ(n.cuup.stats().ul_packets, 3u);
    EXPECT_EQ(n.cuup.stats().dl_packets, 3u);
    EXPECT_EQ(n.du.stats().ul_user, 3u);
    EXPECT_EQ(n.du.stats().dl_user, 3u);
    // The DRB was set up with the UP keys: 128-NEA2, no integrity (the policy said "not-needed").
    const auto setup = n.named("ran.session.setup");
    ASSERT_EQ(setup.size(), 1u);
    EXPECT_EQ(*setup[0].find("integrity"), "0");
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, ADnPingToTheUeIsAnswered) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.amf.smf().ping_ue(kSupi, 1, 1));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.upf()->stats().echo_from_ue == 1; }, n.loop.now() + 1'000));
    EXPECT_EQ(n.named("ue.ping.answered").size(), 1u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_4_3_TheUeReleasesItsSession) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.ue->ps_release(1));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceReleaseResponse") == 1 && n.amf.smf().sessions() == 0; },
                                 n.loop.now() + 5'000)) << n.failures();
    const Event* c = n.last("nas.sm.rel.command");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(*c->find("network"), "0");
    EXPECT_TRUE(n.ue->sessions().empty());
    EXPECT_TRUE(n.cucp.sessions_of(n.amf.ids(0)->ran).empty());
    EXPECT_EQ(n.named("ran.cuup.bearer.release").size(), 1u);   // the last session: the bearer context went
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_3_3_TheNetworkReleasesASession) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.amf.nas()->release_session(1, 36));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceReleaseResponse") == 1 && n.amf.smf().sessions() == 0; },
                                 n.loop.now() + 5'000)) << n.failures();
    const Event* c = n.last("nas.sm.rel.command");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(*c->find("network"), "1");
    EXPECT_EQ(*c->find("cause"), "36");
    EXPECT_TRUE(n.ue->sessions().empty());
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, TwoSessionsGetTwoDrbsAndBothCarryPings) {
    Net n;
    n.register_ue();
    n.establish("internet");
    n.establish("ims");
    const auto list = n.ue->sessions();
    ASSERT_EQ(list.size(), 2u);
    EXPECT_EQ(list[0].dnn, "internet");
    EXPECT_EQ(list[1].dnn, "ims");
    EXPECT_EQ(n.cucp.sessions_of(n.amf.ids(0)->ran).size(), 2u);
    for (std::uint8_t psi : {std::uint8_t{1}, std::uint8_t{2}}) {
        const auto done = n.named("ue.ping.done").size();
        node::PingRequest p;
        p.psi = psi;
        p.dst = {10, 60, 0, 1};
        p.count = 2;
        p.interval = 100;
        ASSERT_TRUE(n.ue->ping(p));
        ASSERT_TRUE(n.loop.run_until([&] { return n.named("ue.ping.done").size() > done; }, n.loop.now() + 5'000));
        EXPECT_EQ(*n.last("ue.ping.done")->find("received"), "2") << int{psi};
    }
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_4_1_4_3_AfterA29WithABackOffTheUeWaitsItOut) {
    corestub::Profile p;
    p.session.establishment = corestub::SessionProfile::Establishment::reject;
    p.session.reject_cause = 29;
    p.session.backoff_s = 60;
    p.session.rejects = 1;
    Net n(p);
    n.register_ue();
    const proc::ue::SessionRequest req{0, "internet", nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}};
    ASSERT_TRUE(n.ue->ps_establish(req));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.reject").empty(); }, n.loop.now() + 5'000));
    const Event* b = n.last("nas.sm.backoff");
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(*b->find("seconds"), "60");
    EXPECT_EQ(*b->find("cause"), "29");
    // Asked again at once: refused locally, nothing sent.
    EXPECT_FALSE(n.ue->ps_establish(req));
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    EXPECT_EQ(n.amf.smf().requests(), 1);
    EXPECT_EQ(n.named("nas.sm.backoff.blocked").size(), 1u);
    // After the timer: the request goes and is accepted.
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.backoff.expiry").empty(); }, n.loop.now() + 61'000));
    ASSERT_TRUE(n.ue->ps_establish(req));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.accept").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(n.amf.smf().requests(), 2);
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_4_1_3_AnAcceptWithoutADefaultQosRuleIsReleasedWith83) {
    corestub::Profile p;
    p.session.default_rule = false;
    Net n(p);
    n.register_ue();
    ASSERT_TRUE(n.ue->ps_establish(proc::ue::SessionRequest{0, "internet", std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("core.anomaly").empty(); }, n.loop.now() + 5'000));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.smf().sessions() == 0; }, n.loop.now() + 5'000));
    EXPECT_EQ(*n.last("nas.sm.rel.command")->find("network"), "0");
}

TEST(Session, Ts24501_6_4_1_6_T3580RetransmitsFourTimesThenAborts) {
    corestub::Profile p;
    p.session.establishment = corestub::SessionProfile::Establishment::silent;
    Net n(p);
    n.register_ue();
    ASSERT_TRUE(n.ue->ps_establish(proc::ue::SessionRequest{0, "internet", std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.abort").empty(); }, n.loop.now() + Millis{5 * 16'000 + 1'000}));
    EXPECT_EQ(n.named("nas.sm.timer.expiry").size(), 5u);
    EXPECT_EQ(n.amf.smf().requests(), 5);   // the request and four retransmissions
    EXPECT_TRUE(n.ue->sessions().empty());
}

TEST(Session, Ts24501_6_3_2_ANetworkModificationIsCompleted) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.amf.nas()->modify_session(1, 200));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.smf().completes() == 1; }, n.loop.now() + 5'000));
    EXPECT_EQ(*n.last("nas.sm.mod.command")->find("ambr_dl"), "200000000");
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts38413_8_2_1_ADuplicatePsiIsRefusedByTheGnb) {
    Net n;
    n.register_ue();
    n.establish();
    const auto ids = n.amf.ids(0);
    ASSERT_TRUE(ids.has_value());
    ngap::PduSessionResourceSetupRequest r;
    r.amf = ids->amf;
    r.ran = ids->ran;
    ngap::SessionSetupItem item;
    item.psi = 1;
    item.snssai = ngap::Snssai{1, std::nullopt};
    item.transfer.ul = ngap::GtpTunnel{{127, 0, 0, 9}, 0x51000099};
    item.transfer.flows = {ngap::QosFlowRequest{}};
    r.sessions = {item};
    n.amf.send(r, 1);
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceSetupResponse") == 2; }, n.loop.now() + 2'000));
    EXPECT_EQ(n.named("ran.session.failure").size(), 1u);
    EXPECT_EQ(n.cucp.sessions_of(ids->ran), std::vector<std::uint8_t>{1});   // the first one still stands
}

TEST(Session, Ts29281_7_3_1_AGpduToAnUnknownTeidIsAnsweredWithAnErrorIndication) {
    Net n;
    n.start();
    auto probe = port(n.net, n.loop, 40);
    ASSERT_NE(probe, nullptr);
    entity::gtpu::Endpoint ep(*probe, 0x77);
    int errors = 0;
    ep.on_error_indication([&](std::uint32_t, const Endpoint&) { ++errors; });
    ASSERT_TRUE(ep.send(Endpoint::v4(127, 0, 0, 31, 2152), entity::gtpu::UserData{0x31ABCDEF, 1, std::nullopt, std::nullopt, Bytes{0x45}}));
    bool echoed = false;
    ASSERT_TRUE(ep.echo(Endpoint::v4(127, 0, 0, 31, 2152), [&] { echoed = true; }));
    ASSERT_TRUE(n.loop.run_until([&] { return errors == 1 && echoed; }, n.loop.now() + 1'000));
}

TEST(Session, Mutant_ignore_backoff_SendsTheRequestWhileTheTimerRuns) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("ignore_backoff");
    corestub::Profile p;
    p.session.establishment = corestub::SessionProfile::Establishment::reject;
    p.session.reject_cause = 29;
    p.session.backoff_s = 60;
    p.session.rejects = 1;
    Net n(p);
    n.register_ue();
    const proc::ue::SessionRequest req{0, "internet", std::nullopt};
    ASSERT_TRUE(n.ue->ps_establish(req));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.reject").empty(); }, n.loop.now() + 5'000));
    EXPECT_TRUE(n.ue->ps_establish(req));
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    EXPECT_EQ(n.amf.smf().requests(), 2);   // the planted fault: the back-off was not honoured
}

} // namespace
} // namespace ksim::proctest
