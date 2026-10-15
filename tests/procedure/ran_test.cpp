// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The whole P1 control path in virtual time (P1 N7): a UE (its 5GMM entity,
// RRC and soft card) over KAIR to the DU, over F1 (memlink, encoded F1AP) to
// the CU-CP, over NG-C (memlink, encoded NGAP) to the core stub's AMF with its
// NAS side and home functions. Every NAS, RRC, F1AP and NGAP message is built
// and read by kaluza-sim's codecs on the way; the stub records its verdicts at
// NAS and NGAP level, and the TS 38.413 §10 cases are driven from the stub.

#include <gtest/gtest.h>

#include <fstream>
#include <memory>
#include <set>
#include <sstream>

#include "../unit/uicc_card/fixture.hpp"
#include "ngap_amf.hpp"
#include "platform/memlink.hpp"
#include "platform/mutation.hpp"
#include "platform/sim_loop.hpp"
#include "proc/ran/cucp.hpp"
#include "proc/ran/du.hpp"
#include "proc/ue/nas_mm/mm.hpp"
#include "proc/ue/rrc/rrc.hpp"
#include "uicc/terminal/terminal.hpp"

namespace ksim::proctest {
namespace {

using proc::ue::MmState;

const char* kSupi = "001010000300001";

std::string field(const Event& e, std::string_view key) {
    const std::string* v = e.find(key);
    return v != nullptr ? *v : std::string("<none>");
}
const nas::ie::Plmn kPlmn{"001", "01"};

/// The DU's end of F1, recording the stream of each message it sends (P2 Q2, ksim-p2.per-ue-stream).
class StreamTap final : public IAssoc {
public:
    explicit StreamTap(IAssoc& in) : in_(in) {}
    void set_handlers(OnMessage m, OnEvent e) override { in_.set_handlers(std::move(m), std::move(e)); }
    Result<void> send(ByteView msg, SctpMeta meta) override {
        streams.push_back(meta.stream);
        return in_.send(msg, meta);
    }
    bool up() const noexcept override { return in_.up(); }
    std::uint16_t out_streams() const noexcept override { return in_.out_streams(); }
    std::uint16_t in_streams() const noexcept override { return in_.in_streams(); }
    void shutdown() override { in_.shutdown(); }
    void abort() override { in_.abort(); }
    Endpoint peer() const override { return in_.peer(); }

    std::vector<std::uint16_t> streams;

private:
    IAssoc& in_;
};

struct Gnb {
    explicit Gnb(corestub::Profile p = {}) : amf(loop, home, kPlmn, std::move(p), ng.b()) {
        home.add(kSupi, uicc::test::sb("465b5ce8b199b49faa5f0a2ee238a6bc"), uicc::test::sb("cd63cb71954a9f4e48a5994e37a02baf"));
        // The UE: RRC first (it is the 5GMM entity's lower layer), then 5GMM.
        proc::ue::RrcConfig rc;
        rc.id = "ue:1";
        rc.plmn = {"001", "01"};
        rc.mac.radio_id = 7;
        proc::ue::RrcUpper up;
        up.nas = [this](Bytes b) { mm->on_nas(b); };
        up.released = [this] { mm->on_released(); };
        up.kgnb = [this] { return mm->kgnb(); };
        up.s_tmsi = [this] { return mm->s_tmsi(); };
        up.paged = [this] { ++paged; };
        rrc = std::make_unique<proc::ue::UeRrc>(loop, Rng(5, {1}), events, rc, up, [this](const air::Frame& f) {
            loop.start_timer(1, [this, f] { du.on_frame(f); });
        });
        proc::ue::MmConfig mc;
        mc.id = "ue:1";
        mc.plmn = kPlmn;
        mc.requested_nssai = {nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}};
        mc.imeisv = "8600000000000101";
        mm = std::make_unique<proc::ue::Mm>(loop, terminal, *rrc, events, mc);
    }
    ~Gnb() {
    // The in-process card answers on the loop's next turn (uicc/transport): a
    // card write still in flight (N12 writes at accepts and de-registrations)
    // finishes before the UE goes, so no procedure is left suspended.
        loop.run_until([] { return false; }, loop.now() + 1);
    }
    Gnb(const Gnb&) = delete;
    Gnb& operator=(const Gnb&) = delete;

    /// F1 and NG-C up, F1 Setup and NG Setup done, the cell on air.
    void start() {
        f1.connect();
        ng.connect();
        ASSERT_TRUE(loop.run_until([&] { return cucp.ng_ready() && du.cell_active(); }, loop.now() + 1'000));
    }
    /// Powered on, camped and registered.
    void register_ue() {
        start();
        mm->power_on();
        ASSERT_TRUE(loop.run_until([&] { return rrc->camped() && mm->state() != MmState::null; }, loop.now() + 1'000));
        mm->register_initial();
        ASSERT_TRUE(loop.run_until([&] { return mm->state() == MmState::registered_normal_service; },
                                   loop.now() + 10'000));
        ASSERT_TRUE(loop.run_until([&] { return amf.count("InitialContextSetupResponse") == 1; }, loop.now() + 1'000));
    }
    std::vector<Event> named(std::string_view name) const {
        std::vector<Event> out;
        for (auto& e : events.since(0)) {
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

    SimLoop loop{0};
    EventRing events{16384, loop.clock()};
    corestub::Home home{Rng(7, {1})};
    MemAssocPair f1{loop, Endpoint::v4(127, 0, 0, 3, 0), loop, Endpoint::v4(127, 0, 0, 2, 38472), 4};
    StreamTap du_f1{f1.a()};
    MemAssocPair ng{loop, Endpoint::v4(127, 0, 0, 2, 0), loop, Endpoint::v4(127, 0, 0, 1, 38412), 3};
    corestub::NgapAmf amf;
    proc::ran::CuCp cucp{loop, events, proc::ran::CuCpConfig{}, ng.a(), f1.b()};
    proc::ran::Du du{loop, events, proc::ran::DuConfig{}, du_f1, [this](const air::Frame& f) {
                         loop.start_timer(1, [this, f] {
                             if (f.radio_id == 0 || f.radio_id == 7) {
                                 rrc->on_frame(f);
                             }
                         });
                     }};
    std::unique_ptr<uicc::os::Card> card = uicc::test::make_card();
    uicc::InProcTransport transport{loop, card.get()};
    uicc::Terminal terminal{transport};
    std::unique_ptr<proc::ue::UeRrc> rrc;
    std::unique_ptr<proc::ue::Mm> mm;
    int paged = 0;
};

TEST(Ran, Ngap8_7_1_F1SetupThenNgSetupPutTheCellOnAir) {
    Gnb g;
    g.start();
    EXPECT_EQ(g.amf.count("NGSetupRequest"), 1u);
    EXPECT_EQ(g.named("ran.f1.setup").size(), 2u);   // the DU's and the CU-CP's
    EXPECT_EQ(g.named("ran.ng.setup").size(), 1u);
    EXPECT_EQ(g.failures(), "");
}

TEST(Ran, AUeRegistersThroughKairF1AndNgapWithNia2Nea2AtAs) {
    Gnb g;
    g.register_ue();
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.nas() != nullptr && g.amf.nas()->registered(); }, g.loop.now() + 1'000));
    EXPECT_EQ(g.failures(), "");
    EXPECT_TRUE(g.rrc->as_security());
    const auto smc = g.named("rrc.smc.complete");
    ASSERT_EQ(smc.size(), 1u);
    EXPECT_EQ(*smc[0].find("alg"), "nia2/nea2");
    EXPECT_EQ(g.cucp.stats().ics_ok, 1u);
    // No radio capability in the request: the CU-CP asked the UE and told the AMF.
    EXPECT_EQ(g.amf.count("UERadioCapabilityInfoIndication"), 1u);
    EXPECT_EQ(g.amf.count("InitialUEMessage"), 1u);
    EXPECT_GE(g.amf.count("UplinkNASTransport"), 3u);   // AUTH RESPONSE, SMC COMPLETE, REGISTRATION COMPLETE
    EXPECT_NE(g.rrc->srb(2), nullptr);
    EXPECT_EQ(g.mm->unlisted_transitions(), 0u);
}

TEST(Ran, ADeregistrationEndsInAReleaseThroughF1) {
    Gnb g;
    g.register_ue();
    g.mm->deregister(false);
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.count("UEContextReleaseComplete") == 1; }, g.loop.now() + 5'000));
    ASSERT_TRUE(g.loop.run_until([&] { return g.rrc->state() == proc::ue::RrcState::idle; }, g.loop.now() + 1'000));
    EXPECT_EQ(g.mm->state(), MmState::deregistered_normal_service);
    EXPECT_EQ(g.cucp.ues(), 0u);
    EXPECT_EQ(g.du.ues(), 0u);
    EXPECT_EQ(g.failures(), "");
}

TEST(Ran, Ngap8_2_1_PagingForTheUesSTmsiReachesItInIdle) {
    Gnb g;
    g.register_ue();
    auto ids = g.amf.ids(0);
    ASSERT_TRUE(ids);
    g.amf.release(0, ngap::Cause{"radioNetwork", "user-inactivity"});
    ASSERT_TRUE(g.loop.run_until([&] { return g.rrc->state() == proc::ue::RrcState::idle; }, g.loop.now() + 1'000));
    ASSERT_TRUE(g.mm->s_tmsi());
    const ngap::Tai tai{ngap::plmn_id("001", "01"), 1};
    g.amf.send(ngap::Paging{ngap::FiveGSTmsi::of(*g.mm->s_tmsi()), {tai}, std::nullopt});
    ASSERT_TRUE(g.loop.run_until([&] { return g.paged == 1; }, g.loop.now() + 1'000));
    EXPECT_EQ(g.named("ran.ngap.paging").size(), 1u);
    EXPECT_EQ(g.named("ran.du.paging").size(), 1u);
}

TEST(Ran, Ngap10_2_AnUndecodablePduGetsATransferSyntaxErrorIndication) {
    Gnb g;
    g.start();
    g.amf.send_raw(*from_hex("ff00ff"));
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.error_indications() == 1; }, g.loop.now() + 1'000));
    ASSERT_TRUE(g.amf.last_error_cause());
    EXPECT_EQ(g.amf.last_error_cause()->value, "transfer-syntax-error");
    EXPECT_TRUE(g.cucp.ng_ready());   // nothing an AMF sends ends the CU-CP (L15)
}

TEST(Ran, Ngap10_6_DownlinkNasForAnUnknownRanUeNgapIdIsReported) {
    Gnb g;
    g.start();
    g.amf.send(ngap::DownlinkNasTransport{99, 4242, {0x7e, 0x00, 0x5b, 0x01}}, 1);
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.error_indications() == 1; }, g.loop.now() + 1'000));
    EXPECT_EQ(g.amf.last_error_cause()->value, "unknown-local-UE-NGAP-ID");
}

/// A PDU SESSION RESOURCE SETUP REQUEST from the external corpus: a procedure
/// with criticality reject that P1 does not take yet (N10).
std::optional<Bytes> corpus_pdu(const std::string& pdu) {
    std::ifstream in(std::string(KSIM_SOURCE_DIR) + "/tests/vectors/ngap/index.tsv");
    std::string line;
    while (std::getline(in, line)) {
        std::vector<std::string> cols;
        std::istringstream ss(line);
        std::string c;
        while (std::getline(ss, c, '\t')) {
            cols.push_back(c);
        }
        if (cols.size() > 3 && cols[2] == pdu) {
            return from_hex(cols.back()).value_or(Bytes{});
        }
    }
    return std::nullopt;
}

TEST(Ran, Ngap10_3_AProcedureOutsideP1WithCriticalityRejectIsReported) {
    Gnb g;
    g.start();
    auto pdu = corpus_pdu("HandoverRequest");   // handover is P3; PDU sessions came in with N10
    ASSERT_TRUE(pdu);
    g.amf.send_raw(*pdu, 1);
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.error_indications() == 1; }, g.loop.now() + 1'000));
    EXPECT_EQ(g.amf.last_error_cause()->value, "abstract-syntax-error-reject");
}

TEST(Ran, Ngap8_7_4_AnNgResetReleasesTheUesAndIsAcknowledged) {
    Gnb g;
    g.register_ue();
    g.amf.send(ngap::NgReset{ngap::Cause{"misc", "om-intervention"}, true, {}});
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.count("NGResetAcknowledge") == 1; }, g.loop.now() + 1'000));
    EXPECT_EQ(g.cucp.ues(), 0u);
    ASSERT_TRUE(g.loop.run_until([&] { return g.du.ues() == 0; }, g.loop.now() + 1'000));
    EXPECT_EQ(g.named("ran.ng.reset").size(), 1u);
}

TEST(Ran, Ngap8_7_3_AnAmfConfigurationUpdateIsAcknowledged) {
    Gnb g;
    g.start();
    g.amf.send(ngap::AmfConfigurationUpdate{"ksim-stub-amf-2"});
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.count("AMFConfigurationUpdateAcknowledge") == 1; },
                                 g.loop.now() + 1'000));
}

// P2 Q2 (row ksim-p2.f1-loss-release; TS 38.413 §8.3.2): F1 lost under a registered UE. The CU-CP asks
// the AMF to release it (radio connection with UE lost), and the release completes with no DU to go through.
TEST(Ran, F1LossAsksTheAmfToReleaseTheUeAndTheReleaseCompletesWithoutTheDu) {
    Gnb g;
    g.register_ue();
    g.f1.a().abort();   // the DU's end goes
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.count("UEContextReleaseComplete") == 1; }, g.loop.now() + 2'000))
        << g.failures();
    EXPECT_EQ(g.amf.count("UEContextReleaseRequest"), 1u);
    ASSERT_FALSE(g.named("ran.f1.lost").empty());
    const auto req = g.named("ran.ue.release_request");
    ASSERT_FALSE(req.empty());
    EXPECT_EQ(field(req.back(), "cause"), "radio-connection-with-ue-lost");
    EXPECT_FALSE(g.cucp.f1_ready());
    EXPECT_TRUE(g.failures().empty()) << g.failures();
}

// P2 Q4 (TS 38.473 8.2.5.2): the gNB-CU takes the DU's cell off the air and puts it back; a cell that
// is not the DU's cannot be activated and is listed so in the acknowledge.
TEST(Ran, F1ap8_2_5_TheGnbCuDeactivatesAndActivatesTheCell) {
    Gnb g;
    g.start();
    ASSERT_TRUE(g.du.cell_active());
    const f1ap::NrCgi own = g.du.cgi();
    f1ap::NrCgi other = own;
    other.nci ^= 1;
    ASSERT_TRUE(g.cucp.cu_configuration_update({}, {own}));
    ASSERT_TRUE(g.loop.run_until([&] { return g.named("ran.f1.cu_config_update").size() == 2; }, g.loop.now() + 1'000));
    EXPECT_FALSE(g.du.cell_active());
    const std::uint64_t si = g.du.stats().si_tx;
    g.loop.run_for(500);
    EXPECT_EQ(g.du.stats().si_tx, si);   // nothing on air
    ASSERT_TRUE(g.cucp.cu_configuration_update({own, other}, {}));
    ASSERT_TRUE(g.loop.run_until([&] { return g.named("ran.f1.cu_config_update").size() == 4; }, g.loop.now() + 1'000));
    EXPECT_TRUE(g.du.cell_active());
    const auto acks = g.named("ran.f1.cu_config_update");
    EXPECT_EQ(field(acks.back(), "failed"), "1");   // the other cell, at the CU-CP
    g.loop.run_for(500);
    EXPECT_GT(g.du.stats().si_tx, si);
    EXPECT_TRUE(g.failures().empty()) << g.failures();
}

// P2 Q4 (TS 38.473 8.3.4.3): a modification the DU can make none of is refused with UE CONTEXT
// MODIFICATION FAILURE; here DRBs without F1-U at the DU.
TEST(Ran, F1ap8_3_4_3_AModificationTheDuCannotMakeIsRefused) {
    Gnb g;
    g.register_ue();
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.nas() != nullptr && g.amf.nas()->registered(); }, g.loop.now() + 1'000));
    f1ap::UeContextModificationRequest m;
    m.cu_ue = 1;
    m.du_ue = 1;
    m.drbs = {f1ap::DrbToSetup{1, f1ap::Snssai{1, std::nullopt}, {f1ap::Flow{1, 9, 8, false, true}},
                               f1ap::GtpTunnel{{127, 0, 0, 4}, 1}, 18, 18}};
    auto wire = f1ap::encode(m);
    ASSERT_TRUE(wire);
    ASSERT_TRUE(g.f1.b().send(*wire, {62, ue_stream(4, 1)}));
    ASSERT_TRUE(g.loop.run_until([&] { return !g.named("ran.f1.ue_mod_failure").empty(); }, g.loop.now() + 1'000));
    EXPECT_EQ(field(g.named("ran.f1.ue_mod_failure").back(), "cause"), "transport/transport-resource-unavailable");
    EXPECT_EQ(g.du.ues(), 1u);   // the UE context stays
}

// P2 Q2 (TS 38.472 §7): non-UE-associated F1AP on stream 0; a UE's on the one stream its ID picks, never 0.
TEST(Ran, EachUeKeepsItsOwnF1StreamAndStreamZeroIsForTheRest) {
    Gnb g;
    g.register_ue();
    ASSERT_GE(g.du_f1.streams.size(), 4u);
    EXPECT_EQ(g.du_f1.streams.front(), 0);   // F1 SETUP REQUEST
    std::set<std::uint16_t> ue_streams(g.du_f1.streams.begin() + 1, g.du_f1.streams.end());
    ASSERT_EQ(ue_streams.size(), 1u);
    EXPECT_EQ(*ue_streams.begin(), ue_stream(4, 1));   // the first UE's gNB-DU UE F1AP ID is 1
    EXPECT_NE(*ue_streams.begin(), 1);                 // what a single shared UE stream would give
}

// P2 Q2 (row ksim-p2.f1-reassociation): F1 back after a loss, the DU sets F1 up again, the cell comes back on
// air, and the UE registers anew through it.
TEST(Ran, AfterAnF1LossTheDuSetsF1UpAgainAndTheCellServesAgain) {
    Gnb g;
    g.register_ue();
    g.f1.b().abort();   // the CU-CP's end goes (a CU-CP restart, as the DU sees it)
    ASSERT_TRUE(g.loop.run_until([&] { return !g.du.cell_active(); }, g.loop.now() + 1'000));
    g.f1.connect();
    ASSERT_TRUE(g.loop.run_until([&] { return g.du.cell_active() && g.cucp.f1_ready(); }, g.loop.now() + 2'000));
    EXPECT_EQ(g.named("ran.f1.setup").size(), 4u);   // the DU's and the CU-CP's, twice
    EXPECT_TRUE(g.failures().empty()) << g.failures();
}

TEST(Ran, Mutant_single_ue_stream_PutsEveryUeOnStreamOne) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("single_ue_stream");
    Gnb g;
    g.register_ue();
    std::set<std::uint16_t> ue_streams(g.du_f1.streams.begin() + 1, g.du_f1.streams.end());
    EXPECT_EQ(ue_streams, std::set<std::uint16_t>{1});
}

TEST(Ran, Mutant_f1_loss_silent_LeavesTheAmfWithTheUe) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("f1_loss_silent");
    Gnb g;
    g.register_ue();
    g.f1.a().abort();
    g.loop.run_until([] { return false; }, g.loop.now() + 2'000);
    EXPECT_EQ(g.amf.count("UEContextReleaseRequest"), 0u);
}

TEST(Ran, Mutant_kgnb_wrong_ul_count_FailsTheAsSecurityModeAndTheContextSetup) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("kgnb_wrong_ul_count");
    Gnb g;
    g.start();
    g.mm->power_on();
    ASSERT_TRUE(g.loop.run_until([&] { return g.rrc->camped() && g.mm->state() != MmState::null; }, g.loop.now() + 1'000));
    g.mm->register_initial();
    ASSERT_TRUE(g.loop.run_until([&] { return g.amf.count("InitialContextSetupFailure") == 1; }, g.loop.now() + 10'000));
    EXPECT_EQ(g.cucp.stats().ics_failed, 1u);
    EXPECT_FALSE(g.rrc->as_security());
    EXPECT_NE(g.failures().find("the gNB set up the UE context"), std::string::npos) << g.failures();
}

} // namespace
} // namespace ksim::proctest
