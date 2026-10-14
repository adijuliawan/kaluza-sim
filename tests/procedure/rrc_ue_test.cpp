// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's RRC entity against a scripted gNB in virtual time (P1 N6; TS 38.331
// j40 §5.2, §5.3). The scripted gNB plays the DU's MAC (RAR, Msg4, SDUs on the
// C-RNTI) and the CU's RRC over gNB-side PDCP entities, with the same
// builders; it holds the K_gNB the UE's NAS hands its RRC, so a key mismatch
// shows as an integrity failure, as it would against a real gNB.

#include <gtest/gtest.h>

#include <deque>
#include <vector>

#include "crypto/keys5g.hpp"
#include "entity/pdcp/pdcp.hpp"
#include "platform/event.hpp"
#include "platform/sim_loop.hpp"
#include "proc/ue/rrc/rrc.hpp"

namespace ksim::proctest {
namespace {

using proc::ue::RrcState;
using proc::ue::UeRrc;

Bytes h(const char* s) { return *from_hex(s); }

std::string field_of(const Event& e, std::string_view key) {
    const std::string* v = e.find(key);
    return v != nullptr ? *v : std::string("<none>");
}
SecretBytes kgnb_value() {
    return SecretBytes::from_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf").value();
}

const Bytes kRegistration = h("7e004179000d0100f110000000000000000001");

/// The scripted gNB: DU MAC plus CU RRC.
struct Gnb {
    explicit Gnb(SimLoop& l) : loop(l) {}

    SimLoop& loop;
    std::function<void(air::Frame)> deliver;   // to the UE, one hop later
    std::uint32_t cell = 0x10;
    std::uint16_t rnti = 0x4601;
    bool answer_rar = true;
    bool reject = false;
    SecretBytes kgnb = kgnb_value();

    std::optional<rrc::SetupRequest> setup_request;
    std::vector<rrc::UlDcch> ul;          // every UL-DCCH message, decoded
    std::vector<Bytes> ul_raw;            // and the PDCP PDUs they came in
    std::vector<Bytes> drb_rx;            // uplink user data, SDAP header removed
    std::unique_ptr<entity::Pdcp> srb1, srb2, drb1;
    SecretBytes up_int, up_enc, rrc_int, rrc_enc;

    void send(air::Frame f) {
        f.cell_handle = cell;
        loop.start_timer(1, [this, f] { deliver(f); });
    }
    void broadcast(const rrc::Plmn& plmn = {"001", "01"}, bool barred = false) {
        air::Frame b;
        b.type = air::FrameType::bch;
        b.sdus.push_back({0, air::RlcMode::tm, *rrc::encode(rrc::Mib{0, true, 0, false, 0, 0, barred, true})});
        send(b);
        rrc::Sib1 s;
        s.plmns = {plmn};
        s.tac = 1;
        s.cell_identity = 0x1A0000001;
        s.timers = rrc::UeTimers{};
        air::Frame si;
        si.type = air::FrameType::si;
        si.sdus.push_back({0, air::RlcMode::tm, *rrc::encode(s)});
        send(si);
    }
    entity::Pdcp* pdcp_of(std::uint8_t lcid) {
        return lcid == 1 ? srb1.get() : lcid == 2 ? srb2.get() : lcid == 4 ? drb1.get() : nullptr;
    }
    void on_ul(const air::Frame& f) {
        switch (f.type) {
        case air::FrameType::prach:
            if (answer_rar) {
                air::Frame r;
                r.type = air::FrameType::rar;
                r.rnti = f.prach->ra_rnti();
                r.rar = air::Rar{f.prach->preamble, rnti, 0, 0};
                send(r);
            }
            return;
        case air::FrameType::msg3: {
            auto req = rrc::decode_ul_ccch(f.sdus.at(0).data);
            ASSERT_TRUE(req);
            setup_request = *req;
            air::Frame m4;
            m4.type = air::FrameType::msg4;
            m4.rnti = f.rnti;
            m4.contention_id = air::contention_id_of(f.sdus.at(0).data);
            if (reject) {
                m4.sdus.push_back({0, air::RlcMode::tm, *rrc::encode(rrc::Reject{2})});
            } else {
                rrc::CellGroup cg;
                cg.bearers.push_back(rrc::RlcBearer{1, true, 1, true});
                m4.sdus.push_back({0, air::RlcMode::tm,
                                   *rrc::encode(rrc::Setup{0, rrc::RadioBearers{{rrc::SrbAdd{1, false}}, {}, {}}, cg})});
                srb1 = make_pdcp(true, 1, 1);
            }
            send(m4);
            return;
        }
        case air::FrameType::ul_sdu:
            for (const auto& s : f.sdus) {
                if (entity::Pdcp* p = pdcp_of(s.lcid)) {
                    if (s.lcid != 4) {
                        ul_raw.push_back(s.data);
                    }
                    p->on_pdu(s.data);
                }
            }
            return;
        default:
            return;
        }
    }
    std::unique_ptr<entity::Pdcp> make_pdcp(bool srb, std::uint8_t id, std::uint8_t lcid) {
        entity::PdcpConfig c;
        c.srb = srb;
        c.rb_id = id;
        c.side = entity::PdcpSide::gnb;
        if (!srb) {
            c.sn_tx = c.sn_rx = pdcp::SnSize::len18;
            c.sdap_header_tx = c.sdap_header_rx = true;
            c.drb_integrity = true;
        }
        auto lower = [this, lcid](Bytes pdu) {
            air::Frame d;
            d.type = air::FrameType::dl_sdu;
            d.rnti = rnti;
            d.sdus.push_back({lcid, air::RlcMode::am, std::move(pdu)});
            send(d);
        };
        auto upper = [this, srb](Bytes sdu) {
            if (!srb) {
                drb_rx.emplace_back(sdu.begin() + 1, sdu.end());
                return;
            }
            auto m = rrc::decode_ul_dcch(sdu);
            ASSERT_TRUE(m) << to_hex(sdu);
            if (std::holds_alternative<rrc::SecurityModeComplete>(*m)) {
                srb1->set_ciphering(true, true);   // §5.3.4: ciphering after the complete
            }
            ul.push_back(*m);
        };
        return std::make_unique<entity::Pdcp>(loop, c, lower, upper);
    }
    void dcch(entity::Pdcp& p, Result<Bytes> msg) {
        ASSERT_TRUE(msg);
        p.write_sdu(*msg);
    }
    void security_mode(std::uint8_t nea = 2, std::uint8_t nia = 2) {
        using crypto::keys5g::AlgType;
        rrc_int = crypto::keys5g::algorithm_key(kgnb, AlgType::rrc_int, nia).value();
        rrc_enc = crypto::keys5g::algorithm_key(kgnb, AlgType::rrc_enc, nea).value();
        up_int = crypto::keys5g::algorithm_key(kgnb, AlgType::up_int, nia).value();
        up_enc = crypto::keys5g::algorithm_key(kgnb, AlgType::up_enc, nea).value();
        ASSERT_TRUE(srb1->set_keys(static_cast<crypto::Nia>(nia), rrc_int.clone(), static_cast<crypto::Nea>(nea),
                                   rrc_enc.clone()));
        srb1->set_integrity(true, true);
        dcch(*srb1, rrc::encode(rrc::SecurityModeCommand{1, nea, nia}));
    }
    void reconfigure(std::vector<Bytes> nas) {
        srb2 = make_pdcp(true, 2, 2);
        ASSERT_TRUE(srb2->set_keys(crypto::Nia::nia2, rrc_int.clone(), crypto::Nea::nea2, rrc_enc.clone()));
        srb2->set_integrity(true, true);
        srb2->set_ciphering(true, true);
        drb1 = make_pdcp(false, 1, 4);
        ASSERT_TRUE(drb1->set_keys(crypto::Nia::nia2, up_int.clone(), crypto::Nea::nea2, up_enc.clone()));
        drb1->set_integrity(true, true);
        drb1->set_ciphering(true, true);
        rrc::RadioBearers rb;
        rb.srbs.push_back(rrc::SrbAdd{2, false});
        rrc::DrbAdd d;
        d.drb_id = 1;
        d.pdu_session = 1;
        d.sdap_header_dl = d.sdap_header_ul = true;
        d.qfis = {9};
        d.pdcp.integrity = true;
        rb.drbs.push_back(d);
        rrc::CellGroup cg;
        cg.bearers.push_back(rrc::RlcBearer{2, true, 2, true});
        cg.bearers.push_back(rrc::RlcBearer{4, false, 1, true});
        dcch(*srb1, rrc::encode(rrc::Reconfiguration{2, rb, cg, std::move(nas)}));
    }
};

struct UeRig {
    SimLoop loop;
    EventRing events{4096, loop.clock()};
    Gnb gnb{loop};
    std::vector<Bytes> nas_dl;
    int air_frames = 0;                    // frames the UE has sent
    std::vector<int> air_frames_at_nas;    // how many when each NAS message went up
    std::vector<std::pair<std::uint8_t, Bytes>> data_dl;
    int released = 0;
    int paged = 0;
    std::optional<std::uint64_t> s_tmsi;
    std::optional<SecretBytes> kgnb = kgnb_value();
    std::unique_ptr<UeRrc> ue;

    UeRig() {
        proc::ue::RrcConfig c;
        c.id = "ue:test";
        c.plmn = {"001", "01"};
        c.mac.radio_id = 7;
        proc::ue::RrcUpper up;
        up.nas = [this](Bytes b) {
            air_frames_at_nas.push_back(air_frames);
            nas_dl.push_back(std::move(b));
        };
        up.released = [this] { ++released; };
        up.kgnb = [this]() -> Result<SecretBytes> {
            if (!kgnb) {
                return make_error(Errc::invalid_argument, 0, "none");
            }
            return kgnb->clone();
        };
        up.s_tmsi = [this] { return s_tmsi; };
        up.paged = [this] { ++paged; };
        up.dl_data = [this](std::uint8_t psi, std::optional<sdap::DlHeader>, Bytes b) {
            data_dl.emplace_back(psi, std::move(b));
        };
        ue = std::make_unique<UeRrc>(loop, Rng(3, {4}), events, c, up, [this](const air::Frame& f) {
            ++air_frames;
            loop.start_timer(1, [this, f] { gnb.on_ul(f); });
        });
        gnb.deliver = [this](const air::Frame& f) { ue->on_frame(f); };
    }
    bool run_until(const std::function<bool()>& done, Millis within = 5'000) {
        return loop.run_until(done, loop.now() + within);
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
    template <class T>
    int count_ul() const {
        int n = 0;
        for (const auto& m : gnb.ul) {
            n += std::holds_alternative<T>(m) ? 1 : 0;
        }
        return n;
    }
    /// Camped, then connected with the registration request delivered.
    void connect() {
        gnb.broadcast();
        ASSERT_TRUE(run_until([&] { return ue->camped(); }));
        ue->send_nas(kRegistration);
        ASSERT_TRUE(run_until([&] { return count_ul<rrc::SetupComplete>() == 1; }));
    }
    void secure() {
        connect();
        gnb.security_mode();
        ASSERT_TRUE(run_until([&] { return count_ul<rrc::SecurityModeComplete>() == 1; }));
    }
};

TEST(UeRrc, Clause5_2_2_TheUeCampsOnlyOnAnUnbarredCellOfItsPlmn) {
    UeRig r;
    r.gnb.broadcast({"999", "70"});
    r.loop.run_for(100);
    EXPECT_FALSE(r.ue->camped());
    r.gnb.broadcast({"001", "01"}, true);
    r.loop.run_for(100);
    EXPECT_FALSE(r.ue->camped());
    r.gnb.broadcast({"001", "01"});
    ASSERT_TRUE(r.run_until([&] { return r.ue->camped(); }));
    EXPECT_EQ(r.named("rrc.camped").size(), 1u);
    r.gnb.broadcast({"001", "01"});   // the same SIB1 again: still one camping
    r.loop.run_for(100);
    EXPECT_EQ(r.named("rrc.camped").size(), 1u);
}

TEST(UeRrc, Clause5_3_3_SetupThroughRandomAccessCarriesTheNasMessage) {
    UeRig r;
    r.ue->send_nas(kRegistration);   // before camping: it waits for a suitable cell
    r.gnb.broadcast();
    ASSERT_TRUE(r.run_until([&] { return r.count_ul<rrc::SetupComplete>() == 1; }));
    EXPECT_EQ(r.ue->state(), RrcState::connected);
    EXPECT_EQ(r.ue->c_rnti(), 0x4601);
    ASSERT_TRUE(r.gnb.setup_request);
    EXPECT_FALSE(r.gnb.setup_request->s_tmsi_part1);   // no 5G-GUTI: a random value
    EXPECT_EQ(r.gnb.setup_request->cause, rrc::EstablishmentCause::mo_signalling);
    const auto& c = std::get<rrc::SetupComplete>(r.gnb.ul.at(0));
    EXPECT_EQ(c.nas, kRegistration);
    EXPECT_EQ(c.selected_plmn, 1);
    EXPECT_FALSE(c.s_tmsi_part2);
    EXPECT_NE(r.ue->srb(1), nullptr);
    // A second NAS message goes in a ULInformationTransfer on SRB1.
    r.ue->send_nas(h("7e0057"));
    ASSERT_TRUE(r.run_until([&] { return r.count_ul<rrc::UlInformationTransfer>() == 1; }));
}

TEST(UeRrc, Clause5_3_3_3_TheFiveGSTmsiSplitsIntoPart1AndPart2) {
    UeRig r;
    r.s_tmsi = 0x0CA040000001ULL;   // a 48-bit 5G-S-TMSI
    r.connect();
    ASSERT_TRUE(r.gnb.setup_request);
    EXPECT_TRUE(r.gnb.setup_request->s_tmsi_part1);
    EXPECT_EQ(r.gnb.setup_request->identity, 0x0CA040000001ULL & ((std::uint64_t{1} << 39) - 1));
    const auto& c = std::get<rrc::SetupComplete>(r.gnb.ul.at(0));
    ASSERT_TRUE(c.s_tmsi_part2);
    EXPECT_EQ(*c.s_tmsi_part2, static_cast<std::uint16_t>(0x0CA040000001ULL >> 39));
}

TEST(UeRrc, Clause5_3_3_7_T300RunningOutIsAFailureTheNasSees) {
    UeRig r;
    r.gnb.answer_rar = false;
    r.gnb.broadcast();
    ASSERT_TRUE(r.run_until([&] { return r.ue->camped(); }));
    const Millis t0 = r.loop.now();
    r.ue->send_nas(kRegistration);
    ASSERT_TRUE(r.run_until([&] { return r.released == 1; }));
    EXPECT_LE(r.loop.now() - t0, 1'000);   // T300 from SIB1 (ms1000), or the RA problem before it
    EXPECT_EQ(r.ue->state(), RrcState::idle);
    EXPECT_FALSE(r.named("rrc.setup.failure").empty());
}

TEST(UeRrc, Clause5_3_15_AnRrcRejectEndsTheSetup) {
    UeRig r;
    r.gnb.reject = true;
    r.gnb.broadcast();
    ASSERT_TRUE(r.run_until([&] { return r.ue->camped(); }));
    r.ue->send_nas(kRegistration);
    ASSERT_TRUE(r.run_until([&] { return r.released == 1; }));
    EXPECT_EQ(field_of(r.named("rrc.setup.failure").at(0), "reason"), "RRCReject");
}

TEST(UeRrc, Clause5_3_4_AsSecurityStartsWithAnUncipheredComplete) {
    UeRig r;
    r.secure();
    EXPECT_TRUE(r.ue->as_security());
    const auto smc = r.named("rrc.smc.complete");
    ASSERT_EQ(smc.size(), 1u);
    EXPECT_EQ(field_of(smc[0], "alg"), "nia2/nea2");
    // The complete went integrity protected but not ciphered: its RRC octets
    // are in the clear between the PDCP header and the MAC-I.
    const Bytes plain = *rrc::encode(rrc::SecurityModeComplete{1});
    const Bytes& pdu = r.gnb.ul_raw.back();
    ASSERT_EQ(pdu.size(), 2 + plain.size() + 4);
    EXPECT_EQ(Bytes(pdu.begin() + 2, pdu.end() - 4), plain);
    // From here both directions are ciphered and verified.
    r.ue->send_nas(h("7e0043"));
    ASSERT_TRUE(r.run_until([&] { return r.count_ul<rrc::UlInformationTransfer>() == 1; }));
    EXPECT_NE(Bytes(r.gnb.ul_raw.back().begin() + 2, r.gnb.ul_raw.back().end() - 4),
              *rrc::encode(rrc::UlInformationTransfer{h("7e0043")}));
    r.gnb.dcch(*r.gnb.srb1, rrc::encode(rrc::DlInformationTransfer{0, h("7e005b01")}));
    ASSERT_TRUE(r.run_until([&] { return r.nas_dl.size() == 1; }));
    EXPECT_EQ(r.nas_dl[0], h("7e005b01"));
    EXPECT_EQ(r.ue->srb(1)->stats().integrity_failures, 0u);
}

TEST(UeRrc, Clause5_3_4_3_ACommandUnderAnotherKGnbFailsItsIntegrityCheck) {
    // The UE's K_gNB differs from the gNB's (a wrong uplink NAS COUNT, say):
    // the command's MAC-I does not verify, and the UE answers unprotected.
    UeRig r;
    r.kgnb = SecretBytes::from_hex("00000000000000000000000000000000000000000000000000000000000000ff").value();
    r.connect();
    r.gnb.security_mode();
    r.gnb.srb1->set_integrity(true, false);   // the failure arrives without integrity
    ASSERT_TRUE(r.run_until([&] { return r.count_ul<rrc::SecurityModeFailure>() == 1; }));
    EXPECT_FALSE(r.ue->as_security());
    EXPECT_EQ(field_of(r.named("rrc.smc.failure").at(0), "reason"), "integrity check of the SecurityModeCommand");
}

TEST(UeRrc, Clause5_3_4_NullIntegrityIsRefusedOutsideTheBisectSwitch) {
    UeRig r;
    r.connect();
    r.gnb.srb1->set_integrity(false, false);
    r.gnb.dcch(*r.gnb.srb1, rrc::encode(rrc::SecurityModeCommand{1, 0, 0}));
    ASSERT_TRUE(r.run_until([&] { return r.count_ul<rrc::SecurityModeFailure>() == 1; }));
    EXPECT_FALSE(r.ue->as_security());
}

TEST(UeRrc, Clause5_3_5_ReconfigurationAddsSrb2AndADrbAndForwardsTheNasAfterTheComplete) {
    UeRig r;
    r.secure();
    const int before = r.air_frames;
    r.gnb.reconfigure({h("7e0042"), h("2e0101c1")});
    ASSERT_TRUE(r.run_until(
        [&] { return r.nas_dl.size() == 2 && r.count_ul<rrc::ReconfigurationComplete>() == 1; }));
    EXPECT_EQ(r.nas_dl[0], h("7e0042"));
    EXPECT_EQ(r.air_frames_at_nas.at(0), before + 1);   // the complete was out before the NAS went up
    EXPECT_NE(r.ue->srb(2), nullptr);
    EXPECT_EQ(r.ue->drbs(), std::vector<std::uint8_t>{1});
    // NAS now goes on SRB2.
    r.ue->send_nas(h("7e0043"));
    ASSERT_TRUE(r.run_until([&] { return r.count_ul<rrc::UlInformationTransfer>() == 1; }));
    EXPECT_EQ(r.gnb.srb2->rx_next(), 1u);
    // User data both ways, through SDAP and a ciphered, integrity-protected DRB.
    ASSERT_TRUE(r.ue->send_data(1, 9, h("450000140000")));
    ASSERT_TRUE(r.run_until([&] { return r.gnb.drb_rx.size() == 1; }));
    EXPECT_EQ(r.gnb.drb_rx[0], h("450000140000"));
    r.gnb.drb1->write_sdu(h("09450000140001"));   // DL SDAP header: QFI 9
    ASSERT_TRUE(r.run_until([&] { return r.data_dl.size() == 1; }));
    EXPECT_EQ(r.data_dl[0].first, 1);
    EXPECT_EQ(r.data_dl[0].second, h("450000140001"));
    EXPECT_EQ(r.gnb.drb1->stats().integrity_failures, 0u);
    EXPECT_FALSE(r.ue->send_data(2, 9, h("45")));   // no such session
}

TEST(UeRrc, Clause5_3_5_3_BearersBeforeAsSecurityTakeTheUeIdle) {
    UeRig r;
    r.connect();
    rrc::RadioBearers rb;
    rb.srbs.push_back(rrc::SrbAdd{2, false});
    r.gnb.dcch(*r.gnb.srb1, rrc::encode(rrc::Reconfiguration{0, rb, std::nullopt, {}}));
    ASSERT_TRUE(r.run_until([&] { return r.released == 1; }));
    EXPECT_EQ(r.ue->state(), RrcState::idle);
}

TEST(UeRrc, Clause5_3_8_ReleaseTakesTheUeIdleAndTellsTheNas) {
    UeRig r;
    r.secure();
    r.gnb.dcch(*r.gnb.srb1, rrc::encode(rrc::Release{3}));
    ASSERT_TRUE(r.run_until([&] { return r.released == 1; }));
    EXPECT_EQ(r.ue->state(), RrcState::idle);
    EXPECT_FALSE(r.ue->as_security());
    EXPECT_EQ(r.ue->srb(1), nullptr);
    EXPECT_FALSE(r.ue->c_rnti());
}

TEST(UeRrc, Clause5_6_1_TheCapabilityEnquiryIsAnsweredWithTheNrCapability) {
    UeRig r;
    r.secure();
    r.gnb.dcch(*r.gnb.srb1, rrc::encode(rrc::CapabilityEnquiry{0}));
    ASSERT_TRUE(r.run_until([&] { return r.count_ul<rrc::CapabilityInformation>() == 1; }));
    for (const auto& m : r.gnb.ul) {
        if (const auto* c = std::get_if<rrc::CapabilityInformation>(&m)) {
            EXPECT_EQ(c->nr_capability, *rrc::generic_nr_capability());
        }
    }
}

TEST(UeRrc, Clause5_3_2_PagingForThisUesSTmsiReachesTheNasInIdle) {
    UeRig r;
    r.s_tmsi = 0x0CA040000001ULL;
    r.gnb.broadcast();
    ASSERT_TRUE(r.run_until([&] { return r.ue->camped(); }));
    air::Frame p;
    p.type = air::FrameType::pcch;
    p.paging = air::PagingStamp{0, 0, false};
    p.sdus.push_back({0, air::RlcMode::tm, *rrc::encode(rrc::Paging{{0x0CA040000002ULL}})});
    r.gnb.send(p);
    r.loop.run_for(10);
    EXPECT_EQ(r.paged, 0);
    p.sdus[0].data = *rrc::encode(rrc::Paging{{0x0CA040000002ULL, 0x0CA040000001ULL}});
    r.gnb.send(p);
    ASSERT_TRUE(r.run_until([&] { return r.paged == 1; }));
}

TEST(UeRrc, AnSrbIntegrityFailureLosesTheConnection) {
    UeRig r;
    r.secure();
    // A downlink PDU whose MAC-I is wrong (the gNB's integrity key altered).
    r.gnb.srb1 = r.gnb.make_pdcp(true, 1, 1);
    ASSERT_TRUE(r.gnb.srb1->set_keys(crypto::Nia::nia2, SecretBytes::from_hex("00000000000000000000000000000001").value(),
                                     crypto::Nea::nea2, r.gnb.rrc_enc.clone()));
    r.gnb.srb1->set_integrity(true, true);
    r.gnb.srb1->set_ciphering(true, true);
    r.gnb.srb1->set_state(1, 0, 0);
    r.gnb.dcch(*r.gnb.srb1, rrc::encode(rrc::DlInformationTransfer{0, h("7e005b01")}));
    ASSERT_TRUE(r.run_until([&] { return r.released == 1; }));
    EXPECT_TRUE(r.nas_dl.empty());
    EXPECT_FALSE(r.named("rrc.integrity_failure").empty());
}

} // namespace
} // namespace ksim::proctest
