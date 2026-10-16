// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The typed RRC builders and readers (P1 N6; TS 38.331 j40): every builder's
// output decodes back to the same struct, inputs out of range are refused
// before encoding, and the JER of each is available for logs. Whether the
// octets are right is judged by tshark and pycrate (oracle.py builders).

#include <gtest/gtest.h>

#include "rrc_samples.hpp"

namespace ksim::rrc {
namespace {

TEST(RrcMsg, EveryBuilderEncodesAndItsJerReads) {
    for (const auto& s : samples::all()) {
        ASSERT_TRUE(s.bytes) << s.name << ": " << s.bytes.error().what;
        auto j = to_jer(s.channel, *s.bytes);
        ASSERT_TRUE(j) << s.name;
        EXPECT_FALSE(j->empty());
    }
}

// P2 Q9: a DRB whose UP confidentiality is not performed carries cipheringDisabled in
// PDCP-Config's first extension group, after t-Reordering.
TEST(RrcMsg, CipheringDisabledRoundTrips) {
    RadioBearers b;
    b.drbs.push_back(DrbAdd{});
    b.drbs[0].pdcp.t_reordering_ms = 100;
    b.drbs[0].pdcp.ciphering_disabled = true;
    const Reconfiguration rc{1, b, std::nullopt, {}};
    auto wire = encode(rc);
    ASSERT_TRUE(wire) << wire.error().what;
    auto d = decode_dl_dcch(*wire);
    ASSERT_TRUE(d) << d.error().what;
    const auto& back = std::get<Reconfiguration>(*d);
    ASSERT_TRUE(back.bearers);
    EXPECT_TRUE(back.bearers->drbs.at(0).pdcp.ciphering_disabled);
    EXPECT_EQ(back.bearers->drbs.at(0).pdcp.t_reordering_ms, 100);
    EXPECT_EQ(back, rc);
}

TEST(RrcMsg, BroadcastAndPagingRoundTrip) {
    const Mib mib{512, true, 0, false, 12, 0, false, true};
    auto m = decode_mib(*encode(mib));
    ASSERT_TRUE(m);
    EXPECT_EQ(*m, mib);
    Mib odd = mib;
    odd.sfn = 517;   // only the six MSBs travel
    EXPECT_EQ(decode_mib(*encode(odd))->sfn, 512);

    Sib1 s;
    s.plmns = {Plmn{"001", "01"}, Plmn{"999", "70"}};
    s.tac = 0x000001;
    s.cell_identity = 0x1A0000001;
    s.timers = UeTimers{};
    auto back = decode_sib1(*encode(s));
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, s);

    const Paging p{{0x0CA040000001ULL}};
    EXPECT_EQ(*decode_paging(*encode(p)), p);
    EXPECT_EQ(*decode_paging(*encode(Paging{})), Paging{});
}

TEST(RrcMsg, CcchMessagesRoundTrip) {
    const SetupRequest r{true, 0x40000001ULL, EstablishmentCause::mt_access};
    EXPECT_EQ(*decode_ul_ccch(*encode(r)), r);
    const rrc::Setup s{0, RadioBearers{{SrbAdd{1, false}}, {}, {}}, samples::cell_group()};
    auto d = decode_dl_ccch(*encode(s));
    ASSERT_TRUE(d);
    ASSERT_TRUE(std::holds_alternative<rrc::Setup>(*d));
    EXPECT_EQ(std::get<rrc::Setup>(*d), s);
    auto rej = decode_dl_ccch(*encode(Reject{5}));
    ASSERT_TRUE(rej);
    EXPECT_EQ(std::get<Reject>(*rej).wait_time_s, 5);
}

TEST(RrcMsg, DcchMessagesRoundTrip) {
    const Reconfiguration rc{2, samples::bearers(), samples::cell_group(), {*from_hex("7e0068"), *from_hex("7e0043")}};
    auto d = decode_dl_dcch(*encode(rc));
    ASSERT_TRUE(d);
    EXPECT_EQ(std::get<Reconfiguration>(*d), rc);
    EXPECT_EQ(std::get<SecurityModeCommand>(*decode_dl_dcch(*encode(SecurityModeCommand{1, 2, 1}))),
              (SecurityModeCommand{1, 2, 1}));
    EXPECT_EQ(std::get<Release>(*decode_dl_dcch(*encode(Release{3}))).tid, 3);
    EXPECT_EQ(std::get<DlInformationTransfer>(*decode_dl_dcch(*encode(DlInformationTransfer{1, {0x7e, 0x00}}))).nas,
              (Bytes{0x7e, 0x00}));
    EXPECT_TRUE(std::holds_alternative<CapabilityEnquiry>(*decode_dl_dcch(*encode(CapabilityEnquiry{0}))));

    const SetupComplete sc{0, 1, {0x7e, 0x00, 0x41}, 0x0CA};
    EXPECT_EQ(std::get<SetupComplete>(*decode_ul_dcch(*encode(sc))), sc);
    EXPECT_EQ(std::get<SecurityModeComplete>(*decode_ul_dcch(*encode(SecurityModeComplete{1}))).tid, 1);
    EXPECT_TRUE(std::holds_alternative<SecurityModeFailure>(*decode_ul_dcch(*encode(SecurityModeFailure{1}))));
    EXPECT_EQ(std::get<ReconfigurationComplete>(*decode_ul_dcch(*encode(ReconfigurationComplete{2}))).tid, 2);
    EXPECT_EQ(std::get<UlInformationTransfer>(*decode_ul_dcch(*encode(UlInformationTransfer{{0x7e, 0x00, 0x43}}))).nas,
              (Bytes{0x7e, 0x00, 0x43}));
    auto cap = generic_nr_capability();
    ASSERT_TRUE(cap);
    EXPECT_EQ(std::get<CapabilityInformation>(*decode_ul_dcch(*encode(CapabilityInformation{0, *cap}))).nr_capability,
              *cap);
}

TEST(RrcMsg, InputsOutOfRangeAreRefusedBeforeEncoding) {
    EXPECT_EQ(encode(Mib{1024}).error().code, Errc::invalid_argument);
    Sib1 s;
    EXPECT_FALSE(encode(s));   // no PLMN
    s.plmns = {Plmn{"01", "01"}};
    EXPECT_FALSE(encode(s));   // a two-digit MCC
    s.plmns = {Plmn{"001", "01"}};
    s.cell_identity = std::uint64_t{1} << 36;
    EXPECT_FALSE(encode(s));
    s.cell_identity = 1;
    s.timers = UeTimers{};
    s.timers->t300 = 250;
    EXPECT_FALSE(encode(s));
    EXPECT_FALSE(encode(SetupRequest{false, std::uint64_t{1} << 39}));
    EXPECT_FALSE(encode(SecurityModeCommand{4, 2, 2}));
    EXPECT_FALSE(encode(SecurityModeCommand{0, 4, 2}));
    EXPECT_FALSE(encode(DlInformationTransfer{0, {}}));
    EXPECT_FALSE(encode(Paging{{std::uint64_t{1} << 48}}));
    EXPECT_FALSE(encode(CellGroup{0, {RlcBearer{33, true, 1, true}}, {}}));
    RadioBearers b;
    b.drbs.push_back(DrbAdd{});
    b.drbs[0].pdcp.t_reordering_ms = 7;
    EXPECT_FALSE(encode(Reconfiguration{0, b, std::nullopt, {}}));
}

// P2 Q4 (KS-F1AP-D2): the served cell's MeasurementTimingConfiguration names its SSB.
// The octets were read back by pycrate (NR-InterNodeDefinitions) as carrierFreq
// 632640, kHz30, sf20 : 0, duration sf5, physCellId 101, and re-encoded the same.
TEST(RrcMsg, MeasurementTimingConfigurationCarriesTheCellsSsb) {
    SsbTiming s;
    s.pci = 101;
    auto m = measurement_timing_configuration(s);
    ASSERT_TRUE(m);
    EXPECT_EQ(*m, (Bytes{0x10, 0x31, 0x34, 0xe8, 0x05, 0x02, 0x00, 0x81, 0x23, 0x28, 0x00}));
    SsbTiming bad = s;
    bad.offset = 20;   // not below the period
    EXPECT_FALSE(measurement_timing_configuration(bad));
    bad = s;
    bad.duration = 6;
    EXPECT_FALSE(measurement_timing_configuration(bad));
    bad = s;
    bad.period_ms = 30;
    EXPECT_FALSE(measurement_timing_configuration(bad));
    bad = s;
    bad.pci = 1008;
    EXPECT_FALSE(measurement_timing_configuration(bad));
}

TEST(RrcMsg, GarbageAndTheWrongChannelAreErrorsNotCrashes) {
    EXPECT_FALSE(decode_dl_dcch(*from_hex("ff")));
    EXPECT_FALSE(decode_ul_ccch({}));
    // An RRCRelease read as UL-DCCH is some other message, or nothing P1 reads.
    auto r = decode_ul_dcch(*encode(Release{0}));
    EXPECT_TRUE(!r || !std::holds_alternative<rrc::SetupComplete>(*r));
}

} // namespace
} // namespace ksim::rrc
