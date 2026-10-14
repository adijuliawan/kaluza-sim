// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The terminal against the soft card over the in-process transport, in
// virtual time (P1 N3): what the UE's ME will do at power-on and for 5G AKA,
// with the T=0 procedures exercised on the way.

#include <gtest/gtest.h>

#include "../crypto/kat_file.hpp"
#include "crypto/milenage.hpp"
#include "fixture.hpp"
#include "platform/coro.hpp"
#include "platform/sim_loop.hpp"
#include "uicc/terminal/terminal.hpp"

namespace ksim::uicc::test {
namespace {

using coro::Task;

TEST(Terminal, PowersOnFindsTheUsimReadsTheImsiAndAuthenticates) {
    const auto sets = kat::load("milenage");
    const auto& s = sets.front().second;
    const SecretBytes k = s.secret("K");
    auto opc = crypto::milenage::opc(k, s.secret("OP"));
    auto card = make_card(test_secrets(k, *opc));
    os::File& sqn_file = at(usim(*card), 0xAF30);
    sqn_file.data.at(0) = static_cast<std::uint8_t>(sqn_file.data.at(0) & ~0x40);   // the KAT's SQN is far ahead (Annex C.2.2)
    SimLoop loop(0);
    InProcTransport t(loop, card.get());
    Terminal term(t);

    struct Out {
        bool done = false;
        Bytes atr;
        Bytes imsi;
        AuthOutcome auth;
        Bytes smsp;
    } out;
    Bytes autn(16);
    {
        const Bytes sqn = s.bytes("SQN");
        const Bytes ak = s.bytes("f5");
        for (std::size_t i = 0; i < 6; ++i) {
            autn[i] = static_cast<std::uint8_t>(sqn[i] ^ ak[i]);
        }
        const Bytes amf = s.bytes("AMF");
        const Bytes mac = s.bytes("f1");
        autn[6] = amf[0];
        autn[7] = amf[1];
        std::copy(mac.begin(), mac.end(), autn.begin() + 8);
    }
    coro::spawn([](Terminal& tm, Out& o, Bytes rand, Bytes autn_in) -> Task<void> {
        auto atr = co_await tm.power_on();
        EXPECT_TRUE(atr);
        o.atr = *atr;
        auto sel = co_await tm.select_usim();
        EXPECT_TRUE(sel) << (sel ? "" : sel.error().what) << " sw " << std::hex << tm.last_sw();
        auto imsi = co_await tm.read_ef({0x6F07});
        EXPECT_TRUE(imsi);
        o.imsi = *imsi;
        auto smsp = co_await tm.read_record({0x6F42}, 1);
        EXPECT_TRUE(smsp);
        o.smsp = *smsp;
        auto a = co_await tm.authenticate(std::move(rand), std::move(autn_in));
        EXPECT_TRUE(a);
        o.auth = std::move(*a);
        o.done = true;
    }(term, out, s.bytes("RAND"), autn));
    ASSERT_TRUE(loop.run_until([&] { return out.done; }, 10'000));
    EXPECT_EQ(out.atr, card->atr());
    EXPECT_EQ(to_hex(out.imsi), "080910100000030010");
    EXPECT_EQ(to_hex(ByteView(out.smsp).subspan(13, 6)), "059199090000");   // TS-SC address +99900000
    ASSERT_EQ(out.auth.kind, AuthOutcome::Kind::success);
    EXPECT_EQ(to_hex(out.auth.res.expose()), s.hex("f2"));
    EXPECT_EQ(to_hex(out.auth.ck.expose()), s.hex("f3"));
    EXPECT_EQ(to_hex(out.auth.ik.expose()), s.hex("f4"));
    EXPECT_EQ(to_hex(term.usim_aid()), "a0000000871002ffffffff8907090000");
    // T=0 at work: every SELECT with an FCP and the AUTHENTICATE took a GET RESPONSE.
    EXPECT_GE(term.apdus(), 14u);
}

TEST(Terminal, AReplayedChallengeComesBackAsSyncFailureWithAuts) {
    const auto sets = kat::load("milenage");
    const auto& s = sets.front().second;
    const SecretBytes k = s.secret("K");
    auto opc = crypto::milenage::opc(k, s.secret("OP"));
    auto card = make_card(test_secrets(k, *opc));
    os::File& sqn_file = at(usim(*card), 0xAF30);
    sqn_file.data.at(0) = static_cast<std::uint8_t>(sqn_file.data.at(0) & ~0x40);   // the KAT's SQN is far ahead (Annex C.2.2)
    SimLoop loop(0);
    InProcTransport t(loop, card.get());
    Terminal term(t);
    const Bytes sqn = s.bytes("SQN");
    const Bytes ak = s.bytes("f5");
    Bytes autn(16);
    for (std::size_t i = 0; i < 6; ++i) {
        autn[i] = static_cast<std::uint8_t>(sqn[i] ^ ak[i]);
    }
    autn[6] = s.bytes("AMF")[0];
    autn[7] = s.bytes("AMF")[1];
    const Bytes mac = s.bytes("f1");
    std::copy(mac.begin(), mac.end(), autn.begin() + 8);
    std::vector<AuthOutcome::Kind> kinds;
    std::size_t auts_len = 0;
    bool done = false;
    coro::spawn([](Terminal& tm, Bytes rand, Bytes a, std::vector<AuthOutcome::Kind>& ks, std::size_t& alen,
                   bool& d) -> Task<void> {
        (void)co_await tm.power_on();
        (void)co_await tm.select_usim();
        for (int i = 0; i < 2; ++i) {
            auto r = co_await tm.authenticate(rand, a);
            EXPECT_TRUE(r);
            ks.push_back(r->kind);
            alen = r->auts.size();
        }
        Bytes bad = a;
        bad[15] ^= 1;
        auto r = co_await tm.authenticate(rand, bad);
        ks.push_back(r->kind);
        d = true;
    }(term, s.bytes("RAND"), autn, kinds, auts_len, done));
    ASSERT_TRUE(loop.run_until([&] { return done; }, 10'000));
    EXPECT_EQ(kinds, (std::vector<AuthOutcome::Kind>{AuthOutcome::Kind::success, AuthOutcome::Kind::sync_failure,
                                                     AuthOutcome::Kind::mac_failure}));
    EXPECT_EQ(auts_len, 14u);
}

TEST(Terminal, AWrongPinReportsTheStatusWordAndARemovedCardIsClosed) {
    auto card = make_card();
    SimLoop loop(0);
    InProcTransport t(loop, card.get());
    Terminal term(t);
    bool done = false;
    Errc after_removal{};
    coro::spawn([](Terminal& tm, InProcTransport& tr, Errc& e, bool& d) -> Task<void> {
        (void)co_await tm.power_on();
        auto r = co_await tm.verify_pin(0x81, *secrets::pin_block(digits("0000")));
        EXPECT_FALSE(r);
        EXPECT_EQ(tm.last_sw(), 0x63C2);
        tr.insert(nullptr);
        auto gone = co_await tm.power_on();
        e = gone.error().code;
        d = true;
    }(term, t, after_removal, done));
    ASSERT_TRUE(loop.run_until([&] { return done; }, 10'000));
    EXPECT_EQ(after_removal, Errc::closed);
}

} // namespace
} // namespace ksim::uicc::test
