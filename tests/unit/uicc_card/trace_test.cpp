// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The APDU trace (P1 N14; sim-uicc.md §6): the TPDU form of each case, and
// what redaction masks, over a real session with the soft card: keys from
// AUTHENTICATE (straight or through GET RESPONSE), PINs, and the secret EFs by
// FID and by SFI, while everything else is traced as it went.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "fixture.hpp"
#include "platform/sim_loop.hpp"
#include "uicc/trace/trace.hpp"

namespace ksim::uicc::test {
namespace {

std::string h(ByteView b) { return to_hex(b); }
/// The records of one exchange, joined by '|'.
std::string h(const std::vector<Bytes>& v) {
    std::string out;
    for (const auto& b : v) {
        out += (out.empty() ? "" : "|") + to_hex(b);
    }
    return out;
}
Bytes x(const char* s) { return *from_hex(s); }

TEST(Trace, TheTpduFormOfTheFourCases) {
    EXPECT_EQ(h(trace::tpdu(x("0070000000"), x("9000"))), "00700000009000");   // as sent
    EXPECT_EQ(h(trace::tpdu(x("00700000"), x("9000"))), "00700000009000");     // case 1 gets P3 = 0
    EXPECT_EQ(h(trace::tpdu(x("00B0000002"), x("12349000"))), "00b000000212349000");
    EXPECT_EQ(h(trace::tpdu(x("00A40004023F00"), x("6125"))), "00a40004023f006125");
    EXPECT_EQ(h(trace::tpdu(x("00A40004023F0000"), x("AB9000"))), "00a40004023f00ab9000");   // case 4: Le dropped
}

TEST(Trace, NothingIsRecordedForNothingAndAShortCommandGoesAsItCame) {
    trace::Redactor r;   // fuzz_vpcd found an empty record for an empty exchange
    EXPECT_TRUE(r.apply(Bytes{}, Bytes{}).empty());
    EXPECT_EQ(h(r.apply(x("00A4"), x("6700"))), "00a46700");
}

TEST(Trace, A61xxIsMergedWithItsGetResponseAnd6CxxWithTheCommandSentAgain) {
    trace::Redactor r;
    EXPECT_EQ(h(r.apply(x("00A40004023F00"), x("6104"))), "");   // held
    EXPECT_EQ(h(r.apply(x("00C0000004"), x("620282019000"))), "00a40004023f00620282019000");
    EXPECT_EQ(h(r.apply(x("00B0000000"), x("6C09"))), "");
    EXPECT_EQ(h(r.apply(x("00B0000009"), x("0809101000000300109000"))), "00b00000090809101000000300109000");
    // A held exchange nobody followed up goes out as it was, before the next one.
    EXPECT_EQ(h(r.apply(x("00A40004023F00"), x("6104"))), "");
    EXPECT_EQ(h(r.apply(x("00F2000000"), x("9000"))), "00a40004023f006104|00f20000009000");
    EXPECT_EQ(h(r.apply(x("00A40004023F00"), x("6104"))), "");
    EXPECT_EQ(h(r.flush()), "00a40004023f006104");
    EXPECT_EQ(h(r.flush()), "");
    // Channels are apart: a GET RESPONSE on channel 1 does not take channel 0's.
    EXPECT_EQ(h(r.apply(x("00A40004023F00"), x("6104"))), "");
    EXPECT_EQ(h(r.apply(x("01C0000004"), x("AABBCCDD9000"))), "01c0000004aabbccdd9000");
    EXPECT_EQ(h(r.apply(x("00C0000004"), x("620282019000"))), "00a40004023f00620282019000");
}

TEST(Trace, PinDataIsMaskedAndAuthenticateKeysToo) {
    trace::Redactor r;
    EXPECT_EQ(h(r.apply(x("002000010831323334FFFFFFFF"), x("9000"))), "0020000108ffffffffffffffff9000");
    // DB 08 RES 10 CK 10 IK 08 Kc: RES stays, the keys are zero.
    const std::string res = "0102030405060708", ck(32, 'a'), ik(32, 'b'), kc(16, 'c');
    const std::string rand_autn = "10" + std::string(32, '1') + "10" + std::string(32, '2');
    const std::string cmd = "0088008122" + rand_autn;
    const Bytes ans = x(("DB08" + res + "10" + ck + "10" + ik + "08" + kc + "9000").c_str());
    const std::string masked = "db08" + res + "10" + std::string(32, '0') + "10" + std::string(32, '0') + "08" +
                               std::string(16, '0') + "9000";
    EXPECT_EQ(h(r.apply(x((cmd + "00").c_str()), ans)), cmd + masked);   // case 4: straight
    // T=0: 61xx, then the GET RESPONSE carries them; the record is the command and the masked answer.
    EXPECT_EQ(h(r.apply(x(cmd.c_str()), x("6135"))), "");
    EXPECT_EQ(h(r.apply(x("00C0000035"), ans)), cmd + masked);
    // ...and only that one: a GET RESPONSE with nothing held is left as it is.
    EXPECT_EQ(h(r.apply(x("00C0000002"), x("ABCD9000"))), "00c0000002abcd9000");
}

TEST(Trace, TheSecretEfsAreMaskedByFidAndBySfiInDf5gs) {
    trace::Redactor r;
    r.apply(x("00A4000C025FC0"), x("9000"));   // DF.5GS (from the ADF)
    EXPECT_EQ(h(r.apply(x("00B0830004"), x("112233449000"))), "00b0830004000000009000");   // SFI 03: 4F03
    EXPECT_EQ(h(r.apply(x("00B0810004"), x("112233449000"))), "00b0810004112233449000");   // SFI 01: 4F01 stays
    r.apply(x("00A4000C024F05"), x("9000"));
    EXPECT_EQ(h(r.apply(x("00B0000002"), x("AABB9000"))), "00b000000200009000");
    EXPECT_EQ(h(r.apply(x("00D6000002AABB"), x("9000"))), "00d600000200009000");
    // Selected with 61xx and GET RESPONSE: still tracked once merged.
    r.apply(x("00A40004024F01"), x("6119"));
    r.apply(x("00C0000019"), x(("62" + std::string(48, '0') + "9000").c_str()));
    EXPECT_EQ(h(r.apply(x("00B0000002"), x("AABB9000"))), "00b0000002aabb9000");
    r.apply(x("00A40004024F03"), x("6119"));
    r.apply(x("00C0000019"), x(("62" + std::string(48, '0') + "9000").c_str()));
    EXPECT_EQ(h(r.apply(x("00B0000002"), x("AABB9000"))), "00b000000200009000");
    // EF.KEYS by SFI 08 in the ADF.
    r.apply(x("00A4040410A0000000871002FFFFFFFF8907090000"), x("9000"));
    EXPECT_EQ(h(r.apply(x("00B0880003"), x("07AABB9000"))), "00b0880003" "000000" "9000");
    // A path to AF20 from the MF.
    r.apply(x("00A4080C047FF0AF20"), x("9000"));
    EXPECT_EQ(h(r.apply(x("00B0000002"), x("AABB9000"))), "00b000000200009000");
    // Off (the test-only switch): nothing is masked.
    trace::Redactor off(false);
    off.apply(x("00A4000C024F05"), x("9000"));
    EXPECT_EQ(h(off.apply(x("00B0000002"), x("AABB9000"))), "00b0000002aabb9000");
}

TEST(Trace, ARealSessionThroughTheDecoratorKeepsTheKeysOut) {
    SimLoop loop;
    auto card = make_card();
    InProcTransport inproc(loop, card.get());
    std::vector<std::pair<std::uint8_t, std::string>> out;
    trace::TracingTransport t(inproc, [&](std::uint8_t sub, const Bytes& p) { out.emplace_back(sub, h(p)); });
    t.reset([](const Result<Bytes>&) {});
    t.transmit(x("00A40004023F00"), [](const Result<Bytes>&) {});   // T=0: 61xx
    loop.run_for(10);
    ASSERT_EQ(out.size(), 1u);   // the ATR; the SELECT still waits for its answer
    std::string sw;
    t.transmit(x("00C0000000"), [&](const Result<Bytes>& r) { sw = r ? to_hex(*r) : "err"; });   // again: 6Cxx
    loop.run_for(10);
    ASSERT_EQ(sw.substr(0, 2), "6c");
    t.transmit(*from_hex("00C00000" + sw.substr(2, 2)), [](const Result<Bytes>&) {});   // the right Le
    loop.run_for(10);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[1].second.substr(0, 14), "00a40004023f00");   // the SELECT with its FCP...
    EXPECT_EQ(out[1].second.substr(out[1].second.size() - 4), "9000");   // ...and 9000
    t.transmit(x("0020000A083131313131313131"), [](const Result<Bytes>&) {});   // ADM1 11111111
    loop.run_for(10);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0].first, trace::kSubAtr);
    EXPECT_EQ(out[0].second, h(card->atr()));
    EXPECT_EQ(out[1].first, trace::kSubApdu);
    EXPECT_EQ(out.back().second.find("3131313131313131"), std::string::npos);
    EXPECT_EQ(t.traced(), out.size());
}

} // namespace
} // namespace ksim::uicc::test
