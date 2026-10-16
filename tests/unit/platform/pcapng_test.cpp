// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The pcapng writers (plan M13): block structure, and a capture with each
// framing read back by tshark on stdin (skipped where tshark is absent): the
// dissectors it names, the comments and the timestamps. A damaged block must
// make tshark complain (the must-fail case).

#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <string_view>

#include "platform/pcapng.hpp"

namespace ksim::pcap {
namespace {

Bytes hex(std::string_view s) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(s.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

std::uint32_t le32(const Bytes& b, std::size_t at) {
    return std::uint32_t{b[at]} | (std::uint32_t{b[at + 1]} << 8) | (std::uint32_t{b[at + 2]} << 16) |
           (std::uint32_t{b[at + 3]} << 24);
}

Bytes capture() {
    Bytes out;
    PcapngWriter w([&](ByteView b) { out.insert(out.end(), b.begin(), b.end()); });
    const auto upper = w.add_interface(LinkType::upper_pdu, "uu");
    const auto ip = w.add_interface(LinkType::ipv4, "n3");
    // a REGISTRATION REQUEST (TS 24.501 8.2.6) as the Uu NAS capture carries it
    EXPECT_TRUE(w.write(upper, 1'760'000'000'123'456'789, exported_pdu("nas-5gs", hex("7e004179000d0100f110000000000000000001")),
                        "SUPI imsi-001010000300000"));
    // a GTP-U Echo Request on 2152 and a GSMTAP-SIM SELECT MF with its response
    Udp4 g;
    g.dst_port = kGtpuPort;
    EXPECT_TRUE(w.write(ip, 1'760'000'000'200'000'000, *ipv4_udp(g, hex("320100040000000012340000"))));
    Udp4 s;
    s.dst_port = kGsmtapPort;
    EXPECT_TRUE(w.write(ip, 1'760'000'000'300'000'000,
                        *ipv4_udp(s, gsmtap(kGsmtapSim, 0, hex("00a40004023f00" "9000")))));
    EXPECT_FALSE(w.write(5, 0, hex("00")));   // no such interface
    return out;
}

TEST(Pcapng, BlocksAreWholeAndClosed) {
    const Bytes c = capture();
    std::size_t at = 0;
    int blocks = 0;
    while (at < c.size()) {
        const std::uint32_t len = le32(c, at + 4);
        ASSERT_EQ(len % 4, 0U);
        ASSERT_LE(at + len, c.size());
        EXPECT_EQ(le32(c, at + len - 4), len);   // the length again at the end
        at += len;
        ++blocks;
    }
    EXPECT_EQ(blocks, 1 + 2 + 3);
    EXPECT_EQ(le32(c, 0), 0x0A0D0D0AU);
    EXPECT_EQ(le32(c, 8), 0x1A2B3C4DU);
}

TEST(Pcapng, ExportedPduNamePadding) {
    EXPECT_EQ(exported_pdu("ngap", hex("00")), hex("000c0004" "6e676170" "00000000" "00"));
    EXPECT_EQ(exported_pdu("nas-5gs", {}), hex("000c0008" "6e61732d35677300" "00000000"));
    const auto ip = ipv4_udp(Udp4{}, hex("aa"));
    ASSERT_TRUE(ip);
    EXPECT_EQ(ip->size(), 29U);
    // the IPv4 header checksum sums to 0xFFFF
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < 20; i += 2) {
        sum += (std::uint32_t{(*ip)[i]} << 8) | (*ip)[i + 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    EXPECT_EQ(sum, 0xFFFFU);
}

std::string tshark(const Bytes& pcap, const std::string& args) {
    // one file per test: ctest runs the tests of this binary in parallel processes
    const std::string path = ::testing::TempDir() + "ksim_pcapng_" +
                             ::testing::UnitTest::GetInstance()->current_test_info()->name() + "_" +
                             std::to_string(::getpid()) + ".pcapng";
    std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(pcap.data()),
                                                static_cast<std::streamsize>(pcap.size()));
    const std::string cmd = "tshark -n -r - " + args + " < " + path + " 2>&1";
    std::string out;
    if (FILE* p = ::popen(cmd.c_str(), "r")) {
        char buf[4096];
        while (std::size_t n = std::fread(buf, 1, sizeof buf, p)) {
            out.append(buf, n);
        }
        ::pclose(p);
    }
    std::remove(path.c_str());
    return out;
}

bool have_tshark() {
    return std::system("tshark -v > /dev/null 2>&1") == 0;
}

TEST(Pcapng, TsharkReadsEachFraming) {
    if (!have_tshark()) {
        GTEST_SKIP() << "no tshark";
    }
    const std::string out = tshark(capture(), "-T fields -E separator=/t -e frame.time_epoch -e frame.protocols "
                                              "-e frame.comment -e _ws.expert.message");
    std::vector<std::string> rows;
    for (std::size_t a = 0, b; a < out.size(); a = b + 1) {
        b = out.find('\n', a);
        if (b == std::string::npos) {
            b = out.size();
        }
        rows.push_back(out.substr(a, b - a));
    }
    ASSERT_GE(rows.size(), 3U) << out;
    EXPECT_NE(rows[0].find("1760000000.123456789"), std::string::npos) << rows[0];
    EXPECT_NE(rows[0].find("exported_pdu:nas-5gs"), std::string::npos) << rows[0];
    EXPECT_NE(rows[0].find("SUPI imsi-001010000300000"), std::string::npos) << rows[0];
    EXPECT_NE(rows[1].find("ip:udp:gtp"), std::string::npos) << rows[1];
    EXPECT_NE(rows[2].find("gsmtap:gsm_sim"), std::string::npos) << rows[2];
    for (const auto& r : rows) {
        EXPECT_EQ(r.find("alformed"), std::string::npos) << r;
    }
}

TEST(Pcapng, TsharkRefusesADamagedBlock) {
    if (!have_tshark()) {
        GTEST_SKIP() << "no tshark";
    }
    Bytes c = capture();
    c[c.size() - 4] ^= 0x04;   // the last block's closing length no longer matches
    const std::string out = tshark(c, "-T fields -e frame.number");
    EXPECT_TRUE(out.find("damaged") != std::string::npos || out.find("corrupt") != std::string::npos ||
                out.find("isn't") != std::string::npos || out.find("rror") != std::string::npos)
        << out;
}

} // namespace
} // namespace ksim::pcap

namespace ksim::pcap {
namespace {

// P2 Q12: a headers-only frame is the full frame's first octets, its lengths and checksum
// the whole frame's.
TEST(Pcapng, AHeadOnlyFrameIsTheFullFramesPrefixWithItsLengths) {
    Udp4 u;
    u.src = {10, 0, 0, 1};
    u.dst = {10, 0, 0, 2};
    u.src_port = 2152;
    u.dst_port = 2152;
    const Bytes pdu(1400, 0x5A);
    auto full = ipv4_udp(u, pdu);
    auto head = ipv4_udp_head(u, pdu, 100);
    ASSERT_TRUE(full && head);
    ASSERT_EQ(head->size(), 128u);
    EXPECT_TRUE(std::equal(head->begin(), head->end(), full->begin()));
    EXPECT_EQ(((*head)[2] << 8) | (*head)[3], 1428);   // the IPv4 total length: the whole frame's
    auto all = ipv4_udp_head(u, pdu, 5000);
    ASSERT_TRUE(all);
    EXPECT_EQ(*all, *full);
}

} // namespace
} // namespace ksim::pcap
