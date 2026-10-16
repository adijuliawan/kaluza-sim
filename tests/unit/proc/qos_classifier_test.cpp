// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The packet filter classifier (P2 Q10; TS 24.501 Table 9.11.4.13.1, TS 23.501 5.7.1.5):
// every component type matches the packet it describes and not one that differs in that
// field, from the UE's side in both directions; precedence decides between rules.

#include <gtest/gtest.h>

#include <initializer_list>
#include <vector>

#include "platform/mutation.hpp"
#include "proc/ue/qos_classifier.hpp"

namespace ksim::proc::ue {
namespace {

using Rule = nas::ie::QosRules::Rule;
using Filter = nas::ie::QosRules::PacketFilter;
using Component = nas::ie::QosRules::Component;

Component c(std::uint8_t type, std::initializer_list<std::uint8_t> v = {}) { return Component{type, Bytes(v)}; }
Filter f(std::uint8_t direction, std::vector<Component> comps) { return Filter{direction, 1, std::move(comps)}; }

/// An IPv4 packet from the UE (src) to the far end (dst): protocol, ports or SPI, ToS.
Bytes ipv4(std::array<std::uint8_t, 4> src, std::array<std::uint8_t, 4> dst, std::uint8_t proto, std::uint16_t sport,
           std::uint16_t dport, std::uint8_t tos = 0, std::uint32_t spi = 0) {
    Bytes p = {0x45, tos, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0};
    p.insert(p.end(), src.begin(), src.end());
    p.insert(p.end(), dst.begin(), dst.end());
    if (proto == 50) {   // ESP: SPI, sequence
        p.insert(p.end(), {static_cast<std::uint8_t>(spi >> 24), static_cast<std::uint8_t>(spi >> 16),
                           static_cast<std::uint8_t>(spi >> 8), static_cast<std::uint8_t>(spi), 0, 0, 0, 1});
    } else if (proto == 51) {   // AH: next header, length, reserved, SPI
        p.insert(p.end(), {17, 4, 0, 0, static_cast<std::uint8_t>(spi >> 24), static_cast<std::uint8_t>(spi >> 16),
                           static_cast<std::uint8_t>(spi >> 8), static_cast<std::uint8_t>(spi)});
    } else {
        p.insert(p.end(), {static_cast<std::uint8_t>(sport >> 8), static_cast<std::uint8_t>(sport),
                           static_cast<std::uint8_t>(dport >> 8), static_cast<std::uint8_t>(dport), 0, 8, 0, 0});
    }
    p[3] = static_cast<std::uint8_t>(p.size());
    return p;
}

/// An IPv6 UDP packet with a hop-by-hop options header before it, traffic class and flow label.
Bytes ipv6(std::uint8_t src_last, std::uint8_t dst_last, std::uint8_t tc, std::uint32_t label, std::uint16_t sport,
           std::uint16_t dport) {
    const auto tc_low = static_cast<std::uint32_t>(tc & 0x0F);
    Bytes p = {static_cast<std::uint8_t>(0x60 | tc >> 4), static_cast<std::uint8_t>(tc_low << 4 | (label >> 16 & 0x0F)),
               static_cast<std::uint8_t>(label >> 8), static_cast<std::uint8_t>(label), 0, 16, 0, 64};
    Bytes src(16, 0x20);
    src[15] = src_last;
    Bytes dst(16, 0x30);
    dst[15] = dst_last;
    p.insert(p.end(), src.begin(), src.end());
    p.insert(p.end(), dst.begin(), dst.end());
    p.insert(p.end(), {17, 0, 1, 4, 0, 0, 0, 0});   // hop-by-hop: next UDP, length 0 (8 octets)
    p.insert(p.end(), {static_cast<std::uint8_t>(sport >> 8), static_cast<std::uint8_t>(sport),
                       static_cast<std::uint8_t>(dport >> 8), static_cast<std::uint8_t>(dport), 0, 8, 0, 0});
    return p;
}

/// An Ethernet frame from the UE's MAC (…:01) to the far end's (…:02), S-TAG and C-TAG, ethertype.
Bytes eth(std::uint8_t dst_last, std::uint16_t s_tci, std::uint16_t c_tci, std::uint16_t type) {
    Bytes p = {0x02, 0, 0, 0, 0, dst_last, 0x02, 0, 0, 0, 0, 0x01};
    p.insert(p.end(), {0x88, 0xA8, static_cast<std::uint8_t>(s_tci >> 8), static_cast<std::uint8_t>(s_tci)});
    p.insert(p.end(), {0x81, 0x00, static_cast<std::uint8_t>(c_tci >> 8), static_cast<std::uint8_t>(c_tci)});
    p.insert(p.end(), {static_cast<std::uint8_t>(type >> 8), static_cast<std::uint8_t>(type), 0xde, 0xad});
    return p;
}

constexpr auto UL = QosDirection::uplink;
constexpr auto DL = QosDirection::downlink;

bool m(std::vector<Component> comps, const Bytes& pkt, QosDirection dir = UL, PduKind k = PduKind::ip) {
    return filter_matches(f(3, std::move(comps)), pkt, dir, k);
}

TEST(QosClassifier, Ts24501_Table9_11_4_13_1_EachIpComponent) {
    const Bytes up = ipv4({10, 45, 0, 5}, {10, 60, 0, 2}, 17, 4000, 5004, 0xB8);
    // match-all
    EXPECT_TRUE(m({c(0x01)}, up));
    // IPv4 remote (the destination going up) and local (the source), with masks
    EXPECT_TRUE(m({c(0x10, {10, 60, 0, 0, 255, 255, 255, 0})}, up));
    EXPECT_FALSE(m({c(0x10, {10, 61, 0, 0, 255, 255, 255, 0})}, up));
    EXPECT_TRUE(m({c(0x11, {10, 45, 0, 5, 255, 255, 255, 255})}, up));
    EXPECT_FALSE(m({c(0x11, {10, 45, 0, 6, 255, 255, 255, 255})}, up));
    // protocol identifier
    EXPECT_TRUE(m({c(0x30, {17})}, up));
    EXPECT_FALSE(m({c(0x30, {6})}, up));
    // single and range ports, local and remote
    EXPECT_TRUE(m({c(0x40, {0x0F, 0xA0})}, up));             // 4000
    EXPECT_FALSE(m({c(0x40, {0x0F, 0xA1})}, up));
    EXPECT_TRUE(m({c(0x41, {0x0F, 0x00, 0x0F, 0xFF})}, up));
    EXPECT_FALSE(m({c(0x41, {0x10, 0x00, 0x10, 0xFF})}, up));
    EXPECT_TRUE(m({c(0x50, {0x13, 0x8C})}, up));             // 5004
    EXPECT_FALSE(m({c(0x50, {0x13, 0x8D})}, up));
    EXPECT_TRUE(m({c(0x51, {0x13, 0x88, 0x13, 0x90})}, up));
    EXPECT_FALSE(m({c(0x51, {0x00, 0x01, 0x00, 0x02})}, up));
    // type of service with mask (DSCP EF, 0xB8)
    EXPECT_TRUE(m({c(0x70, {0xB8, 0xFC})}, up));
    EXPECT_FALSE(m({c(0x70, {0x28, 0xFC})}, up));
    // SPI, ESP and AH
    const Bytes esp = ipv4({10, 45, 0, 5}, {10, 60, 0, 2}, 50, 0, 0, 0, 0x01020304);
    const Bytes ah = ipv4({10, 45, 0, 5}, {10, 60, 0, 2}, 51, 0, 0, 0, 0x01020304);
    EXPECT_TRUE(m({c(0x60, {1, 2, 3, 4})}, esp));
    EXPECT_TRUE(m({c(0x60, {1, 2, 3, 4})}, ah));
    EXPECT_FALSE(m({c(0x60, {1, 2, 3, 5})}, esp));
    EXPECT_FALSE(m({c(0x60, {1, 2, 3, 4})}, up));   // no SPI in UDP
    // a component the packet does not have: a port in ICMP
    const Bytes icmp = ipv4({10, 45, 0, 5}, {10, 60, 0, 2}, 1, 0, 0);
    EXPECT_FALSE(m({c(0x50, {0, 0})}, icmp));
    // all components of a filter must match
    EXPECT_TRUE(m({c(0x10, {10, 60, 0, 2, 255, 255, 255, 255}), c(0x30, {17}), c(0x50, {0x13, 0x8C})}, up));
    EXPECT_FALSE(m({c(0x10, {10, 60, 0, 2, 255, 255, 255, 255}), c(0x30, {6})}, up));
}

TEST(QosClassifier, Ts24501_Table9_11_4_13_1_Ipv6ComponentsPastAnExtensionHeader) {
    const Bytes up = ipv6(5, 9, 0xB8, 0x12345, 4000, 5004);
    Bytes remote(17, 0x30);
    remote[16] = 120;   // a /120 prefix
    EXPECT_TRUE(m({c(0x21, {})}, up) == false);   // a value too short never matches
    Component r6{0x21, remote};
    EXPECT_TRUE(m({r6}, up));
    Bytes local(17, 0x20);
    local[15] = 5;
    local[16] = 128;   // a /128
    EXPECT_TRUE(m({Component{0x23, local}}, up));
    local[15] = 6;
    EXPECT_FALSE(m({Component{0x23, local}}, up));
    EXPECT_TRUE(m({c(0x30, {17})}, up));   // the next header after hop-by-hop
    EXPECT_TRUE(m({c(0x50, {0x13, 0x8C})}, up));
    EXPECT_TRUE(m({c(0x70, {0xB8, 0xFF})}, up));
    EXPECT_TRUE(m({c(0x80, {0x01, 0x23, 0x45})}, up));
    EXPECT_FALSE(m({c(0x80, {0x01, 0x23, 0x46})}, up));
    EXPECT_FALSE(m({c(0x10, {10, 60, 0, 2, 255, 255, 255, 255})}, up));   // an IPv4 address on IPv6
}

TEST(QosClassifier, Ts24501_Table9_11_4_13_1_EthernetComponents) {
    const Bytes up = eth(0x02, 0x6064, 0xA00A, 0x0800);   // S-TAG PCP 3 VID 100, C-TAG PCP 5 VID 10
    const auto e = [&up](std::vector<Component> comps) { return m(std::move(comps), up, UL, PduKind::ethernet); };
    EXPECT_TRUE(e({c(0x81, {0x02, 0, 0, 0, 0, 0x02})}));   // destination (remote) MAC
    EXPECT_FALSE(e({c(0x81, {0x02, 0, 0, 0, 0, 0x03})}));
    EXPECT_TRUE(e({c(0x82, {0x02, 0, 0, 0, 0, 0x01})}));   // source (local) MAC
    EXPECT_TRUE(e({c(0x88, {0x02, 0, 0, 0, 0, 0x00, 0x02, 0, 0, 0, 0, 0x0F})}));   // destination range
    EXPECT_FALSE(e({c(0x88, {0x02, 0, 0, 0, 0, 0x03, 0x02, 0, 0, 0, 0, 0x0F})}));
    EXPECT_TRUE(e({c(0x89, {0x02, 0, 0, 0, 0, 0x00, 0x02, 0, 0, 0, 0, 0x01})}));
    EXPECT_TRUE(e({c(0x83, {0x00, 0x0A})}));   // C-TAG VID 10
    EXPECT_FALSE(e({c(0x83, {0x00, 0x0B})}));
    EXPECT_TRUE(e({c(0x84, {0x00, 0x64})}));   // S-TAG VID 100
    EXPECT_TRUE(e({c(0x85, {0x0A})}));         // C-TAG PCP 5, DEI 0
    EXPECT_FALSE(e({c(0x85, {0x0B})}));
    EXPECT_TRUE(e({c(0x86, {0x06})}));         // S-TAG PCP 3, DEI 0
    EXPECT_TRUE(e({c(0x8A, {0x20 | 0x0A})}));  // extended: PCP present, 5
    EXPECT_TRUE(e({c(0x8A, {0x10})}));         // extended: DEI present, 0
    EXPECT_FALSE(e({c(0x8A, {0x20 | 0x0C})}));
    EXPECT_TRUE(e({c(0x8B, {0x20 | 0x06})}));
    EXPECT_TRUE(e({c(0x87, {0x08, 0x00})}));   // ethertype after both tags
    EXPECT_FALSE(e({c(0x87, {0x86, 0xDD})}));
    EXPECT_FALSE(m({c(0x81, {0x02, 0, 0, 0, 0, 0x02})}, ipv4({1, 1, 1, 1}, {2, 2, 2, 2}, 17, 1, 1)));   // no MAC in IP
    EXPECT_FALSE(e({c(0x91, {0})}));   // (S)RTP multiplexed media: not matched
}

TEST(QosClassifier, LocalAndRemoteSwapInTheDownlinkAndTheDirectionFieldHolds) {
    const Bytes down = ipv4({10, 60, 0, 2}, {10, 45, 0, 5}, 17, 5004, 4000);   // the far end to the UE
    const std::vector<Component> remote = {c(0x10, {10, 60, 0, 2, 255, 255, 255, 255}), c(0x50, {0x13, 0x8C})};
    EXPECT_TRUE(filter_matches(f(3, remote), down, DL));    // bidirectional
    EXPECT_TRUE(filter_matches(f(1, remote), down, DL));    // downlink only
    EXPECT_FALSE(filter_matches(f(2, remote), down, DL));   // uplink only
    EXPECT_FALSE(filter_matches(f(1, remote), ipv4({10, 45, 0, 5}, {10, 60, 0, 2}, 17, 4000, 5004), UL));
}

Rule rule(std::uint8_t id, std::uint8_t qfi, std::uint8_t precedence, std::vector<Filter> filters, bool dqr = false) {
    Rule r;
    r.id = id;
    r.qfi = qfi;
    r.precedence = precedence;
    r.filters = std::move(filters);
    r.default_rule = dqr;
    return r;
}

TEST(QosClassifier, Ts23501_5_7_1_5_TheLowestPrecedenceValueWinsAndNoMatchIsNone) {
    const Bytes to2 = ipv4({10, 45, 0, 5}, {10, 60, 0, 2}, 17, 4000, 5004);
    const Bytes to1 = ipv4({10, 45, 0, 5}, {10, 60, 0, 1}, 1, 0, 0);
    const std::vector<Rule> rules = {
        rule(1, 1, 255, {f(3, {c(0x01)})}, true),                                        // the default: match-all
        rule(2, 2, 20, {f(2, {c(0x10, {10, 60, 0, 2, 255, 255, 255, 255})})}),           // to 10.60.0.2
        rule(3, 3, 10, {f(2, {c(0x10, {10, 60, 0, 2, 255, 255, 255, 255}), c(0x30, {17})})}),   // and UDP: first
    };
    ASSERT_NE(classify(rules, to2, UL), nullptr);
    EXPECT_EQ(classify(rules, to2, UL)->qfi, 3);
    EXPECT_EQ(classify(rules, to1, UL)->qfi, 1);
    const std::vector<Rule> narrow = {rule(2, 2, 20, {f(2, {c(0x10, {10, 60, 0, 2, 255, 255, 255, 255})})})};
    EXPECT_EQ(classify(narrow, to1, UL), nullptr);   // no rule matches: not sent
}

TEST(QosClassifier, Mutants_DefaultOnlyAndPrecedenceReversed) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "a mutant build's test";
    }
    const Bytes to2 = ipv4({10, 45, 0, 5}, {10, 60, 0, 2}, 17, 4000, 5004);
    const std::vector<Rule> rules = {rule(1, 1, 255, {f(3, {c(0x01)})}, true),
                                     rule(3, 3, 10, {f(2, {c(0x10, {10, 60, 0, 2, 255, 255, 255, 255})})})};
    {
        const testing::MutantScope s("classifier_default_only");
        EXPECT_EQ(classify(rules, to2, UL)->qfi, 1);
    }
    {
        const testing::MutantScope s("precedence_reversed");
        EXPECT_EQ(classify(rules, to2, UL)->qfi, 1);   // 255 first
    }
}

} // namespace
} // namespace ksim::proc::ue
