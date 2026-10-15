// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Personas (P1 N15): every file in personas/ loads, its NR capability decodes
// with our RRC codec, the generic one is the UE's built-in capability, and the
// intersection rules of node/ue/persona hold (row KS-SCN-B1).

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "codec/asn1/msg/rrc.hpp"
#include "node/ue/persona.hpp"

namespace ksim::node {
namespace {

namespace fs = std::filesystem;
const std::string kDir = std::string(KSIM_SOURCE_DIR) + "/personas";

TEST(Persona, EveryPersonaInTheRepositoryLoads) {
    std::size_t n = 0;
    for (const auto& e : fs::directory_iterator(kDir)) {
        if (e.path().extension() != ".yaml") {
            continue;
        }
        std::string why;
        auto p = load_persona(e.path().string(), why);
        ASSERT_TRUE(p) << e.path() << ": " << why;
        EXPECT_TRUE(p->nr_capability().has_value()) << e.path();
        ++n;
    }
    EXPECT_EQ(n, 3u);   // generic, oneplus9pro, s22plus
}

TEST(Persona, TheGenericOneIsTheBuiltInCapability) {
    std::string why;
    auto p = load_persona(kDir + "/generic.yaml", why);
    ASSERT_TRUE(p) << why;
    auto built_in = rrc::generic_nr_capability();
    ASSERT_TRUE(built_in);
    EXPECT_EQ(to_hex(p->nr_capability().value_or(Bytes{})), to_hex(*built_in));
    EXPECT_FALSE(p->tac.has_value());
    EXPECT_FALSE(p->mm_capability_sent().has_value());
    EXPECT_EQ(to_hex(p->security().encode()), "e060");
}

TEST(Persona, TheIntersectionKeepsOnlyWhatTheSimImplements) {
    Persona p;
    p.ue_security_capability = *from_hex("f070f070");   // EA0-3, IA1-3 and EPS
    p.mm_capability = *from_hex("07");                  // S1 mode, HO attach, LPP
    EXPECT_EQ(to_hex(p.security().encode()), "e060");
    EXPECT_EQ(to_hex(p.mm_capability_sent().value_or(Bytes{})), "00");
    p.ue_security_capability = *from_hex("1010");       // EA3 and IA3 only (ZUC): EA0 is left
    EXPECT_EQ(to_hex(p.security().encode()), "8000");
}

TEST(Persona, ACapabilityThatDoesNotDecodeIsRefused) {
    const std::string f = (fs::temp_directory_path() / "ksim-bad-persona.yaml").string();
    std::ofstream(f) << "name: bad\nrrc:\n  ue_capability_rat_containers:\n    - {rat: nr, uper: ffffffff}\n";
    std::string why;
    EXPECT_FALSE(load_persona(f, why));
    EXPECT_NE(why.find("does not decode"), std::string::npos) << why;
    fs::remove(f);
}

} // namespace
} // namespace ksim::node
