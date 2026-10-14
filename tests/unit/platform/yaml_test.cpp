// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The YAML configuration reader (P1 N1): values by path, strict scalars, and
// errors that say where.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "platform/yaml.hpp"

namespace ksim {
namespace {

constexpr const char* kTopology = R"(plan: 00101
gnb:
  id: {value: 0x1A0, bits: 22}
  tac: 1
  enabled: true
ues:
  - persona: generic
    count: 3
  - persona: s22plus
    count: 1
)";

TEST(Yaml, ReadsValuesByPathWithHexAndDecimalIntegers) {
    const Yaml y = Yaml::parse(kTopology, "topo.yaml");
    EXPECT_EQ(y.at("gnb").at("id").at("value").as<std::uint32_t>(), 0x1A0u);
    EXPECT_EQ(y.at("gnb").at("id").at("bits").as<std::uint8_t>(), 22);
    EXPECT_TRUE(y.at("gnb").at("enabled").as<bool>());
    EXPECT_EQ(y.at("plan").as<std::string>(), "00101");   // a PLMN stays text
    ASSERT_TRUE(y.at("ues").is_seq());
    EXPECT_EQ(y.at("ues").size(), 2u);
    EXPECT_EQ(y.at("ues").at(1).at("persona").as<std::string>(), "s22plus");
    EXPECT_EQ(y.at("ues").at(1).path(), "ues[1]");
    EXPECT_EQ(y.at("gnb").get<std::int32_t>("pci", 101), 101);
    EXPECT_EQ(y.at("gnb").get<std::int32_t>("tac", 7), 1);
}

TEST(Yaml, ErrorsNameTheFileLineAndPath) {
    const Yaml y = Yaml::parse(kTopology, "topo.yaml");
    try {
        (void)y.at("ues").at(0).at("count").as<bool>();
        FAIL() << "a count is not a boolean";
    } catch (const YamlError& e) {
        EXPECT_EQ(e.path(), "ues[0].count");
        EXPECT_EQ(e.where(), "topo.yaml:8:12");
        EXPECT_NE(std::string(e.what()).find("not true or false"), std::string::npos);
    }
    EXPECT_THROW((void)y.at("gnb").at("pci"), YamlError);
    EXPECT_THROW((void)y.at("ues").at(5), YamlError);
    EXPECT_THROW((void)y.at("gnb").at("id").at("value").as<std::uint8_t>(), YamlError);   // 0x1A0 > 255
    EXPECT_THROW((void)Yaml::parse("a: [1, 2", "broken.yaml"), YamlError);
}

TEST(Yaml, ScalarsAreStrict) {
    const Yaml y = Yaml::parse("a: yes\nb: -1\nc: 1.5\nd: 0x\ne: 12abc\nf: -9223372036854775808\n");
    EXPECT_THROW((void)y.at("a").as<bool>(), YamlError);   // only true and false
    EXPECT_THROW((void)y.at("b").as<std::uint32_t>(), YamlError);
    EXPECT_EQ(y.at("b").as<std::int32_t>(), -1);
    EXPECT_DOUBLE_EQ(y.at("c").as<double>(), 1.5);
    EXPECT_THROW((void)y.at("c").as<std::int64_t>(), YamlError);
    EXPECT_THROW((void)y.at("d").as<std::int64_t>(), YamlError);
    EXPECT_THROW((void)y.at("e").as<std::int64_t>(), YamlError);
    EXPECT_EQ(y.at("f").as<std::int64_t>(), INT64_MIN);
}

TEST(Yaml, OnlyRefusesAnUnknownKey) {
    const Yaml y = Yaml::parse("gnb:\n  tac: 1\n  pcy: 101\n", "t.yaml");
    EXPECT_NO_THROW(y.at("gnb").only({"tac", "pcy"}));
    try {
        y.at("gnb").only({"tac", "pci"});
        FAIL() << "a misspelt key must be an error";
    } catch (const YamlError& e) {
        EXPECT_EQ(e.path(), "gnb.pcy");
        EXPECT_EQ(e.where(), "t.yaml:3:3");
    }
}

TEST(Yaml, NullAndAbsentFallBack) {
    const Yaml y = Yaml::parse("a: ~\nb:\n");
    EXPECT_TRUE(y.at("a").is_null());
    EXPECT_EQ(y.get<std::int32_t>("a", 4), 4);
    EXPECT_EQ(y.get<std::int32_t>("b", 5), 5);
    EXPECT_EQ(y.get<std::int32_t>("c", 6), 6);
    EXPECT_FALSE(y.has("c"));
}

} // namespace
} // namespace ksim
