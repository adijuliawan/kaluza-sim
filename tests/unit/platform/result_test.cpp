// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "platform/result.hpp"

using ksim::Errc;
using ksim::Error;
using ksim::Result;

namespace {

Result<int> parse_digit(char c) {
    if (c < '0' || c > '9') {
        return Error{Errc::malformed, 0, "not a digit"};
    }
    return c - '0';
}

} // namespace

TEST(Result, ValueAndError) {
    auto ok = parse_digit('7');
    ASSERT_TRUE(ok);
    EXPECT_EQ(*ok, 7);

    auto bad = parse_digit('x');
    ASSERT_FALSE(bad);
    EXPECT_EQ(bad.error().code, Errc::malformed);
    EXPECT_STREQ(bad.error().what, "not a digit");
    EXPECT_EQ(bad.value_or(-1), -1);
}

TEST(Result, MoveOnlyPayload) {
    Result<std::unique_ptr<std::string>> r = std::make_unique<std::string>("x");
    ASSERT_TRUE(r);
    std::unique_ptr<std::string> p = std::move(r).value();
    EXPECT_EQ(*p, "x");
}

TEST(Result, VoidSpecialisation) {
    Result<void> ok;
    EXPECT_TRUE(ok);
    Result<void> bad = Error{Errc::truncated, 12, "short"};
    ASSERT_FALSE(bad);
    EXPECT_EQ(bad.error().offset, 12U);
    EXPECT_STREQ(ksim::errc_name(bad.error().code), "truncated");
}
