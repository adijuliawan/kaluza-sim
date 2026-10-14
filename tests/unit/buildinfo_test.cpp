// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include <gtest/gtest.h>

#include <string_view>

#include "ksim/build_info.hpp"

TEST(BuildInfo, IdentityIsFilledIn) {
    EXPECT_FALSE(std::string_view(ksim::build::kVersion).empty());
    EXPECT_FALSE(std::string_view(ksim::build::kGitDescribe).empty());
    EXPECT_FALSE(std::string_view(ksim::build::kCxxCompiler).empty());
}
