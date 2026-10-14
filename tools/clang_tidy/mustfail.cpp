// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The clang-tidy hook's must-fail fixture (plan M14): a use after move, which
// .clang-tidy (bugprone-use-after-move) has to report. Not part of the build.

#include <string>
#include <utility>

std::string twice(std::string a) {
    std::string b = std::move(a);
    return a + b;
}
