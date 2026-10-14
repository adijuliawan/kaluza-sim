// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/mutation.hpp"

#include <cstdlib>
#include <string>

namespace ksim {

std::string_view active_mutant() noexcept {
    if constexpr (!kMutationsBuild) {
        return {};
    } else {
        static const std::string name = [] {
            const char* v = std::getenv("KSIM_MUTANT");   // NOLINT(concurrency-mt-unsafe): read once
            return std::string(v != nullptr ? v : "");
        }();
        return name;
    }
}

bool mutant_active(std::string_view name) noexcept {
    return kMutationsBuild && !name.empty() && active_mutant() == name;
}

} // namespace ksim
