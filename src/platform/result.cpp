// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/result.hpp"

namespace ksim {

const char* errc_name(Errc c) noexcept {
    switch (c) {
    case Errc::truncated:
        return "truncated";
    case Errc::malformed:
        return "malformed";
    case Errc::out_of_range:
        return "out_of_range";
    case Errc::unsupported:
        return "unsupported";
    case Errc::overflow:
        return "overflow";
    case Errc::invalid_argument:
        return "invalid_argument";
    case Errc::io:
        return "io";
    case Errc::closed:
        return "closed";
    case Errc::internal:
        return "internal";
    }
    return "unknown";
}

} // namespace ksim
