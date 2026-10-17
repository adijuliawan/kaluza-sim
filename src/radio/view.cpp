// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "radio/view.hpp"

#include <algorithm>

namespace ksim::radio {

std::optional<std::int16_t> StaticView::level(std::uint32_t radio_id, std::uint32_t cell) const {
    if (auto u = overrides_.find(radio_id); u != overrides_.end()) {
        if (auto o = u->second.find(cell); o != u->second.end()) {
            return o->second;
        }
    }
    auto c = cells_.find(cell);
    return c != cells_.end() ? std::optional<std::int16_t>(c->second) : std::nullopt;
}

std::vector<Heard> StaticView::heard(std::uint32_t radio_id) const {
    std::vector<Heard> out;
    for (const auto& [cell, rsrp] : cells_) {
        if (auto l = level(radio_id, cell)) {
            out.push_back({cell, *l});
        }
    }
    // A cell only an override knows is heard too.
    if (auto u = overrides_.find(radio_id); u != overrides_.end()) {
        for (const auto& [cell, l] : u->second) {
            if (l && cells_.count(cell) == 0) {
                out.push_back({cell, *l});
            }
        }
    }
    std::sort(out.begin(), out.end(), [](const Heard& a, const Heard& b) {
        return a.rsrp_dbm != b.rsrp_dbm ? a.rsrp_dbm > b.rsrp_dbm : a.cell < b.cell;
    });
    return out;
}

} // namespace ksim::radio
