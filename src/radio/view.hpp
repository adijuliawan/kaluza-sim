// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The radio seam (P3 R2; ADR 0013 point 3): what each UE hears. A UE asks which
// cells (by their KAIR handle) reach it and at what level, and camps by cell
// selection over the answer; a DU's frames from a cell the UE does not hear do
// not reach it. R2 brings StaticView (the topology's cells at their configured
// power, edited by `cell power` and by the per-UE overrides tests set); R15 puts
// the TR 38.901 replica behind the same interface without touching the UE or the
// DU. Levels are integer dBm (an SS-RSRP), so every process computes the same
// answer (ADR 0013 point 11). Pure (R8): no I/O, no clock.

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace ksim::radio {

struct Heard {
    std::uint32_t cell = 0;          // KAIR cell handle
    std::int16_t rsrp_dbm = -80;
    friend bool operator==(const Heard&, const Heard&) = default;
};

class IRadioView {
public:
    virtual ~IRadioView() = default;
    /// The cells UE `radio_id` hears now, the strongest first (a tie: the lower handle).
    virtual std::vector<Heard> heard(std::uint32_t radio_id) const = 0;
    /// One cell's level at the UE, or none when the UE does not hear it.
    virtual std::optional<std::int16_t> level(std::uint32_t radio_id, std::uint32_t cell) const = 0;
};

/// Every UE hears every cell at the cell's power, unless an override for that UE
/// says otherwise (a level, or not heard at all).
class StaticView final : public IRadioView {
public:
    void set_cell(std::uint32_t cell, std::int16_t rsrp_dbm) { cells_[cell] = rsrp_dbm; }
    void remove_cell(std::uint32_t cell) { cells_.erase(cell); }
    /// For one UE: the cell at `rsrp_dbm`, or not heard (std::nullopt).
    void set_ue_cell(std::uint32_t radio_id, std::uint32_t cell, std::optional<std::int16_t> rsrp_dbm) {
        overrides_[radio_id][cell] = rsrp_dbm;
    }
    void clear_ue(std::uint32_t radio_id) { overrides_.erase(radio_id); }

    std::vector<Heard> heard(std::uint32_t radio_id) const override;
    std::optional<std::int16_t> level(std::uint32_t radio_id, std::uint32_t cell) const override;

private:
    std::map<std::uint32_t, std::int16_t> cells_;
    std::map<std::uint32_t, std::map<std::uint32_t, std::optional<std::int16_t>>> overrides_;
};

} // namespace ksim::radio
