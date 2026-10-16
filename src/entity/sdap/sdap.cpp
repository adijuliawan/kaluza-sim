// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "entity/sdap/sdap.hpp"

namespace ksim::entity {

void Sdap::configure(const SdapDrb& d) {
    if (d.default_drb) {
        for (auto& [id, other] : drbs_) {
            other.default_drb = false;   // one default DRB per PDU session
        }
    }
    drbs_[d.drb_id] = d;
    for (std::uint8_t q : d.qfis_release) {
        // TS 37.324 5.3.1: a released mapping goes; a flow remapped elsewhere keeps the new one.
        if (auto it = qfi_to_drb_.find(q & 0x3F); it != qfi_to_drb_.end() && it->second == d.drb_id) {
            qfi_to_drb_.erase(it);
        }
    }
    for (std::uint8_t q : d.qfis) {
        qfi_to_drb_[q & 0x3F] = d.drb_id;
    }
}

std::vector<std::uint8_t> Sdap::flows_of(std::uint8_t drb_id) const {
    std::vector<std::uint8_t> out;
    for (const auto& [q, d] : qfi_to_drb_) {
        if (d == drb_id) {
            out.push_back(q);
        }
    }
    return out;
}

void Sdap::release(std::uint8_t drb_id) {
    drbs_.erase(drb_id);
    for (auto it = qfi_to_drb_.begin(); it != qfi_to_drb_.end();) {
        it = it->second == drb_id ? qfi_to_drb_.erase(it) : std::next(it);
    }
}

std::optional<std::uint8_t> Sdap::default_drb() const {
    for (const auto& [id, d] : drbs_) {
        if (d.default_drb) {
            return id;
        }
    }
    return std::nullopt;
}

std::optional<Sdap::Ul> Sdap::map_ul(std::uint8_t qfi, Bytes sdu) const {
    std::optional<std::uint8_t> drb;
    if (auto it = qfi_to_drb_.find(qfi & 0x3F); it != qfi_to_drb_.end()) {
        drb = it->second;
    } else {
        drb = default_drb();
    }
    if (!drb) {
        return std::nullopt;
    }
    const SdapDrb& d = drbs_.at(*drb);
    Ul out;
    out.drb_id = *drb;
    if (d.header_ul) {
        out.pdu.reserve(sdu.size() + 1);
        out.pdu.push_back(sdap::encode(sdap::UlHeader{true, static_cast<std::uint8_t>(qfi & 0x3F)}));
        out.pdu.insert(out.pdu.end(), sdu.begin(), sdu.end());
    } else {
        out.pdu = std::move(sdu);
    }
    return out;
}

Result<Sdap::Dl> Sdap::on_dl(std::uint8_t drb_id, Bytes pdu) const {
    auto it = drbs_.find(drb_id);
    if (it == drbs_.end()) {
        return make_error(Errc::invalid_argument, 0, "SDAP: a DRB this session does not have");
    }
    Dl out;
    if (it->second.header_dl) {
        if (pdu.empty()) {
            return make_error(Errc::truncated, 0, "SDAP: no header");
        }
        out.header = sdap::decode_dl(pdu.front());
        out.sdu.assign(pdu.begin() + 1, pdu.end());
    } else {
        out.sdu = std::move(pdu);
    }
    return out;
}

} // namespace ksim::entity
