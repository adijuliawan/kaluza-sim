// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/transport/bridge.hpp"

#include "platform/mutation.hpp"

namespace ksim::uicc::bridge {

namespace {

constexpr std::uint16_t kRefused = 0x6982;   // security status not satisfied (TS 102 221 §10.2.1.5)

bool adm_key(std::uint8_t p2) noexcept { return p2 >= 0x0A && p2 <= 0x0E; }

} // namespace

std::optional<std::uint16_t> AdminFilter::check(ByteView c) {
    if (c.size() < 4) {
        return std::nullopt;   // the card judges a short APDU
    }
    const std::uint8_t ins = c[1];
    const std::uint8_t p1 = c[2];
    const std::uint8_t p2 = c[3];
    if (ins == 0xA4) {
        // SELECT (§11.1.1): by FID (P1 00) or by path (08 from the MF, 09 from the current DF), the
        // last FID is the file; by DF name (04) an ADF, never a key file.
        if ((p1 == 0x00 || p1 == 0x08 || p1 == 0x09) && c.size() >= 7 && c[4] >= 2 && c.size() >= 5U + c[4]) {
            const std::size_t end = 5U + c[4];
            selected_ = static_cast<std::uint16_t>((c[end - 2] << 8) | c[end - 1]);
        } else {
            selected_ = 0;
        }
        return std::nullopt;
    }
    if (admin_ || KSIM_MUTANT("bridge_admin_open")) {
        return std::nullopt;
    }
    bool refuse = false;
    switch (ins) {
    case 0x20: case 0x24: case 0x26: case 0x28: case 0x2C:   // VERIFY, CHANGE, DISABLE, ENABLE, UNBLOCK PIN
        refuse = adm_key(p2);
        break;
    case 0xD6: case 0xDC:   // UPDATE BINARY, UPDATE RECORD
        refuse = selected_ == 0xAF20 || selected_ == 0xAF30;
        break;
    case 0xE0: case 0xE4: case 0xE6: case 0xE8: case 0xFE:   // CREATE, DELETE, TERMINATE DF/EF/CARD USAGE
        refuse = true;
        break;
    default:
        break;
    }
    if (refuse) {
        ++refused_;
        return kRefused;
    }
    return std::nullopt;
}

} // namespace ksim::uicc::bridge
