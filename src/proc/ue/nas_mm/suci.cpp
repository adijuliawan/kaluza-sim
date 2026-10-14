// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/nas_mm/suci.hpp"

#include "platform/mutation.hpp"

namespace ksim::proc::ue {

namespace {

bool bcd_digit(std::uint8_t n, std::string& out) {
    if (n > 9) {
        return false;
    }
    out += static_cast<char>('0' + n);
    return true;
}

} // namespace

Result<Subscription> read_subscription(ByteView ef_imsi, ByteView ef_ad) {
    if (ef_imsi.size() < 2 || ef_imsi[0] < 1 || ef_imsi[0] > 8 || ef_imsi.size() < 1U + ef_imsi[0]) {
        return make_error(Errc::malformed, 0, "EF.IMSI: bad length");
    }
    if ((ef_imsi[1] & 0x07) != 0x01) {
        return make_error(Errc::malformed, 1, "EF.IMSI: not an IMSI");
    }
    const bool odd = (ef_imsi[1] & 0x08) != 0;
    std::string digits;
    if (!bcd_digit(static_cast<std::uint8_t>(ef_imsi[1] >> 4), digits)) {
        return make_error(Errc::malformed, 1, "EF.IMSI: a digit outside 0-9");
    }
    for (std::size_t i = 2; i <= ef_imsi[0]; ++i) {
        if (!bcd_digit(static_cast<std::uint8_t>(ef_imsi[i] & 0x0F), digits)) {
            return make_error(Errc::malformed, static_cast<std::uint32_t>(i), "EF.IMSI: a digit outside 0-9");
        }
        const auto hi = static_cast<std::uint8_t>(ef_imsi[i] >> 4);
        if (i == ef_imsi[0] && !odd) {
            if (hi != 0x0F) {
                return make_error(Errc::malformed, static_cast<std::uint32_t>(i), "EF.IMSI: even length without filler");
            }
            break;
        }
        if (!bcd_digit(hi, digits)) {
            return make_error(Errc::malformed, static_cast<std::uint32_t>(i), "EF.IMSI: a digit outside 0-9");
        }
    }
    if (digits.size() < 6 || digits.size() > 15) {
        return make_error(Errc::malformed, 0, "EF.IMSI: not 6 to 15 digits");
    }
    std::size_t mnc_len = 2;
    if (ef_ad.size() >= 4) {
        const auto n = static_cast<std::size_t>(ef_ad[3] & 0x0F);
        if (n == 2 || n == 3) {
            mnc_len = n;
        }
    }
    Subscription s;
    s.imsi = digits;
    s.home.mcc = digits.substr(0, 3);
    s.home.mnc = digits.substr(3, mnc_len);
    s.msin = digits.substr(3 + mnc_len);
    return s;
}

std::string read_routing_indicator(ByteView ef) {
    std::string out;
    for (std::size_t i = 0; i < ef.size() && i < 2; ++i) {
        for (const auto n : {static_cast<std::uint8_t>(ef[i] & 0x0F), static_cast<std::uint8_t>(ef[i] >> 4)}) {
            if (n > 9) {
                return out.empty() ? "0" : out;
            }
            out += static_cast<char>('0' + n);
        }
    }
    return out.empty() ? "0" : out;
}

nas::ie::MobileIdentity null_suci(const Subscription& s, std::string_view routing_indicator) {
    if (KSIM_MUTANT("null_suci_full_imsi")) {
        return nas::ie::MobileIdentity::null_suci(s.home, s.imsi, routing_indicator);
    }
    return nas::ie::MobileIdentity::null_suci(s.home, s.msin, routing_indicator);
}

} // namespace ksim::proc::ue
