// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "entity/pdcp/pdcp.hpp"

#include "platform/mutation.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace ksim::entity {

namespace {

constexpr std::size_t kKeyLength = 16;   // the 128-bit algorithms (TS 33.501 Annex D)

} // namespace

Pdcp::Pdcp(TimerService& timers, PdcpConfig cfg, Sink to_lower, Sink to_upper)
    : timers_(timers), cfg_(cfg), to_lower_(std::move(to_lower)), to_upper_(std::move(to_upper)),
      alive_(std::make_shared<bool>(true)) {
    if (cfg_.srb) {
        cfg_.sn_tx = cfg_.sn_rx = pdcp::SnSize::len12;   // §6.2.2.1
        cfg_.sdap_header_tx = cfg_.sdap_header_rx = false;
    }
}

Pdcp::~Pdcp() {
    *alive_ = false;
    if (t_reord_) {
        timers_.stop_timer(*t_reord_);
    }
}

Result<void> Pdcp::set_keys(crypto::Nia nia, SecretBytes k_int, crypto::Nea nea, SecretBytes k_enc) {
    if ((nia != crypto::Nia::nia0 && k_int.size() != kKeyLength) ||
        (nea != crypto::Nea::nea0 && k_enc.size() != kKeyLength)) {
        return make_error(Errc::invalid_argument, 0, "PDCP: a 128-bit algorithm needs a 16-octet key");
    }
    auto i = crypto::NiaContext::make(nia, k_int);
    if (!i) {
        return i.error();
    }
    auto e = crypto::NeaContext::make(nea, k_enc);
    if (!e) {
        return e.error();
    }
    nia_ = std::move(*i);
    nea_ = std::move(*e);
    k_int_ = std::move(k_int);
    return {};
}

Result<crypto::Mac> Pdcp::mac_of(std::uint32_t count, std::uint8_t dir, ByteView header_and_data) const {
    if (!nia_) {
        return make_error(Errc::invalid_argument, 0, "PDCP: no integrity key");
    }
    if (KSIM_MUTANT("nia1_wrong_fresh") && cfg_.side == PdcpSide::ue && nia_->alg() == crypto::Nia::nia1 &&
        !header_and_data.empty()) {
        return crypto::uia2_f9(k_int_, count, bearer(), dir, header_and_data, header_and_data.size() * 8);
    }
    return nia_->mac({count, bearer(), dir}, {header_and_data});
}

void Pdcp::set_integrity(bool tx, bool rx) noexcept {
    int_tx_ = tx && nia_.has_value();
    int_rx_ = rx && nia_.has_value();
}

void Pdcp::set_ciphering(bool tx, bool rx) noexcept {
    ciph_tx_ = tx && nea_.has_value();
    ciph_rx_ = rx && nea_.has_value();
}

// ---- transmit (§5.2.1) ---------------------------------------------------------------

void Pdcp::write_sdu(Bytes sdu) {
    const std::uint32_t count = tx_next_;
    // One buffer, sized once: header, data, MAC-I; then ciphered in place (P2 Q8).
    const Bytes h = pdcp::data_header(cfg_.srb, cfg_.sn_tx, count);
    const std::size_t header = h.size();
    Bytes pdu;
    pdu.reserve(header + sdu.size() + pdcp::kMacILength);
    pdu.insert(pdu.end(), h.begin(), h.end());
    pdu.insert(pdu.end(), sdu.begin(), sdu.end());
    if (mac_present()) {
        crypto::Mac mac{};   // §6.3.4: zeros on an SRB without integrity
        if (int_tx_ && nia_) {
            auto m = mac_of(count, tx_dir(), pdu);
            if (!m) {
                ++stats_.discarded;
                return;
            }
            mac = *m;
        }
        pdu.insert(pdu.end(), mac.begin(), mac.end());
    }
    const std::size_t from = header + (cfg_.sdap_header_tx ? 1 : 0);
    if (ciph_tx_ && nea_ && from < pdu.size()) {
        (void)nea_->apply({count, bearer(), tx_dir()}, std::span<std::uint8_t>(pdu).subspan(from));
    }
    ++tx_next_;
    ++stats_.tx;
    to_lower_(std::move(pdu));
}

// ---- receive (§5.2.2) ------------------------------------------------------------------

void Pdcp::on_pdu(ByteView in) {
    auto h = pdcp::parse(cfg_.srb, cfg_.sn_rx, in);
    if (!h) {
        ++stats_.discarded;
        return;
    }
    if (!h->data) {
        ++stats_.discarded;   // control PDUs: the status report procedure is not in P1
        return;
    }
    const auto n = static_cast<unsigned>(cfg_.sn_rx);
    const std::int64_t window = std::int64_t{1} << (n - 1);
    const auto sn = static_cast<std::int64_t>(h->sn);
    const auto sn_deliv = static_cast<std::int64_t>(rx_deliv_ & pdcp::sn_mask(cfg_.sn_rx));
    std::int64_t hfn = rx_deliv_ >> n;
    if (sn < sn_deliv - window) {
        ++hfn;
    } else if (sn >= sn_deliv + window) {
        --hfn;
    }
    if (hfn < 0 || hfn >= (std::int64_t{1} << (32 - n))) {
        ++stats_.discarded;
        return;
    }
    const auto count = static_cast<std::uint32_t>((static_cast<std::uint64_t>(hfn) << n) | h->sn);

    // One copy of the PDU, deciphered in place; the MAC-I is checked over its header and
    // data where they lie (P2 Q8).
    Bytes pdu(in.begin(), in.end());
    const std::size_t hl = h->length;
    std::size_t end = pdu.size();
    const std::size_t from = hl + (cfg_.sdap_header_rx ? 1 : 0);
    if (ciph_rx_ && nea_ && from < end) {
        (void)nea_->apply({count, bearer(), rx_dir()}, std::span<std::uint8_t>(pdu).subspan(from));
    }
    if (mac_present()) {
        if (end - hl < pdcp::kMacILength) {
            ++stats_.discarded;
            return;
        }
        crypto::Mac mac_i{};
        std::copy(pdu.end() - 4, pdu.end(), mac_i.begin());
        end -= pdcp::kMacILength;
        const ByteView body(pdu.data(), end);
        if (int_rx_ && nia_) {
            auto x = mac_of(count, rx_dir(), body);
            if (!x || *x != mac_i) {
                ++stats_.integrity_failures;
                if (integrity_failure_) {
                    integrity_failure_(count);
                }
                return;
            }
        } else {
            last_unprotected_ = Unprotected{Bytes(body.begin(), body.end()), mac_i, count};
        }
    }
    pdu.resize(end);
    pdu.erase(pdu.begin(), pdu.begin() + static_cast<std::ptrdiff_t>(hl));
    Bytes data = std::move(pdu);

    if (count < rx_deliv_ || buffer_.count(count) != 0) {
        ++stats_.discarded;
        return;
    }
    if (!cfg_.out_of_order && count == rx_deliv_ && buffer_.empty()) {
        // In order with nothing waiting (P2 Q8): §5.2.2.1's delivery without the buffer.
        rx_deliv_ = count + 1;
        rx_next_ = std::max(rx_next_, rx_deliv_);
        ++stats_.delivered;
        to_upper_(std::move(data));
        if (t_reord_ && rx_deliv_ >= rx_reord_) {
            timers_.stop_timer(*t_reord_);
            t_reord_.reset();
        }
        return;
    }
    if (cfg_.out_of_order) {
        // Delivered now; still counted for RX_DELIV below (§5.2.2.1).
        ++stats_.delivered;
        to_upper_(data);
        buffer_.emplace(count, Bytes{});
    } else {
        buffer_.emplace(count, std::move(data));
    }
    if (count >= rx_next_) {
        rx_next_ = count + 1;
    }
    if (count == rx_deliv_) {
        deliver_from(rx_deliv_);
    }
    if (t_reord_ && rx_deliv_ >= rx_reord_) {
        timers_.stop_timer(*t_reord_);
        t_reord_.reset();
    }
    if (!t_reord_ && rx_deliv_ < rx_next_) {
        rx_reord_ = rx_next_;
        start_reordering();
    }
}

void Pdcp::deliver_from(std::uint32_t count) {
    std::vector<Bytes> out;
    auto it = buffer_.find(count);
    while (it != buffer_.end() && it->first == count) {
        if (!cfg_.out_of_order) {
            out.push_back(std::move(it->second));
        }
        it = buffer_.erase(it);
        ++count;
    }
    rx_deliv_ = count;
    for (auto& sdu : out) {
        ++stats_.delivered;
        to_upper_(std::move(sdu));
    }
}

void Pdcp::start_reordering() {
    if (!cfg_.t_reordering) {
        return;   // infinity
    }
    t_reord_ = timers_.start_timer(*cfg_.t_reordering, [this, alive = alive_] {
        if (*alive) {
            t_reord_.reset();
            on_reordering_expiry();
        }
    });
}

void Pdcp::on_reordering_expiry() {
    // §5.2.2.2: everything below RX_REORD, then the consecutive run from RX_REORD.
    std::vector<Bytes> out;
    while (!buffer_.empty() && buffer_.begin()->first < rx_reord_) {
        if (!cfg_.out_of_order) {
            out.push_back(std::move(buffer_.begin()->second));
        }
        buffer_.erase(buffer_.begin());
    }
    for (auto& sdu : out) {
        ++stats_.delivered;
        to_upper_(std::move(sdu));
    }
    rx_deliv_ = std::max(rx_deliv_, rx_reord_);
    deliver_from(rx_deliv_);
    if (rx_deliv_ < rx_next_) {
        rx_reord_ = rx_next_;
        start_reordering();
    }
}

Result<bool> Pdcp::verify_last_unprotected() const {
    if (!last_unprotected_ || !nia_) {
        return make_error(Errc::invalid_argument, 0, "PDCP: no unprotected PDU or no integrity key");
    }
    auto x = mac_of(last_unprotected_->count, rx_dir(), last_unprotected_->header_and_data);
    if (!x) {
        return x.error();
    }
    return *x == last_unprotected_->mac_i;
}

} // namespace ksim::entity
