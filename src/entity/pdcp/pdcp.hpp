// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A PDCP entity (P1 N6; TS 38.323 j10 §5): one per radio bearer, at the UE or
// at the gNB. Transmit: COUNT = TX_NEXT, integrity over header and data,
// ciphering of data and MAC-I (never the SDAP header), SN = TX_NEXT mod 2^n.
// Receive: RCVD_COUNT from RX_DELIV and the window (§5.2.2.1), deciphering,
// integrity verification (a failure is indicated upward and the PDU dropped),
// duplicate and stale discard, in-order delivery with t-Reordering (§5.2.2.2),
// or out-of-order delivery when configured.
//
// Security is configured by RRC per direction, as the AS security mode
// procedure needs (TS 38.331 §5.3.4): integrity on both directions at once,
// ciphering on receive at once and on transmit after the SecurityModeComplete.
// A PDU received before integrity is on is kept, so RRC can have the
// SecurityModeCommand's own MAC-I checked once it knows the keys (§5.9 NOTE 1).
//
// Passive (rule R4): time from the injected TimerService, I/O through the
// injected sinks. Not built: ROHC, EHC, UDC, discard timers, duplication,
// re-establishment and the status report procedure (P3, with handover).

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>

#include "codec/pdcp/pdcp.hpp"
#include "crypto/as_security.hpp"
#include "crypto/nea.hpp"
#include "platform/buf.hpp"
#include "platform/executor.hpp"
#include "platform/secret.hpp"

namespace ksim::entity {

enum class PdcpSide : std::uint8_t { ue, gnb };   // the UE transmits uplink (DIRECTION 0)

struct PdcpConfig {
    bool srb = true;
    std::uint8_t rb_id = 1;                       // SRB 0..3 or DRB 1..32; BEARER = rb_id - 1
    PdcpSide side = PdcpSide::ue;
    pdcp::SnSize sn_tx = pdcp::SnSize::len12;     // SRBs: 12 bits
    pdcp::SnSize sn_rx = pdcp::SnSize::len12;
    bool drb_integrity = false;                   // integrityProtection enabled (a DRB's MAC-I present)
    bool sdap_header_tx = false;                  // the SDAP header is the SDU's first octet, never ciphered
    bool sdap_header_rx = false;
    bool out_of_order = false;
    std::optional<Millis> t_reordering;           // absent: infinity (TS 38.331 PDCP-Config)
};

struct PdcpStats {
    std::uint64_t tx = 0;
    std::uint64_t delivered = 0;
    std::uint64_t integrity_failures = 0;
    std::uint64_t discarded = 0;      // duplicates, stale, malformed
};

class Pdcp {
public:
    using Sink = std::function<void(Bytes)>;

    Pdcp(TimerService& timers, PdcpConfig cfg, Sink to_lower, Sink to_upper);
    ~Pdcp();
    Pdcp(const Pdcp&) = delete;
    Pdcp& operator=(const Pdcp&) = delete;

    /// Called with the RCVD_COUNT of a PDU whose integrity check failed (§5.2.2.1).
    void on_integrity_failure(std::function<void(std::uint32_t)> f) { integrity_failure_ = std::move(f); }

    /// The algorithms and keys (K_RRCint/K_RRCenc or K_UPint/K_UPenc).
    Result<void> set_keys(crypto::Nia nia, SecretBytes k_int, crypto::Nea nea, SecretBytes k_enc);
    void set_integrity(bool tx, bool rx) noexcept;
    void set_ciphering(bool tx, bool rx) noexcept;
    bool integrity_rx() const noexcept { return int_rx_; }

    void write_sdu(Bytes sdu);
    void on_pdu(ByteView pdu);

    /// Checks the MAC-I of the last PDU delivered while receive integrity was
    /// off, with the keys now set (the SecurityModeCommand, §5.9 NOTE 1).
    Result<bool> verify_last_unprotected() const;

    /// Sets the state variables, as an SN STATUS TRANSFER does at handover
    /// (TS 38.323 §5.1.2; P3) and as the known-answer tests do.
    void set_state(std::uint32_t tx_next, std::uint32_t rx_next, std::uint32_t rx_deliv) noexcept {
        tx_next_ = tx_next;
        rx_next_ = rx_next;
        rx_deliv_ = rx_deliv;
    }

    std::uint32_t tx_next() const noexcept { return tx_next_; }
    std::uint32_t rx_next() const noexcept { return rx_next_; }
    std::uint32_t rx_deliv() const noexcept { return rx_deliv_; }
    bool t_reordering_running() const noexcept { return t_reord_.has_value(); }
    const PdcpStats& stats() const noexcept { return stats_; }
    const PdcpConfig& config() const noexcept { return cfg_; }

private:
    std::uint8_t tx_dir() const noexcept { return cfg_.side == PdcpSide::ue ? 0 : 1; }
    std::uint8_t rx_dir() const noexcept { return cfg_.side == PdcpSide::ue ? 1 : 0; }
    std::uint8_t bearer() const noexcept { return static_cast<std::uint8_t>((cfg_.rb_id - 1) & 0x1F); }
    bool mac_present() const noexcept { return cfg_.srb || cfg_.drb_integrity; }
    /// The MAC-I over header and data with the integrity context (mutant nia1_wrong_fresh: the
    /// UE side's 128-NIA1 with FRESH = BEARER unshifted, row ksim-p2.as-nea1-nia1).
    Result<crypto::Mac> mac_of(std::uint32_t count, std::uint8_t dir, ByteView header_and_data) const;
    void deliver_from(std::uint32_t count);
    void start_reordering();
    void on_reordering_expiry();

    TimerService& timers_;
    PdcpConfig cfg_;
    Sink to_lower_;
    Sink to_upper_;
    std::function<void(std::uint32_t)> integrity_failure_;
    std::shared_ptr<bool> alive_;

    // P2 Q8, the fast path: each algorithm with its key set once (crypto/as_security.hpp).
    mutable std::optional<crypto::NiaContext> nia_;
    std::optional<crypto::NeaContext> nea_;
    SecretBytes k_int_;   // for the mutant only
    bool int_tx_ = false;
    bool int_rx_ = false;
    bool ciph_tx_ = false;
    bool ciph_rx_ = false;

    std::uint32_t tx_next_ = 0;
    std::uint32_t rx_next_ = 0;
    std::uint32_t rx_deliv_ = 0;
    std::uint32_t rx_reord_ = 0;
    std::map<std::uint32_t, Bytes> buffer_;   // received, not yet delivered, by COUNT
    std::optional<TimerId> t_reord_;

    struct Unprotected {
        Bytes header_and_data;
        crypto::Mac mac_i{};
        std::uint32_t count = 0;
    };
    std::optional<Unprotected> last_unprotected_;
    PdcpStats stats_;
};

} // namespace ksim::entity
