// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The APDU trace (P1 N14; sim-uicc.md §6): each exchange becomes a GSMTAP
// SIM payload (type 4, sub-type APDU, or ATR for the reset) in the form
// Wireshark's gsm_sim and pySim-trace read: CLA INS P1 P2 P3, the command
// data, the response data, then SW1 SW2. Records are APDUs, not T=0 TPDUs: an
// answer 61xx (or 6Cxx) is held and merged with the GET RESPONSE (or the
// command sent again) that follows on its channel, so the record holds the
// command and its final answer. pySim-trace takes each GSMTAP record as a
// whole APDU and would otherwise see a SELECT ending in 61xx as failed.
//
// Redaction is on unless asked off (a test-only switch): CK, IK and Kc in
// AUTHENTICATE answers (also when they come in the GET RESPONSE after 61xx),
// the data of the PIN commands, and anything read from or written to a key
// file (os::key_fid: EF.KEYS, EF.KEYSPS, 4F03, 4F04, 4F05, AF20, AF30), by FID
// or by SFI in the ADF and DF.5GS. A redacted octet is 0x00 (0xFF for PINs); lengths stay, so the
// trace still decodes.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "platform/buf.hpp"
#include "uicc/transport/transport.hpp"

namespace ksim::uicc::trace {

inline constexpr std::uint8_t kSubApdu = 0x00;   // GSMTAP_SIM_APDU
inline constexpr std::uint8_t kSubAtr = 0x01;    // GSMTAP_SIM_ATR

/// The TPDU form of one exchange: the command in its T=0 shape (P3 added to
/// a case 1, Le dropped from a case 4) followed by the response.
Bytes tpdu(ByteView command, ByteView response);

/// Merges the T=0 exchanges into APDUs, and follows the selected DF and EF
/// per channel to know what to mask.
class Redactor {
public:
    explicit Redactor(bool on = true) : on_(on) {}
    /// The records this exchange completes: none while it waits for its GET
    /// RESPONSE, one, or two when a held exchange was not followed up.
    std::vector<Bytes> apply(ByteView command, ByteView response);
    /// What is still held (at a reset or the end).
    std::vector<Bytes> flush();
    void reset() noexcept;
    bool on() const noexcept { return on_; }

private:
    struct Lchan {
        std::uint16_t df = 0x3F00;
        std::uint16_t ef = 0;
        bool auth_pending = false;   // an AUTHENTICATE's answer still to come in a GET RESPONSE
        Bytes held_cmd;              // an exchange answered 61xx or 6Cxx
        Bytes held_rsp;
    };
    Bytes one(Lchan& ch, ByteView command, ByteView response);
    bool secret_target(const Lchan& ch, ByteView c) const;

    bool on_;
    std::array<Lchan, 4> ch_{};
};

/// A decorator: what goes through `inner` is also handed to `sink` as
/// (sub-type, payload). The selection is followed even while no sink is set,
/// so a trace switched on mid-session still masks what it must.
class TracingTransport final : public IApduTransport {
public:
    using Sink = std::function<void(std::uint8_t sub_type, Bytes payload)>;
    TracingTransport(IApduTransport& inner, Sink sink, bool redact = true);

    void reset(Done done) override;
    void transmit(Bytes capdu, Done done) override;
    /// On (a sink) or off (empty).
    void set_sink(Sink sink) { *sink_ = std::move(sink); }
    bool tracing() const noexcept { return static_cast<bool>(*sink_); }
    std::size_t traced() const noexcept { return *count_; }

private:
    IApduTransport& inner_;
    std::shared_ptr<Sink> sink_;
    std::shared_ptr<Redactor> redactor_;
    std::shared_ptr<std::size_t> count_;
};

} // namespace ksim::uicc::trace
