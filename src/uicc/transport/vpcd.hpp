// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The vpcd framing (P1 N14; sim-uicc.md §5): vsmartcard's virtual reader
// protocol over a byte stream. Each message is a 2-octet big-endian length and
// the payload; a 1-octet payload from the reader is a control code (0 power
// off, 1 power on, 2 reset, 4 send the ATR), any other is a command APDU. The
// card answers the ATR request with the ATR and each APDU with its response;
// power and reset get no answer.
//
// Two roles on the same framing:
//   VpcdCard       the card side: our soft card behind pcscd's vpcd driver, so
//                  a PC/SC client (pySim-shell) sees it as a reader with a card.
//   VpcdTransport  the terminal side: an IApduTransport over a stream that a
//                  card connected (the card bridge, lab.md §7).
// The socket itself is net's (TCP); nothing here opens one.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>

#include "platform/buf.hpp"
#include "platform/executor.hpp"
#include "platform/transport.hpp"
#include "uicc/os/card.hpp"
#include "uicc/transport/transport.hpp"

namespace ksim::uicc::vpcd {

inline constexpr std::uint8_t kPowerOff = 0x00;
inline constexpr std::uint8_t kPowerOn = 0x01;
inline constexpr std::uint8_t kReset = 0x02;
inline constexpr std::uint8_t kAtr = 0x04;
/// pcscd's vpcd listens on 35963 (reader 0) and up (reader.conf's CHANNELID 0x8C7B).
inline constexpr std::uint16_t kPort = 35963;

/// A message as it goes on the stream.
Bytes frame(ByteView payload);

/// Cuts a byte stream into messages; `on_message` sees each payload whole.
class Deframer {
public:
    explicit Deframer(std::function<void(ByteView)> on_message) : on_message_(std::move(on_message)) {}
    void feed(ByteView data);
    std::size_t buffered() const noexcept { return buf_.size(); }

private:
    std::function<void(ByteView)> on_message_;
    Bytes buf_;
};

/// The card side. `tap` sees each exchange (command, response) once it is
/// answered, for a trace; the ATR after a reset or power-on goes as an empty
/// command. pcscd's driver also asks for the ATR to see that the card is still
/// there; those polls reset nothing and are not tapped.
class VpcdCard {
public:
    using Tap = std::function<void(ByteView command, ByteView response)>;

    VpcdCard(IStream& stream, os::Card& card, Tap tap = {});
    ~VpcdCard();
    VpcdCard(const VpcdCard&) = delete;
    VpcdCard& operator=(const VpcdCard&) = delete;

    bool powered() const noexcept { return powered_; }
    std::size_t apdus() const noexcept { return apdus_; }
    std::size_t resets() const noexcept { return resets_; }

private:
    void on_message(ByteView m);

    IStream& stream_;
    os::Card& card_;
    Tap tap_;
    Deframer in_;
    bool powered_ = false;
    bool atr_due_ = true;   // a reset or power-on whose ATR is not tapped yet
    std::size_t apdus_ = 0;
    std::size_t resets_ = 0;
};

/// The terminal side: one exchange at a time, in order; a closed stream
/// fails what waits with Errc::closed.
class VpcdTransport final : public IApduTransport {
public:
    VpcdTransport(Executor& exec, std::unique_ptr<IStream> stream);
    ~VpcdTransport() override;
    VpcdTransport(const VpcdTransport&) = delete;
    VpcdTransport& operator=(const VpcdTransport&) = delete;

    void reset(Done done) override;
    void transmit(Bytes capdu, Done done) override;
    bool open() const noexcept { return stream_ && stream_->open(); }

private:
    struct Pending {
        Bytes message;     // empty: a reset (reset, then the ATR request)
        Done done;
        bool sent = false;
    };
    void pump();
    void on_message(ByteView m);
    void fail_all();

    Executor& exec_;
    std::unique_ptr<IStream> stream_;
    Deframer in_;
    std::deque<Pending> queue_;
    std::shared_ptr<bool> alive_;
};

} // namespace ksim::uicc::vpcd
