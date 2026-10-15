// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The PC/SC backend (P2 Q1; sim-uicc.md §5, KS-UICC-009): a card in a reader
// that pcscd serves, a real sysmoISIM in the OmniKey or the soft card behind
// pcscd's vpcd driver. K stays in the card: only APDUs cross.
//
//   PcscCard       a blocking handle (SCardConnect, SCardTransmit,
//                  SCardReconnect) for the tools that run on one thread:
//                  the card bridge and the burn (ksim-sim).
//   PcscTransport  the terminal's asynchronous transport over a PcscCard: each
//                  call runs on the blocking pool, one at a time and in order,
//                  and its answer is posted back to the actor's executor.
//
// pcsc-lite is linked only into what uses this file (ksim-sim, and ksim
// where KSIM_PCSC is on); the lab VM's ksim reaches real cards through the
// card bridge instead (lab.md §7).

#pragma once

#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "platform/blocking.hpp"
#include "platform/executor.hpp"
#include "platform/result.hpp"
#include "uicc/transport/transport.hpp"

namespace ksim::uicc::pcsc {

/// The readers pcscd lists now (blocks).
Result<std::vector<std::string>> readers();

/// A reader by its exact name, by "#<n>" (the n-th listed, from 0), or the
/// one name that contains `pattern`; Errc::not_found or invalid_argument
/// (several match) otherwise.
Result<std::string> pick(const std::vector<std::string>& names, std::string_view pattern);

class PcscCard {
public:
    /// Connects exclusively, T=0 or T=1 as the card offers.
    static Result<std::unique_ptr<PcscCard>> open(const std::string& reader);
    ~PcscCard();
    PcscCard(const PcscCard&) = delete;
    PcscCard& operator=(const PcscCard&) = delete;

    const std::string& reader() const noexcept { return reader_; }
    /// The ATR of the current power-up.
    Result<Bytes> atr();
    /// A warm reset; the new ATR.
    Result<Bytes> reset();
    /// One command APDU; the response with SW1 SW2. The caller's buffers keep
    /// whatever key material an APDU carries; this one wipes its own.
    Result<Bytes> transmit(ByteView capdu);

private:
    struct Handle;
    PcscCard(std::string reader, std::unique_ptr<Handle> h);

    std::string reader_;
    std::unique_ptr<Handle> h_;
};

class PcscTransport final : public IApduTransport {
public:
    /// `reader` is opened on the pool at the first reset.
    PcscTransport(Executor& exec, BlockingPool& pool, std::string reader);
    ~PcscTransport() override;
    PcscTransport(const PcscTransport&) = delete;
    PcscTransport& operator=(const PcscTransport&) = delete;

    void reset(Done done) override;
    void transmit(Bytes capdu, Done done) override;

private:
    struct Job {
        bool reset = false;
        Bytes capdu;
        Done done;
    };
    struct Shared;
    void pump();

    Executor& exec_;
    BlockingPool& pool_;
    std::shared_ptr<Shared> shared_;
    std::deque<Job> queue_;
    bool busy_ = false;
};

} // namespace ksim::uicc::pcsc
