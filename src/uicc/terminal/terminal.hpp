// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The terminal: the ME's side of the card (P1 N3; TS 102 221 §7, TS 31.102 §5,
// §7.1; sim-uicc.md §4). It powers the card, finds the USIM in EF.DIR and
// selects it, reads and updates EFs, verifies PINs and runs AUTHENTICATE, with
// the T=0 procedures a phone runs: '61xx' answered with GET RESPONSE, '6Cxx'
// with the command again and the right Le. It knows nothing of NAS (rule R5):
// what to read and when is the UE's business.
//
// Everything is a coroutine on the actor's executor; CK and IK come back as
// SecretBytes, and the APDU buffer that carried them is wiped.

#pragma once

#include <cstdint>
#include <vector>

#include "codec/uicc/apdu.hpp"
#include "codec/uicc/fcp.hpp"
#include "platform/coro.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"
#include "uicc/transport/transport.hpp"

namespace ksim::uicc {

struct AuthOutcome {
    enum class Kind : std::uint8_t { success, sync_failure, mac_failure };
    Kind kind = Kind::mac_failure;
    SecretBytes res;
    SecretBytes ck;
    SecretBytes ik;
    Bytes auts;        // sync failure: SQN_MS ⊕ AK* ‖ MAC-S (14 octets)
};

/// A status word a card answered that the operation cannot go on with.
struct CardStatus {
    std::uint16_t sw = 0;
};

class Terminal {
public:
    explicit Terminal(IApduTransport& transport) : t_(transport) {}

    coro::Task<Result<Bytes>> power_on();
    /// One command with the T=0 procedures; the SW is the final one.
    coro::Task<Result<Response>> transmit(Command c);
    /// Reads EF.DIR and selects the first application with the USIM's AID prefix.
    coro::Task<Result<void>> select_usim();
    coro::Task<Result<void>> verify_pin(std::uint8_t ref, const SecretBytes& pin_block);

    /// Selects an EF by its path under the USIM ADF ({fid} or {df, fid}) and
    /// returns its FCP; then reads or writes it whole.
    coro::Task<Result<Fcp>> select_in_usim(std::vector<std::uint16_t> path);
    coro::Task<Result<Bytes>> read_ef(std::vector<std::uint16_t> path);
    coro::Task<Result<Bytes>> read_record(std::vector<std::uint16_t> path, std::uint8_t record);
    coro::Task<Result<void>> update_ef(std::vector<std::uint16_t> path, Bytes data);
    coro::Task<Result<void>> update_record(std::vector<std::uint16_t> path, std::uint8_t record, Bytes data);

    /// AUTHENTICATE in the 3G context (TS 31.102 §7.1.2.1).
    coro::Task<Result<AuthOutcome>> authenticate(Bytes rand, Bytes autn);

    const Bytes& usim_aid() const noexcept { return aid_; }
    std::uint64_t apdus() const noexcept { return apdus_; }
    /// The status word behind the last Errc::unsupported this terminal returned.
    std::uint16_t last_sw() const noexcept { return last_sw_; }

private:
    coro::Task<Result<Bytes>> call(Bytes capdu, bool reset);

    IApduTransport& t_;
    Bytes aid_;
    std::uint64_t apdus_ = 0;
    std::uint16_t last_sw_ = 0;
};

} // namespace ksim::uicc
