// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Writing a real card over PC/SC (P2 Q1; sim-uicc.md §8 step 4, decision D3):
// a spare sysmoISIM becomes a sim-range card. The user runs both verbs, never
// an agent.
//
//   ksim-sim adm1 seal --out <file> --kek <file> [--stdin]
//       asks for the card's ADM1 without echo (or reads one line from stdin)
//       and writes it sealed under the KEK, 0600
//   ksim-sim burn --pcsc <reader> --imsi <IMSI> --master <file> --adm1 <file> --kek <file>
//                 [--template cards/usim-5g.yaml] [--dry-run]
//       1. ADF.USIM selected; the ADM1 retry counter read (VERIFY with no
//          data): below 3 tries left it stops, before any VERIFY;
//       2. VERIFY ADM1 once; a refusal stops it at once (no second try);
//       3. AF20 (EF.USIM_AUTH_KEY, the sysmoISIM layout) from K and OPc
//          derived from the range master in memory; then the EFs that make
//          the card this IMSI's (IMSI, AD, SMSP, FPLMN, LOCI, PSLOCI,
//          5GS3GPPLOCI) with the template's contents;
//       4. the IMSI and AD read back;
//       5. one AUTHENTICATE with SQN 0: the card proves K and OPc by a RES
//          or, as a used card answers, by an AUTS whose MAC-S checks (the
//          card's SQN array does not move on a synchronisation failure).
//       It prints the ATR, the tries left, PIN1's state, what it wrote and
//       K_FPR; never a key, the ADM1 or a PIN. --dry-run stops after step 1.
//
// The exchange is a function, so the same code burns a soft card in tests.

#pragma once

#include <functional>
#include <string>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::sim {

/// One APDU to the card and its response (data and SW1 SW2).
using Xfer = std::function<Result<Bytes>(ByteView capdu)>;

struct BurnOptions {
    std::string reader;
    std::string imsi;
    std::string master;
    std::string adm1;      // the sealed ADM1 file
    std::string kek;
    std::string tmpl = "cards/usim-5g.yaml";
    bool dry_run = false;
};

/// Exit status: 0 burned and checked, 1 failed, 3 refused before any VERIFY.
int burn(const BurnOptions& o, const Xfer& xfer);
/// The PC/SC entry: opens the reader, then burn().
int burn_pcsc(const BurnOptions& o);
int adm1_seal(const std::string& out, const std::string& kek, bool from_stdin);

} // namespace ksim::sim
