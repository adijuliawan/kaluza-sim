// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-sim's card verbs (P1 N14; sim-uicc.md §5, §7): serve a soft card on a
// virtual reader, and check, export or import card images.

#pragma once

#include <memory>
#include <string>

#include "uicc/os/card.hpp"

namespace ksim::sim {

struct CardSource {
    std::string tmpl = "cards/usim-5g.yaml";
    std::string imsi = "001010000300001";
    std::string sealed_dir;   // with kek: the card's sealed secrets (ksim-sim range derive)
    std::string kek;
    bool test_keys = false;   // TS 35.208 test set 1 and the test PINs: a lab or CI card, never a real one
    std::string personality;  // e.g. sysmoISIM-SJA5: that card's ATR (sim-uicc.md §3)
};

/// The personalised card, or null with `why`.
std::unique_ptr<uicc::os::Card> make_card(const CardSource& src, std::string& why);

struct ServeOptions {
    CardSource card;
    std::string vpcd = "127.0.0.1:35963";
    std::string trace_udp;    // host:port for GSMTAP (4729), empty: none
    std::string trace_pcap;   // a pcapng file (0600), empty: none
    bool no_redact = false;   // test keys only
    unsigned seconds = 0;     // 0: until SIGINT or SIGTERM
};

int serve(const ServeOptions& o);

/// The card bridge (P2 Q1; lab.md §7): a card in a PC/SC reader lent to one
/// remote terminal over the vpcd framing. Only APDUs cross; unless `admin`,
/// the administrator's commands are refused here (uicc/transport/bridge).
struct BridgeOptions {
    std::string reader;                       // --pcsc: a reader name, "#n" or a unique part
    std::string listen = "127.0.0.1:35970";   // one address
    std::string allow;                        // the one peer address taken
    bool admin = false;
    std::string trace_udp;
    std::string trace_pcap;
    unsigned seconds = 0;
};
int serve_bridge(const BridgeOptions& o);
/// Checks an image (TS 102 221 and TS 31.102: ARR references, FIDs and SFIs,
/// record sizes, EF.DIR, the files each UST service brings, key files never
/// readable). `access`: one line per EF with its READ access in the state
/// after a reset. Exit 0 valid, 1 not.
int validate(const std::string& image, bool access);
/// A pySim-shell script that writes the card's contents: no key file
/// (os::key_fid), no access rule, no PIN, nothing the ARR keeps from a reader.
int export_script(const CardSource& src);
/// A template's EF contents replaced by those in a pySim-shell `fsdump`
/// (without --json), written as a new image; key files and NAS state are kept
/// from the template.
int import_fsdump(const std::string& fsdump, const std::string& tmpl, const std::string& out);

} // namespace ksim::sim
