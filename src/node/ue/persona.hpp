// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Device personas (P1 N15; architecture §6): what a phone sent, as
// tools/persona_extract.py took it from a capture: its UE capability
// containers, the 5GMM capability, UE security capability, S1 UE network
// capability, UE's usage setting and requested NSSAI as IE values, and the
// IMEISV's TAC and SVN.
//
// The UE sends them intersected with what kaluza-sim implements (row
// KS-SCN-B1): the phone's UE-NR-Capability as it came; the UE security
// capability with only 5G-EA0-2 and 128-5G-IA1-2 (no ZUC, KS-SEC-G1) and no
// EPS algorithms (no S1 mode); the 5GMM capability in the phone's length with
// every feature bit cleared, since P1 implements none of them (S1 mode, HO
// attach, LPP, CIoT, LCS, V2X, NSSAA, ...: TS 24.501 §5.5.1.2.2 sets a bit
// only for what the UE supports); no S1 UE network capability; the usage
// setting and NSSAI kept on record only.

#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "codec/nas/ie/ie.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::node {

struct Persona {
    std::string name;
    std::string device;
    std::optional<std::string> tac;   // 8 digits
    std::optional<std::string> svn;   // 2 digits
    std::optional<Bytes> mm_capability;
    std::optional<Bytes> ue_security_capability;
    std::optional<Bytes> s1_ue_network_capability;
    std::optional<Bytes> ue_usage_setting;
    std::optional<Bytes> requested_nssai;
    std::vector<std::pair<std::string, Bytes>> containers;   // RAT type, UPER as the phone sent it

    /// The UE-NR-Capability container, if the persona has one.
    std::optional<Bytes> nr_capability() const;
    /// What the UE sends (see above).
    nas::ie::UeSecurityCapability security() const;
    std::optional<Bytes> mm_capability_sent() const;
};

/// A persona file. Its NR capability must decode (our Rel-19 RRC codec);
/// `why` says what is wrong otherwise.
Result<Persona> load_persona(const std::string& file, std::string& why);

/// The IMEISV of a UE: the persona's TAC and SVN when it has them, else
/// `tac` and SVN 01, around a serial number from the IMSI's last six digits.
std::string imeisv_for(const Persona* p, const std::string& tac, const std::string& imsi);

} // namespace ksim::node
