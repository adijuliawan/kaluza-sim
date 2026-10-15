// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's 5G NAS security context (P1 N4; TS 24.501 j80 §4.4; TS 33.501 j70
// §6.4): ngKSI and K_AMF, the NAS keys of the selected algorithms, and the
// uplink and downlink NAS COUNTs. It protects what the UE sends and checks
// what it receives:
//
// - COUNT (§4.4.3.1): 24 bits, a 16-bit overflow counter over the 8-bit
//   sequence number; 32 bits with leading zeros as an algorithm input. The
//   uplink COUNT is the one the next message uses; the downlink COUNT is the
//   largest one that verified. A received message's COUNT is estimated from
//   its sequence number, always above the stored one (no reordering on NAS),
//   so a replayed message's MAC fails and it is discarded (§4.4.3.2).
// - Integrity (§4.4.3.3) covers octet 7 onwards (the sequence number and the
//   NAS message, ciphered or not); ciphering (§4.4.3.4) the message from octet
//   8. BEARER is the NAS connection identifier, 0 for 3GPP access (TS 33.501
//   §6.4.3.1); DIRECTION 0 uplink, 1 downlink.
// - Before secure exchange is established only the messages of §4.4.4.2 are
//   processed unprotected; afterwards an unprotected or unverified message is
//   discarded.
// - Initial NAS messages (§4.4.6) carry only their cleartext IEs in the clear;
//   the whole message goes in a NAS message container.
//
// The context holds keys as SecretBytes; nothing here prints them.

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "codec/nas/ie/ie.hpp"
#include "codec/nas/nas.hpp"
#include "crypto/nea.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::proc::ue {

/// Security header types (§9.3).
enum class Sht : std::uint8_t {
    plain = 0,
    integrity = 1,
    integrity_ciphered = 2,
    integrity_new = 3,             // with a new 5G NAS security context (the SECURITY MODE COMMAND)
    integrity_ciphered_new = 4,    // the SECURITY MODE COMPLETE
};

enum class Verdict : std::uint8_t {
    ok,
    discard_unprotected,   // plain, but secure exchange is established (or the message is not in §4.4.4.2)
    discard_mac,           // the MAC does not verify (a replay included)
    discard_no_context,    // protected, but there is no context to check it with
    discard_malformed,
};

const char* verdict_name(Verdict v) noexcept;

/// A downlink NAS message after the checks.
struct Inbound {
    Verdict verdict = Verdict::discard_malformed;
    Sht sht = Sht::plain;
    Bytes plain;              // the NAS message, deciphered
    std::uint32_t count = 0;  // the estimated COUNT it verified with
};

/// Which end of the NAS link a context protects for: the UE sends uplink
/// (DIRECTION 0) and receives downlink; the network (the scripted core) the
/// reverse. The same keys and COUNT rules serve both.
enum class NasRole : std::uint8_t { ue, network };

class NasSecurityContext {
public:
    /// A context for K_AMF and the algorithms of a SECURITY MODE COMMAND, with
    /// both COUNTs at zero (a new K_AMF; §4.4.3.1). 5G-EA3 and 5G-IA3 are a
    /// declared gap (KS-SEC-G1); 5G-IA0 is refused outside emergency (TS 33.501
    /// §5.5.2), which P1 does not have.
    static Result<NasSecurityContext> derive(nas::ie::NgKsi ngksi, SecretBytes kamf, std::uint8_t ea, std::uint8_t ia,
                                             NasRole role = NasRole::ue);

    const nas::ie::NgKsi& ngksi() const noexcept { return ngksi_; }
    const SecretBytes& kamf() const noexcept { return kamf_; }
    std::uint8_t ea() const noexcept { return ea_; }
    std::uint8_t ia() const noexcept { return ia_; }
    NasRole role() const noexcept { return role_; }
    /// The COUNT of the next message this end sends (for the UE, the uplink COUNT).
    std::uint32_t ul_count() const noexcept { return ul_count_; }
    /// The largest COUNT this end received that verified (for the UE, the
    /// downlink COUNT); nullopt before the first.
    std::optional<std::uint32_t> dl_count() const noexcept { return dl_count_; }
    /// Restores the COUNTs of a stored context (EF.5GS3GPPNSC; Annex C).
    void restore_counts(std::uint32_t ul, std::optional<std::uint32_t> dl) noexcept;

    /// Protects an encoded plain message and advances the uplink COUNT. A
    /// ciphered header type ciphers it with the context's NEA (5G-EA0 leaves
    /// it as it is).
    Result<Bytes> protect(ByteView plain, Sht sht);
    /// Checks a security protected downlink message: the estimated COUNT, the
    /// MAC, then deciphering. A message that verifies advances the stored
    /// downlink COUNT; one that does not changes nothing.
    Inbound unprotect(ByteView wire);
    /// §4.4.6, TS 33.501 6.4.6: the value part of an initial message's NAS
    /// message container, ciphered with this context's NEA and the COUNT of the
    /// message that carries it, uplink (direction 0); a stream cipher, so the
    /// same call deciphers it at the network. 5G-EA0 leaves it as it is.
    Result<Bytes> container_cipher(ByteView value, std::uint32_t count) const;
    /// The MAC a message would carry, for a candidate context checking a
    /// SECURITY MODE COMMAND before taking it into use.
    Result<crypto::Mac> mac_of(std::uint32_t count, std::uint8_t direction, ByteView seq_and_message) const;

private:
    NasSecurityContext() = default;
    std::uint32_t estimate(std::uint8_t sqn) const noexcept;

    nas::ie::NgKsi ngksi_;
    SecretBytes kamf_;
    SecretBytes knas_int_;
    SecretBytes knas_enc_;
    std::uint8_t ea_ = 0;
    std::uint8_t ia_ = 0;
    NasRole role_ = NasRole::ue;
    std::uint32_t ul_count_ = 0;   // the sending direction's next COUNT
    std::optional<std::uint32_t> dl_count_;
};

/// §4.4.4.2: whether the UE processes a plain (unprotected) downlink 5GMM
/// message. Before secure exchange: IDENTITY REQUEST for the SUCI,
/// AUTHENTICATION REQUEST, RESULT and REJECT, REGISTRATION REJECT unless
/// #76/#78/#81/#82, DEREGISTRATION ACCEPT unless switch-off, SERVICE REJECT
/// unless #76/#78. After it: none.
bool processed_unprotected(const nas::Message& m, bool secure_exchange);

/// §4.4.6: the cleartext version of an initial NAS message (REGISTRATION
/// REQUEST, DEREGISTRATION REQUEST or SERVICE REQUEST), and whether the full
/// message has IEs beyond them (so it must travel in a NAS message container).
struct InitialSplit {
    nas::Message cleartext;
    bool has_non_cleartext = false;
};
Result<InitialSplit> split_initial(const nas::Message& m);

} // namespace ksim::proc::ue
