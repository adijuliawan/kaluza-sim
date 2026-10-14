// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// UICC APDUs (plan M12): the command and response APDUs of ETSI TS 102 221
// clause 10 (short form: Lc 1-255, a one-octet Le), the class byte of 10.1.1,
// the instruction codes of table 10.5 and TS 31.102 clause 7, the status words
// of 10.2.1, and the AUTHENTICATE data of TS 31.102 7.1.2.1. The parameters of
// the v1 commands are read for to_json(); everything is kept as received.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::uicc {

struct Command {
    std::uint8_t cla = 0x00;
    std::uint8_t ins = 0x00;
    std::uint8_t p1 = 0x00;
    std::uint8_t p2 = 0x00;
    Bytes data;                       // Lc octets
    std::optional<std::uint16_t> le;  // 1..256 ('00' is 256)
};

enum class ApduCase : std::uint8_t { one = 1, two, three, four };   // table 10.2
ApduCase apdu_case(const Command& c) noexcept;

/// A command APDU. Extended lengths (an Lc of '00' followed by more octets)
/// are not part of TS 102 221 and are refused as unsupported.
Result<Command> decode_command(ByteView in);
Result<Bytes> encode_command(const Command& c);

struct Response {
    Bytes data;
    std::uint8_t sw1 = 0x90;
    std::uint8_t sw2 = 0x00;
    std::uint16_t sw() const noexcept { return static_cast<std::uint16_t>((sw1 << 8) | sw2); }
};

Result<Response> decode_response(ByteView in);
Bytes encode_response(const Response& r);

// Tables 10.3 and 10.4a.
struct ClaInfo {
    enum class Coding : std::uint8_t { interindustry, uicc, gsm } coding;   // '0X'/'4X'/'6X', '8X'/'CX'/'EX', 'AX'
    std::uint8_t channel;            // 0-19
    std::uint8_t secure_messaging;   // b4-b3 (standard channels) or b6 (extended)
};
Result<ClaInfo> decode_cla(std::uint8_t cla);

/// The command's name (table 10.5; GET IDENTITY from TS 31.102 7.5) when the
/// class byte's coding fits it, else nullptr.
const char* command_name(std::uint8_t cla, std::uint8_t ins) noexcept;

/// The meaning of a status word (10.2.1), or nullptr.
const char* status_meaning(std::uint8_t sw1, std::uint8_t sw2) noexcept;

// ---- AUTHENTICATE (TS 31.102 7.1.2.1) --------------------------------------------------

enum class AuthContext : std::uint8_t { gsm = 0, umts = 1 };   // P2 b3-b1; 1 is the 3G/EPS/5G context

struct AuthChallenge {
    Bytes rand;
    Bytes autn;   // the 3G/EPS/5G context only
};
Result<AuthChallenge> decode_auth_challenge(ByteView data, AuthContext ctx);
Bytes encode_auth_challenge(const AuthChallenge& a, AuthContext ctx);

/// Where a field sits in the data it was read from.
struct Span {
    std::size_t at = 0;
    std::size_t len = 0;
    ByteView in(ByteView data) const noexcept { return data.subspan(at, len); }
};

/// The response data. CK, IK and Kc are not copied out: the codec layer holds
/// no key material (rule R3), so the caller copies them from the data straight
/// into SecretBytes by their spans.
struct AuthResult {
    enum class Kind : std::uint8_t { success, sync_failure, gsm } kind = Kind::success;
    Bytes res;          // RES, or SRES in the GSM context
    Span ck;
    Span ik;
    Span kc;            // len 0 when the card does not return it (service n°27)
    Bytes auts;
};
Result<AuthResult> decode_auth_result(ByteView data, AuthContext ctx);

/// The response data a card returns. The keys come as views the caller takes
/// from its SecretBytes at an allowlisted call site.
Bytes encode_auth_success(ByteView res, ByteView ck, ByteView ik, ByteView kc);
/// The response data with CK, IK and Kc zeroed: what a capture or a log of
/// the SIM interface may carry (plan M14 secret canary).
Bytes redact_keys(ByteView data, const AuthResult& r);
Bytes encode_auth_sync_failure(ByteView auts);
Bytes encode_auth_gsm(ByteView sres, ByteView kc);

/// One-line JSON for ksim-codec and the oracle: the command and, if given, the
/// response, with the v1 commands' parameters read. Key material (CK, IK, Kc)
/// appears by length only.
std::string to_json(const Command& c, const Response* r);

} // namespace ksim::uicc
