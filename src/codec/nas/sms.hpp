// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// SMS over NAS (plan M11): the CP layer and RP layer of TS 24.011 (7.2, 7.3,
// 8.1, 8.2) and the TPDUs of TS 23.040 (9.2), with the GSM 7-bit default
// alphabet of TS 23.038 (6.1.2.1 packing, 6.2.1 alphabet and extension table)
// and UCS2. Fields are kept as received, so encode(decode(x)) == x.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::sms {

// ---- CP layer (TS 24.011 7.2) ------------------------------------------------------

enum class CpType : std::uint8_t { data = 0x01, ack = 0x04, error = 0x10 };

struct Cp {
    std::uint8_t ti = 0;        // transaction identifier, bits 8-5 of octet 1 (TI flag in bit 8)
    CpType type = CpType::data;
    Bytes user_data;            // CP-DATA: the RPDU
    std::uint8_t cause = 0;     // CP-ERROR: CP-Cause
};

Result<Cp> decode_cp(ByteView in);
Bytes encode_cp(const Cp& cp);

// ---- RP layer (TS 24.011 7.3) ------------------------------------------------------

enum class RpMti : std::uint8_t {
    data_ms_n = 0, data_n_ms = 1, ack_ms_n = 2, ack_n_ms = 3, error_ms_n = 4, error_n_ms = 5, smma_ms_n = 6,
};

struct Rp {
    RpMti mti = RpMti::data_ms_n;
    std::uint8_t mr = 0;                 // RP-Message Reference
    Bytes originator;                    // RP-DATA: RP-Originator Address contents (may be empty)
    Bytes destination;                   // RP-DATA: RP-Destination Address contents (may be empty)
    Bytes cause;                         // RP-ERROR: RP-Cause contents
    std::optional<Bytes> user_data;      // RP-DATA (always), RP-ACK and RP-ERROR (optional): the TPDU
};

Result<Rp> decode_rp(ByteView in);
Bytes encode_rp(const Rp& rp);

// ---- TPDU (TS 23.040 9.2) ----------------------------------------------------------

/// Which way a TPDU travels, which TP-MTI alone does not say (9.2.3.1).
enum class TpDir : std::uint8_t { ms_to_sc, sc_to_ms };

enum class TpduType : std::uint8_t { deliver, deliver_report, submit, submit_report, status_report, command };

struct Address {             // TS 23.040 9.1.2.5
    std::uint8_t length = 0; // in semi-octets (useful digits)
    std::uint8_t toa = 0x91; // type of address
    Bytes digits;            // BCD, as received
};

struct Tpdu {
    TpduType type = TpduType::submit;
    std::uint8_t first = 0;               // the first octet, flags as received
    std::uint8_t mr = 0;                  // TP-MR (SUBMIT, STATUS-REPORT, COMMAND)
    Address address;                      // TP-DA, TP-OA or TP-RA
    std::uint8_t pid = 0;                 // TP-PID
    std::uint8_t dcs = 0;                 // TP-DCS
    Bytes scts;                           // TP-SCTS, 7 octets
    Bytes dt;                             // TP-DT (STATUS-REPORT), 7 octets
    std::uint8_t st = 0;                  // TP-ST (STATUS-REPORT)
    Bytes vp;                             // TP-VP: 0, 1 or 7 octets per TP-VPF
    std::optional<std::uint8_t> fcs;      // TP-FCS (a report for RP-ERROR)
    std::optional<std::uint8_t> pi;       // TP-PI octet 1 (reports, STATUS-REPORT)
    Bytes pi_more;                        // TP-PI octets 2..n (each announced by bit 8 of the one before)
    Bytes discarded;                      // after TP-UD when a reserved TP-PI bit is set: ignored (9.2.3.27)
    std::uint8_t ct = 0;                  // TP-CT (COMMAND)
    std::uint8_t mn = 0;                  // TP-MN (COMMAND)
    bool has_pid = false, has_dcs = false, has_ud = false;
    std::uint8_t udl = 0;                 // TP-UDL (septets for 7-bit, else octets) or TP-CDL
    Bytes ud;                             // TP-UD or TP-CD octets

    bool udhi() const noexcept { return (first & 0x40) != 0; }
};

/// rp_error: the TPDU is the RP-User data of an RP-ERROR (a report carries TP-FCS).
Result<Tpdu> decode_tpdu(ByteView in, TpDir dir, bool rp_error = false);
Bytes encode_tpdu(const Tpdu& t);

/// True if TP-DCS selects the GSM 7-bit default alphabet (TS 23.038 4).
bool dcs_is_gsm7(std::uint8_t dcs) noexcept;
/// True if TP-DCS selects UCS2.
bool dcs_is_ucs2(std::uint8_t dcs) noexcept;

// ---- GSM 7-bit default alphabet (TS 23.038) -----------------------------------------

/// Unpack `septets` septets from packed octets, skipping `fill_bits` leading
/// fill bits (after a user data header), and map them to UTF-8; escapes to the
/// extension table are followed. An unknown escape gives U+FFFD.
std::string gsm7_to_utf8(ByteView packed, std::size_t septets, unsigned fill_bits = 0);

/// UTF-8 to packed septets (default alphabet plus extension escapes). Returns
/// the packed octets and the septet count, or an error for a character the
/// alphabet does not have.
Result<std::pair<Bytes, std::size_t>> utf8_to_gsm7(std::string_view text, unsigned fill_bits = 0);

/// UCS2 (big-endian) octets to UTF-8.
std::string ucs2_to_utf8(ByteView in);

/// One-line JSON summaries for ksim-codec and the harness.
std::string to_json(const Cp& cp);
std::string to_json(const Rp& rp);
std::string to_json(const Tpdu& t);

} // namespace ksim::sms
