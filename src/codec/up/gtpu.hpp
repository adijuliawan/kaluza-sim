// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// GTP-U (TS 29.281, plan M12): the header of 5.1 with its optional part, the
// extension header chain of 5.2, and the information elements of clause 8 for
// the signalling messages of clause 7. Extension header contents are octets;
// the PDU Session Container (0x85) and the NR RAN Container (0x84) are read by
// frames.hpp. Everything is kept as received, so encode(decode(x)) == x.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::gtpu {

// Table 6.1-1.
enum class MsgType : std::uint8_t {
    echo_request = 1,
    echo_response = 2,
    error_indication = 26,
    supported_extension_headers_notification = 31,
    tunnel_status = 253,
    end_marker = 254,
    g_pdu = 255,
};

/// The message's name in Table 6.1-1, or nullptr for a type GTP-U does not use.
const char* message_name(std::uint8_t type) noexcept;

// Figure 5.2.1-3.
enum ExtType : std::uint8_t {
    ext_none = 0x00,
    ext_long_pdcp_pdu_number = 0x03,
    ext_pdu_set_information = 0x04,
    ext_service_class_indicator = 0x20,
    ext_udp_port = 0x40,
    ext_ran_container = 0x81,
    ext_long_pdcp_pdu_number_old = 0x82,
    ext_xw_ran_container = 0x83,
    ext_nr_ran_container = 0x84,
    ext_pdu_session_container = 0x85,
    ext_pdu_set_information_old = 0x86,
    ext_pdcp_pdu_number = 0xC0,
};

/// The extension header's name in figure 5.2.1-3, or nullptr if it is not a
/// user plane type of this release.
const char* ext_name(std::uint8_t type) noexcept;

/// Bits 8 and 7 of the type (figure 5.2.1-2): '1x' means the endpoint receiver
/// must understand it.
constexpr bool ext_comprehension_required(std::uint8_t type) noexcept { return (type & 0x80) != 0; }

struct ExtHeader {
    std::uint8_t type = 0;
    Bytes content;   // between the length octet and the next type octet: 4n-2 octets
};

struct Pdu {
    std::uint8_t octet1 = 0x30;   // version 1, PT 1, spare, E, S, PN, as received
    std::uint8_t type = static_cast<std::uint8_t>(MsgType::g_pdu);
    std::uint32_t teid = 0;
    // The optional part (present when E, S or PN is set). Fields whose flag is
    // clear "shall not be evaluated" and are kept as received.
    std::uint16_t sequence = 0;
    std::uint8_t npdu = 0;
    std::uint8_t next_type = 0;   // E clear: as received; E set: written from `ext`
    std::vector<ExtHeader> ext;
    Bytes payload;                // the T-PDU (G-PDU) or the information elements

    bool e() const noexcept { return (octet1 & 0x04) != 0; }
    bool s() const noexcept { return (octet1 & 0x02) != 0; }
    bool pn() const noexcept { return (octet1 & 0x01) != 0; }
    bool has_optional_part() const noexcept { return (octet1 & 0x07) != 0; }
};

/// Decode one GTP-U PDU. The Length field must cover exactly the rest of the
/// input; version 1 and PT 1 are required (GTP' is another protocol).
Result<Pdu> decode(ByteView in);
Result<Bytes> encode(const Pdu& p);

// ---- information elements (clause 8) --------------------------------------------------

// Table 8.1-1.
enum IeType : std::uint8_t {
    ie_recovery = 14,
    ie_teid_data_i = 16,
    ie_peer_address = 133,
    ie_extension_header_type_list = 141,
    ie_tunnel_status_information = 230,
    ie_recovery_time_stamp = 231,
    ie_private_extension = 255,
};

const char* ie_name(std::uint8_t type) noexcept;

struct Ie {
    std::uint8_t type = 0;
    Bytes value;   // TV: the fixed value; TLV: the octets the length counts
};

/// The IEs of a signalling message's payload. TV IEs (type below 128) have a
/// fixed length, so an unknown one cannot be skipped and is an error; TLV IEs
/// have a two-octet length, except the Extension Header Type List (one octet,
/// 8.5).
Result<std::vector<Ie>> decode_ies(ByteView payload);
Result<Bytes> encode_ies(const std::vector<Ie>& ies);

/// One-line JSON for ksim-codec and the oracle harness; IEs are listed for a
/// signalling message (a type other than G-PDU) whose payload decodes.
std::string to_json(const Pdu& p);

} // namespace ksim::gtpu
