// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/up/gtpu.hpp"

namespace ksim::gtpu {

namespace {

Error err(Errc c, std::size_t off, const char* what) {
    return make_error(c, static_cast<std::uint32_t>(off), what);
}

constexpr std::size_t kMandatory = 8;   // figure 5.1-1: octets 1-8

} // namespace

const char* message_name(std::uint8_t type) noexcept {
    switch (static_cast<MsgType>(type)) {
    case MsgType::echo_request: return "Echo Request";
    case MsgType::echo_response: return "Echo Response";
    case MsgType::error_indication: return "Error Indication";
    case MsgType::supported_extension_headers_notification: return "Supported Extension Headers Notification";
    case MsgType::tunnel_status: return "Tunnel Status";
    case MsgType::end_marker: return "End Marker";
    case MsgType::g_pdu: return "G-PDU";
    }
    return nullptr;
}

const char* ext_name(std::uint8_t type) noexcept {
    switch (type) {
    case ext_long_pdcp_pdu_number: return "Long PDCP PDU Number";
    case ext_pdu_set_information: return "PDU Set Information Container";
    case ext_service_class_indicator: return "Service Class Indicator";
    case ext_udp_port: return "UDP Port";
    case ext_ran_container: return "RAN Container";
    case ext_long_pdcp_pdu_number_old: return "Long PDCP PDU Number (earlier releases)";
    case ext_xw_ran_container: return "Xw RAN Container";
    case ext_nr_ran_container: return "NR RAN Container";
    case ext_pdu_session_container: return "PDU Session Container";
    case ext_pdu_set_information_old: return "PDU Set Information Container (earlier versions)";
    case ext_pdcp_pdu_number: return "PDCP PDU Number";
    default: return nullptr;
    }
}

const char* ie_name(std::uint8_t type) noexcept {
    switch (type) {
    case ie_recovery: return "Recovery";
    case ie_teid_data_i: return "Tunnel Endpoint Identifier Data I";
    case ie_peer_address: return "GTP-U Peer Address";
    case ie_extension_header_type_list: return "Extension Header Type List";
    case ie_tunnel_status_information: return "GTP-U Tunnel Status Information";
    case ie_recovery_time_stamp: return "Recovery Time Stamp";
    case ie_private_extension: return "Private Extension";
    default: return nullptr;
    }
}

Result<Pdu> decode(ByteView in) {
    if (in.size() < kMandatory) {
        return err(Errc::truncated, in.size(), "GTP-U: shorter than the mandatory header");
    }
    Pdu p;
    p.octet1 = in[0];
    if ((p.octet1 >> 5) != 1) {
        return err(Errc::unsupported, 0, "GTP-U: version is not 1");
    }
    if ((p.octet1 & 0x10) == 0) {
        return err(Errc::unsupported, 0, "GTP-U: PT 0 is GTP', not GTP");
    }
    p.type = in[1];
    const std::size_t length = (std::size_t{in[2]} << 8) | in[3];
    p.teid = (std::uint32_t{in[4]} << 24) | (std::uint32_t{in[5]} << 16) | (std::uint32_t{in[6]} << 8) | in[7];
    if (kMandatory + length > in.size()) {
        return err(Errc::truncated, 2, "GTP-U: Length runs past the end");
    }
    if (kMandatory + length < in.size()) {
        return err(Errc::malformed, kMandatory + length, "GTP-U: octets after the Length");
    }
    std::size_t pos = kMandatory;
    if (p.has_optional_part()) {
        if (length < 4) {
            return err(Errc::truncated, pos, "GTP-U: E, S or PN set without the optional part");
        }
        p.sequence = static_cast<std::uint16_t>((in[8] << 8) | in[9]);
        p.npdu = in[10];
        p.next_type = in[11];
        pos = 12;
        if (p.e()) {
            for (std::uint8_t next = p.next_type; next != ext_none;) {
                if (pos >= in.size()) {
                    return err(Errc::truncated, pos, "GTP-U: extension header missing");
                }
                const std::size_t units = in[pos];
                if (units == 0) {
                    return err(Errc::malformed, pos, "GTP-U: extension header of length 0");
                }
                if (pos + 4 * units > in.size()) {
                    return err(Errc::truncated, pos, "GTP-U: extension header runs past the end");
                }
                ExtHeader h;
                h.type = next;
                h.content.assign(in.begin() + static_cast<std::ptrdiff_t>(pos + 1),
                                 in.begin() + static_cast<std::ptrdiff_t>(pos + 4 * units - 1));
                next = in[pos + 4 * units - 1];
                pos += 4 * units;
                p.ext.push_back(std::move(h));
            }
        }
    }
    p.payload.assign(in.begin() + static_cast<std::ptrdiff_t>(pos), in.end());
    return p;
}

Result<Bytes> encode(const Pdu& p) {
    if (!p.e() && !p.ext.empty()) {
        return err(Errc::invalid_argument, 0, "GTP-U: extension headers without the E flag");
    }
    ByteWriter w(16 + p.payload.size());
    w.u8(p.octet1);
    w.u8(p.type);
    w.u16(0);   // the Length, patched below
    w.u32(p.teid);
    if (p.has_optional_part()) {
        w.u16(p.sequence);
        w.u8(p.npdu);
        w.u8(p.e() ? (p.ext.empty() ? std::uint8_t{ext_none} : p.ext.front().type) : p.next_type);
        for (std::size_t i = 0; i < p.ext.size(); ++i) {
            const Bytes& c = p.ext[i].content;
            if ((c.size() + 2) % 4 != 0 || c.size() + 2 > std::size_t{4} * 255) {
                return err(Errc::invalid_argument, w.size(), "GTP-U: extension header content is not 4n-2 octets");
            }
            w.u8(static_cast<std::uint8_t>((c.size() + 2) / 4));
            w.bytes(c);
            w.u8(i + 1 < p.ext.size() ? p.ext[i + 1].type : std::uint8_t{ext_none});
        }
    }
    w.bytes(p.payload);
    const std::size_t length = w.size() - kMandatory;
    if (length > 0xFFFF) {
        return err(Errc::overflow, 2, "GTP-U: longer than the Length field allows");
    }
    if (auto ok = w.patch_u16(2, static_cast<std::uint16_t>(length)); !ok) {
        return ok.error();
    }
    return std::move(w).take();
}

Result<std::vector<Ie>> decode_ies(ByteView in) {
    std::vector<Ie> out;
    std::size_t pos = 0;
    while (pos < in.size()) {
        Ie ie;
        ie.type = in[pos];
        std::size_t hdr = 1;
        std::size_t len = 0;
        if (ie.type < 128) {   // TV
            if (ie.type == ie_recovery) {
                len = 1;
            } else if (ie.type == ie_teid_data_i) {
                len = 4;
            } else {
                return err(Errc::unsupported, pos, "GTP-U: an unknown TV IE (its length is not known)");
            }
        } else if (ie.type == ie_extension_header_type_list) {
            if (pos + 2 > in.size()) {
                return err(Errc::truncated, pos, "GTP-U: IE length missing");
            }
            hdr = 2;
            len = in[pos + 1];
        } else {
            if (pos + 3 > in.size()) {
                return err(Errc::truncated, pos, "GTP-U: IE length missing");
            }
            hdr = 3;
            len = (std::size_t{in[pos + 1]} << 8) | in[pos + 2];
        }
        if (pos + hdr + len > in.size()) {
            return err(Errc::truncated, pos, "GTP-U: IE runs past the end");
        }
        ie.value.assign(in.begin() + static_cast<std::ptrdiff_t>(pos + hdr),
                        in.begin() + static_cast<std::ptrdiff_t>(pos + hdr + len));
        pos += hdr + len;
        out.push_back(std::move(ie));
    }
    return out;
}

Result<Bytes> encode_ies(const std::vector<Ie>& ies) {
    ByteWriter w(32);
    for (const Ie& ie : ies) {
        w.u8(ie.type);
        if (ie.type < 128) {
            const std::size_t want = ie.type == ie_recovery ? 1 : ie.type == ie_teid_data_i ? 4 : 0;
            if (want == 0 || ie.value.size() != want) {
                return err(Errc::invalid_argument, w.size(), "GTP-U: a TV IE of unknown type or wrong length");
            }
        } else if (ie.type == ie_extension_header_type_list) {
            if (ie.value.size() > 0xFF) {
                return err(Errc::overflow, w.size(), "GTP-U: Extension Header Type List over 255 types");
            }
            w.u8(static_cast<std::uint8_t>(ie.value.size()));
        } else {
            if (ie.value.size() > 0xFFFF) {
                return err(Errc::overflow, w.size(), "GTP-U: IE over 65535 octets");
            }
            w.u16(static_cast<std::uint16_t>(ie.value.size()));
        }
        w.bytes(ie.value);
    }
    return std::move(w).take();
}

std::string to_json(const Pdu& p) {
    const char* name = message_name(p.type);
    std::string s = "{\"protocol\":\"gtpu\",\"message\":\"" + std::string(name != nullptr ? name : "?") +
                    "\",\"type\":" + std::to_string(p.type) + ",\"octet1\":" + std::to_string(p.octet1) +
                    ",\"teid\":" + std::to_string(p.teid);
    if (p.has_optional_part()) {
        s += ",\"sequence\":" + std::to_string(p.sequence) + ",\"npdu\":" + std::to_string(p.npdu) +
             ",\"next_type\":" + std::to_string(p.e() ? (p.ext.empty() ? 0 : p.ext.front().type) : p.next_type);
    }
    s += ",\"ext\":[";
    for (std::size_t i = 0; i < p.ext.size(); ++i) {
        s += (i != 0 ? "," : "") + std::string("{\"type\":") + std::to_string(p.ext[i].type) + ",\"content\":\"" +
             to_hex(p.ext[i].content) + "\"}";
    }
    s += "],\"payload\":\"" + to_hex(p.payload) + "\"";
    if (p.type != static_cast<std::uint8_t>(MsgType::g_pdu)) {
        if (auto ies = decode_ies(p.payload); ies) {
            s += ",\"ies\":[";
            for (std::size_t i = 0; i < ies->size(); ++i) {
                s += (i != 0 ? "," : "") + std::string("{\"type\":") + std::to_string((*ies)[i].type) +
                     ",\"value\":\"" + to_hex((*ies)[i].value) + "\"}";
            }
            s += "]";
        } else {
            s += ",\"ies_error\":\"" + std::string(ies.error().what) + "\"";
        }
    }
    return s + "}";
}

} // namespace ksim::gtpu
