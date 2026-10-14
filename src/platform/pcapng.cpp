// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/pcapng.hpp"

namespace ksim::pcap {

namespace {

constexpr std::uint32_t kShb = 0x0A0D0D0A;
constexpr std::uint32_t kIdb = 0x00000001;
constexpr std::uint32_t kEpb = 0x00000006;
constexpr std::uint16_t kOptEnd = 0;
constexpr std::uint16_t kOptComment = 1;
constexpr std::uint16_t kShbUserAppl = 4;
constexpr std::uint16_t kIfName = 2;
constexpr std::uint16_t kIfTsresol = 9;
constexpr std::uint16_t kExpPduTagEnd = 0;
constexpr std::uint16_t kExpPduTagProtoName = 12;

void le16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v));
    b.push_back(static_cast<std::uint8_t>(v >> 8));
}

void le32(Bytes& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
}

void pad4(Bytes& b) {
    while (b.size() % 4 != 0) {
        b.push_back(0);
    }
}

void option(Bytes& b, std::uint16_t code, ByteView value) {
    le16(b, code);
    le16(b, static_cast<std::uint16_t>(value.size()));
    b.insert(b.end(), value.begin(), value.end());
    pad4(b);
}

ByteView text(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

/// A block: type, total length, body, total length again.
Bytes block(std::uint32_t type, const Bytes& body) {
    Bytes b;
    const auto total = static_cast<std::uint32_t>(12 + body.size());
    le32(b, type);
    le32(b, total);
    b.insert(b.end(), body.begin(), body.end());
    le32(b, total);
    return b;
}

} // namespace

PcapngWriter::PcapngWriter(Sink sink, std::string_view application) : sink_(std::move(sink)) {
    Bytes body;
    le32(body, 0x1A2B3C4D);   // byte-order magic
    le16(body, 1);            // version 1.0
    le16(body, 0);
    le32(body, 0xFFFFFFFF);   // section length: not given
    le32(body, 0xFFFFFFFF);
    option(body, kShbUserAppl, text(application));
    option(body, kOptEnd, {});
    sink_(block(kShb, body));
}

std::uint32_t PcapngWriter::add_interface(LinkType type, std::string_view name) {
    Bytes body;
    le16(body, static_cast<std::uint16_t>(type));
    le16(body, 0);
    le32(body, 262144);   // snaplen
    option(body, kIfName, text(name));
    const std::uint8_t nanoseconds = 9;   // if_tsresol: 10^-9
    option(body, kIfTsresol, ByteView(&nanoseconds, 1));
    option(body, kOptEnd, {});
    sink_(block(kIdb, body));
    return interfaces_++;
}

Result<void> PcapngWriter::write(std::uint32_t iface, std::int64_t ts_ns, ByteView packet, std::string_view comment) {
    if (iface >= interfaces_) {
        return make_error(Errc::invalid_argument, iface, "pcapng: no such interface");
    }
    if (packet.size() > 262144 || comment.size() > 0xFFFF) {
        return make_error(Errc::overflow, 0, "pcapng: packet over the snaplen or comment too long");
    }
    const auto ts = static_cast<std::uint64_t>(ts_ns);
    Bytes body;
    le32(body, iface);
    le32(body, static_cast<std::uint32_t>(ts >> 32));
    le32(body, static_cast<std::uint32_t>(ts));
    le32(body, static_cast<std::uint32_t>(packet.size()));
    le32(body, static_cast<std::uint32_t>(packet.size()));
    body.insert(body.end(), packet.begin(), packet.end());
    pad4(body);
    if (!comment.empty()) {
        option(body, kOptComment, text(comment));
        option(body, kOptEnd, {});
    }
    sink_(block(kEpb, body));
    return {};
}

Bytes exported_pdu(std::string_view dissector, ByteView pdu) {
    // Tags are big-endian {type, length}; the name is NUL-padded to 4 octets and
    // the length counts the padding (Wireshark's exported_pdu.h).
    Bytes b;
    const std::size_t len = (dissector.size() + 3) / 4 * 4;
    b.push_back(0);
    b.push_back(static_cast<std::uint8_t>(kExpPduTagProtoName));
    b.push_back(static_cast<std::uint8_t>(len >> 8));
    b.push_back(static_cast<std::uint8_t>(len));
    b.insert(b.end(), dissector.begin(), dissector.end());
    b.resize(4 + len, 0);
    b.push_back(0);
    b.push_back(static_cast<std::uint8_t>(kExpPduTagEnd));
    b.push_back(0);
    b.push_back(0);
    b.insert(b.end(), pdu.begin(), pdu.end());
    return b;
}

Result<Bytes> ipv4_udp(const Udp4& a, ByteView payload) {
    // The size is checked before the addition, which could otherwise wrap and
    // leave a short buffer (GCC 15 -O3 rightly flagged that path).
    if (payload.size() > 0xFFFF - 28) {
        return make_error(Errc::overflow, 0, "ipv4_udp: payload over 65507 octets");
    }
    const std::size_t total = 28 + payload.size();
    Bytes b(total, 0);
    const auto put16 = [&b](std::size_t at, std::size_t v) {
        b[at] = static_cast<std::uint8_t>(v >> 8);
        b[at + 1] = static_cast<std::uint8_t>(v);
    };
    b[0] = 0x45;   // version 4, IHL 5
    put16(2, total);
    put16(6, 0x4000);   // don't fragment
    b[8] = 64;          // TTL
    b[9] = 17;          // UDP
    for (std::size_t i = 0; i < 4; ++i) {
        b[12 + i] = a.src[i];
        b[16 + i] = a.dst[i];
    }
    put16(20, a.src_port);
    put16(22, a.dst_port);
    put16(24, 8 + payload.size());   // UDP checksum (26-27) left 0: none
    for (std::size_t i = 0; i < payload.size(); ++i) {
        b[28 + i] = payload[i];
    }
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < 20; i += 2) {
        sum += (std::uint32_t{b[i]} << 8) | b[i + 1];
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    put16(10, static_cast<std::uint16_t>(~sum));
    return b;
}

Bytes gsmtap(std::uint8_t type, std::uint8_t sub_type, ByteView payload) {
    // version 2, header length 4 words, type, timeslot, ARFCN (2), signal dBm,
    // SNR dB, frame number (4), sub-type, antenna, sub-slot, reserved
    Bytes b{2, 4, type, 0, 0, 0, 0, 0, 0, 0, 0, 0, sub_type, 0, 0, 0};
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

} // namespace ksim::pcap
