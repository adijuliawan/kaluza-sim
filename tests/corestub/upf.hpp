// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The core stub's UPF (P1 N10, ADR 0009 point f): one N3 GTP-U endpoint and a
// DN reflector behind it. A session's uplink tunnel is opened by the SMF; the
// gNB's downlink end is learned from the PDU SESSION RESOURCE SETUP RESPONSE.
// Every uplink G-PDU is checked (TS 38.415: a UL PDU SESSION INFORMATION frame
// with the session's QFI; the inner packet from the UE's address), and an ICMP
// echo request to any address is answered from that address, on the downlink
// tunnel with a DL PDU SESSION INFORMATION frame naming the QFI. A test can
// also ping the UE from the DN (N12 paging rows).

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "codec/asn1/msg/ngap.hpp"
#include "codec/ip/ipv4.hpp"
#include "entity/gtpu/gtpu.hpp"
#include "platform/transport.hpp"
#include "verdict.hpp"

namespace ksim::corestub {



struct UpfStats {
    std::uint64_t ul_packets = 0;
    std::uint64_t dl_packets = 0;
    std::uint64_t echo_replies = 0;      // sent to a UE
    std::uint64_t echo_from_ue = 0;      // echo replies a UE sent to a DN ping
    std::uint64_t unknown_teid = 0;
};

class Upf {
public:
    /// `addr`: the N3 address the SMF advertises; `port`: GTP-U's on the gNB side.
    Upf(IDatagram& n3, std::array<std::uint8_t, 4> addr, std::uint16_t port = 2152);
    Upf(const Upf&) = delete;
    Upf& operator=(const Upf&) = delete;

    /// A new uplink tunnel for a UE address and its flow's QFI; its TEID.
    std::uint32_t open(ip::Addr ue, std::uint8_t qfi);
    void set_dl(std::uint32_t ul_teid, const ngap::GtpTunnel& dl);
    void close(std::uint32_t ul_teid);
    /// An echo request from `from` to the UE behind `ul_teid` (a DN ping).
    Result<void> ping_ue(std::uint32_t ul_teid, ip::Addr from, std::uint16_t seq);

    ngap::GtpTunnel tunnel(std::uint32_t ul_teid) const { return {addr_, ul_teid}; }
    const UpfStats& stats() const noexcept { return stats_; }
    const std::vector<Verdict>& verdicts() const noexcept { return verdicts_; }
    std::uint64_t error_indications() const noexcept { return gtpu_.stats().error_indications; }

private:
    struct Tunnel {
        ip::Addr ue{};
        std::uint8_t qfi = 1;
        std::optional<ngap::GtpTunnel> dl;
    };
    void on_ul(std::uint32_t teid, const entity::gtpu::UserData& d);
    void send_dl(const Tunnel& t, Bytes packet);
    void check(bool ok, const char* clause, const char* what, std::string detail = {});

    entity::gtpu::Endpoint gtpu_;
    std::array<std::uint8_t, 4> addr_;
    std::uint16_t port_;
    std::map<std::uint32_t, Tunnel> tunnels_;
    UpfStats stats_;
    std::vector<Verdict> verdicts_;
};

} // namespace ksim::corestub
