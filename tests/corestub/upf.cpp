// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "upf.hpp"

#include "verdict.hpp"

namespace ksim::corestub {

namespace {

constexpr std::uint8_t kUpfTag = 0x51;   // the stub UPF's TEIDs

std::string text(const ip::Addr& a) {
    return std::to_string(a[0]) + "." + std::to_string(a[1]) + "." + std::to_string(a[2]) + "." + std::to_string(a[3]);
}

} // namespace

Upf::Upf(IDatagram& n3, std::array<std::uint8_t, 4> addr, std::uint16_t port)
    : gtpu_(n3, kUpfTag), addr_(addr), port_(port) {}

void Upf::check(bool ok, const char* clause, const char* what, std::string detail) {
    verdicts_.push_back(Verdict{clause, what, ok, std::move(detail)});
}

std::uint32_t Upf::open(ip::Addr ue, std::uint8_t qfi) {
    const std::uint32_t teid = gtpu_.bind([this](const entity::gtpu::UserData& d, const ksim::Endpoint&) { on_ul(d.teid, d); });
    tunnels_[teid] = Tunnel{ue, qfi, std::nullopt};
    return teid;
}

void Upf::set_dl(std::uint32_t ul_teid, const ngap::GtpTunnel& dl) {
    auto it = tunnels_.find(ul_teid);
    if (it != tunnels_.end()) {
        it->second.dl = dl;
    }
}

void Upf::close(std::uint32_t ul_teid) {
    gtpu_.unbind(ul_teid);
    tunnels_.erase(ul_teid);
}

void Upf::send_dl(const Tunnel& t, Bytes packet) {
    if (!t.dl) {
        return;
    }
    const auto& a = t.dl->addr;
    entity::gtpu::UserData d{t.dl->teid, t.qfi, std::nullopt, std::nullopt, std::move(packet)};
    if (gtpu_.send(ksim::Endpoint::v4(a[0], a[1], a[2], a[3], port_), d)) {
        ++stats_.dl_packets;
    }
}

void Upf::on_ul(std::uint32_t teid, const entity::gtpu::UserData& d) {
    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        ++stats_.unknown_teid;
        return;
    }
    ++stats_.ul_packets;
    const Tunnel& t = it->second;
    check(d.ul_qfi.has_value(), "TS 38.415 5.5.2.2", "an uplink G-PDU carries a UL PDU SESSION INFORMATION frame");
    if (d.ul_qfi) {
        check(*d.ul_qfi == t.qfi, "TS 38.415 5.5.3.3", "the uplink QFI is the session's", std::to_string(*d.ul_qfi));
    }
    auto p = ip::decode(d.payload);
    check(p.has_value(), "RFC 791 3.1", "the uplink T-PDU is an IPv4 packet", p ? "" : p.error().what);
    if (!p) {
        return;
    }
    check(p->src == t.ue, "TS 23.501 5.8.2.2", "the packet comes from the UE's address", text(p->src));
    if (p->protocol != ip::kIcmp) {
        return;
    }
    auto e = ip::decode_icmp(p->payload);
    if (!e || !*e) {
        return;
    }
    if ((*e)->reply) {
        ++stats_.echo_from_ue;
        return;
    }
    ip::Echo reply = **e;
    reply.reply = true;
    ip::Ipv4 out;
    out.id = p->id;
    out.ttl = 63;
    out.protocol = ip::kIcmp;
    out.src = p->dst;
    out.dst = p->src;
    out.payload = ip::encode_icmp(reply);
    ++stats_.echo_replies;
    send_dl(t, ip::encode(out));
}

Result<void> Upf::ping_ue(std::uint32_t ul_teid, ip::Addr from, std::uint16_t seq) {
    auto it = tunnels_.find(ul_teid);
    if (it == tunnels_.end() || !it->second.dl) {
        return make_error(Errc::invalid_argument, ul_teid, "upf: no session with a downlink tunnel");
    }
    send_dl(it->second, ip::ping(from, it->second.ue, 0x5155, seq, 56));
    return {};
}

} // namespace ksim::corestub
