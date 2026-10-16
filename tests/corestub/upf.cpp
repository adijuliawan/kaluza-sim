// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "upf.hpp"

#include "proc/ue/qos_classifier.hpp"

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
    // Per packet: a pass is counted, a failure kept (P2 Q12: at Gbit/s every pass kept grew
    // the stub by tens of MB a second).
    if (ok) {
        ++checks_passed_;
        return;
    }
    verdicts_.push_back(Verdict{clause, what, ok, std::move(detail)});
}

std::uint32_t Upf::open(ip::Addr ue, std::uint8_t qfi) {
    const std::uint32_t teid = gtpu_.bind([this](const entity::gtpu::UserData& d, const ksim::Endpoint&) { on_ul(d.teid, d); });
    tunnels_[teid] = Tunnel{ue, qfi, std::nullopt, {}, {}, {}};
    by_ue_[ue] = teid;
    return teid;
}

void Upf::set_dl(std::uint32_t ul_teid, const ngap::GtpTunnel& dl) {
    auto it = tunnels_.find(ul_teid);
    if (it == tunnels_.end()) {
        return;
    }
    it->second.dl = dl;
    auto held = std::move(it->second.held);
    it->second.held.clear();
    for (auto& p : held) {
        send_dl(it->second, std::move(p));
    }
}

void Upf::deactivate(std::uint32_t ul_teid) {
    if (auto it = tunnels_.find(ul_teid); it != tunnels_.end()) {
        it->second.dl.reset();
    }
}

void Upf::close(std::uint32_t ul_teid) {
    gtpu_.unbind(ul_teid);
    if (auto it = tunnels_.find(ul_teid); it != tunnels_.end()) {
        if (auto u = by_ue_.find(it->second.ue); u != by_ue_.end() && u->second == ul_teid) {
            by_ue_.erase(u);
        }
        tunnels_.erase(it);
    }
}

void Upf::send_dl(Tunnel& t, Bytes packet, std::optional<std::uint8_t> qfi_override, bool rqi) {
    if (!t.dl) {
        // Deactivated: held, and the first one reported so the UE is paged.
        const bool first = t.held.empty();
        if (t.held.size() < 16) {
            t.held.push_back(std::move(packet));
            ++stats_.held;
        }
        if (first && on_pending_) {
            for (const auto& [teid, tun] : tunnels_) {
                if (&tun == &t) {
                    on_pending_(teid);
                    break;
                }
            }
        }
        return;
    }
    const auto& a = t.dl->addr;
    // P2 Q10: the QFI the downlink filters give the packet; the default rule's otherwise.
    std::uint8_t qfi = t.qfi;
    if (const auto* r = proc::ue::classify(t.rules, packet, proc::ue::QosDirection::downlink); r != nullptr && r->qfi) {
        qfi = *r->qfi;
    }
    qfi = qfi_override.value_or(qfi);   // P2 Q11: a test's own marking
    ++stats_.dl_per_qfi[qfi];
    if (rqi) {
        ++stats_.rqi_marked;
    }
    const std::size_t octets = packet.size();
    const auto d = entity::gtpu::UserData::dl_psc(t.dl->teid, qfi, std::move(packet), rqi);
    if (gtpu_.send(ksim::Endpoint::v4(a[0], a[1], a[2], a[3], port_), d)) {
        ++stats_.dl_packets;
        stats_.dl_bytes += octets;
    }
}

void Upf::attach_dn(IPacketPort* dn) {
    dn_ = dn;
    if (dn_ == nullptr) {
        return;
    }
    dn_->set_handler([this](ByteView packet) {
        // A DN packet for a UE: down the tunnel of its destination address.
        ++stats_.dn_rx;
        if (packet.size() < 20 || (packet[0] >> 4) != 4) {
            ++stats_.dn_no_ue;
            return;
        }
        const ip::Addr dst{packet[16], packet[17], packet[18], packet[19]};
        auto u = by_ue_.find(dst);
        auto t = u != by_ue_.end() ? tunnels_.find(u->second) : tunnels_.end();
        if (t == tunnels_.end()) {
            ++stats_.dn_no_ue;
            return;
        }
        send_dl(t->second, Bytes(packet.begin(), packet.end()));
    });
}

void Upf::set_rules(std::uint32_t ul_teid, std::vector<nas::ie::QosRules::Rule> rules) {
    if (auto it = tunnels_.find(ul_teid); it != tunnels_.end()) {
        it->second.rules = std::move(rules);
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
        ++stats_.ul_per_qfi[*d.ul_qfi];
        // P2 Q11: a reply to a datagram sent with the RQI goes on its QFI (the UE's derived rule).
        // Read in place: the forwarding path (P2 Q12) copies no packet for its checks.
        std::optional<std::uint8_t> reflected;
        const ByteView pl(d.payload);
        if (pl.size() >= 20 && (pl[0] >> 4) == 4 && pl[9] == ip::kUdp) {
            ++stats_.udp_from_ue;
            const std::size_t ihl = static_cast<std::size_t>(pl[0] & 0x0F) * 4;
            if (!t.reflected.empty() && pl.size() >= ihl + 4) {
                const ip::Addr dst{pl[16], pl[17], pl[18], pl[19]};
                const auto dport = static_cast<std::uint16_t>(pl[ihl + 2] << 8 | pl[ihl + 3]);
                if (auto r = t.reflected.find({dst, dport}); r != t.reflected.end()) {
                    reflected = r->second;
                }
            }
        }
        if (reflected) {
            const bool ok = *d.ul_qfi == *reflected;
            check(ok, "TS 24.501 6.2.5.1.4.3", "the reply to an RQI packet goes on its QFI",
                  ok ? std::string() : std::to_string(*d.ul_qfi) + " for " + std::to_string(*reflected));
        } else if (t.rules.empty()) {
            const bool ok = *d.ul_qfi == t.qfi;
            check(ok, "TS 38.415 5.5.3.3", "the uplink QFI is the session's", ok ? std::string() : std::to_string(*d.ul_qfi));
        } else {
            // P2 Q10: the QFI of the QoS rule the packet matches (TS 23.501 5.7.1.5, 24.501 6.2.5.1.1.2).
            const auto* r = proc::ue::classify(t.rules, d.payload, proc::ue::QosDirection::uplink);
            const std::uint8_t want = r != nullptr && r->qfi ? *r->qfi : 0;
            const bool ok = *d.ul_qfi == want;
            check(ok, "TS 23.501 5.7.1.5", "the uplink QFI is the one the session's QoS rules give the packet",
                  ok ? std::string() : std::to_string(*d.ul_qfi) + " for " + std::to_string(want));
        }
    }
    if (dn_ != nullptr) {
        // P2 Q12: forwarded to the DN once it is the UE's own IPv4 packet.
        const ByteView pl(d.payload);
        const bool v4 = pl.size() >= 20 && (pl[0] >> 4) == 4;
        check(v4, "RFC 791 3.1", "the uplink T-PDU is an IPv4 packet");
        if (!v4) {
            return;
        }
        const ip::Addr src{pl[12], pl[13], pl[14], pl[15]};
        check(src == t.ue, "TS 23.501 5.8.2.2", "the packet comes from the UE's address", src == t.ue ? std::string() : text(src));
        if (dn_->write(pl)) {
            ++stats_.dn_tx;
        }
        return;
    }
    auto p = ip::decode(d.payload);
    check(p.has_value(), "RFC 791 3.1", "the uplink T-PDU is an IPv4 packet", p ? std::string() : std::string(p.error().what));
    if (!p) {
        return;
    }
    check(p->src == t.ue, "TS 23.501 5.8.2.2", "the packet comes from the UE's address",
          p->src == t.ue ? std::string() : text(p->src));
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
    Tunnel& tt = it->second;
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
    send_dl(tt, ip::encode(out));
}

Result<void> Upf::udp_ue(std::uint32_t ul_teid, ip::Addr from, std::uint16_t sport, std::optional<std::uint8_t> qfi, bool rqi,
                         std::uint16_t seq) {
    auto it = tunnels_.find(ul_teid);
    if (it == tunnels_.end()) {
        return make_error(Errc::invalid_argument, ul_teid, "upf: no such session");
    }
    Tunnel& t = it->second;
    ip::Ipv4 p;
    p.id = seq;
    p.ttl = 63;
    p.protocol = ip::kUdp;
    p.src = from;
    p.dst = t.ue;
    p.payload = {static_cast<std::uint8_t>(sport >> 8), static_cast<std::uint8_t>(sport), 0, 7, 0, 14, 0, 0,
                 'k', 's', 'i', 'm', static_cast<std::uint8_t>(seq >> 8), static_cast<std::uint8_t>(seq)};
    const Bytes packet = ip::encode(p);
    if (rqi) {
        std::uint8_t q = t.qfi;
        if (const auto* r = proc::ue::classify(t.rules, packet, proc::ue::QosDirection::downlink); r != nullptr && r->qfi) {
            q = *r->qfi;
        }
        t.reflected[{from, sport}] = qfi.value_or(q);
    }
    ++stats_.udp_to_ue;
    send_dl(t, packet, qfi, rqi);
    return {};
}

Result<void> Upf::ping_ue(std::uint32_t ul_teid, ip::Addr from, std::uint16_t seq) {
    auto it = tunnels_.find(ul_teid);
    if (it == tunnels_.end()) {
        return make_error(Errc::invalid_argument, ul_teid, "upf: no such session");
    }
    send_dl(it->second, ip::ping(from, it->second.ue, 0x5155, seq, 56));
    return {};
}

} // namespace ksim::corestub
