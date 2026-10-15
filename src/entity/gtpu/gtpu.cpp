// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "entity/gtpu/gtpu.hpp"

#include "codec/up/frames.hpp"
#include "codec/up/gtpu.hpp"

namespace ksim::entity::gtpu {

namespace {

namespace codec = ksim::gtpu;

Result<Bytes> frame(up::Protocol p, std::uint8_t type, std::uint8_t octet2, std::optional<std::uint32_t> sn) {
    auto f = up::make(p, type);
    if (!f) {
        return f.error();
    }
    f->flags[1] = octet2;
    if (sn) {
        if (auto r = up::set(*f, "NR-U Sequence Number", *sn); !r) {
            return r.error();
        }
    }
    return up::encode(*f);
}

} // namespace

Result<Bytes> encode(const UserData& d) {
    codec::Pdu p;
    p.type = static_cast<std::uint8_t>(codec::MsgType::g_pdu);
    p.teid = d.teid;
    p.payload = d.payload;
    std::optional<Result<Bytes>> ext;
    std::uint8_t ext_type = 0;
    if (d.dl_qfi || d.ul_qfi) {
        const bool dl = d.dl_qfi.has_value();
        ext = frame(up::Protocol::psc, dl ? 0 : 1, static_cast<std::uint8_t>((dl ? *d.dl_qfi : *d.ul_qfi) & 0x3F), std::nullopt);
        ext_type = codec::ext_pdu_session_container;
    } else if (d.nru_sn) {
        ext = frame(up::Protocol::nru, 0, 0, d.nru_sn);
        ext_type = codec::ext_nr_ran_container;
    }
    if (ext) {
        if (!*ext) {
            return ext->error();
        }
        p.octet1 = 0x34;   // version 1, PT 1, E
        p.ext.push_back(codec::ExtHeader{ext_type, std::move(**ext)});
    }
    return codec::encode(p);
}

Result<UserData> decode_gpdu(ByteView in) {
    auto p = codec::decode(in);
    if (!p) {
        return p.error();
    }
    if (p->type != static_cast<std::uint8_t>(codec::MsgType::g_pdu)) {
        return make_error(Errc::invalid_argument, 1, "GTP-U: not a G-PDU");
    }
    UserData d;
    d.teid = p->teid;
    d.payload = std::move(p->payload);
    for (const auto& e : p->ext) {
        if (e.type == codec::ext_pdu_session_container) {
            auto f = up::decode(up::Protocol::psc, e.content);
            if (!f) {
                return f.error();
            }
            const std::uint8_t qfi = f->flags.size() > 1 ? static_cast<std::uint8_t>(f->flags[1] & 0x3F) : 0;
            if (f->spec->pdu_type == 0) {
                d.dl_qfi = qfi;
            } else {
                d.ul_qfi = qfi;
            }
        } else if (e.type == codec::ext_nr_ran_container) {
            auto f = up::decode(up::Protocol::nru, e.content);
            if (!f) {
                return f.error();
            }
            if (auto sn = f->value("NR-U Sequence Number")) {
                d.nru_sn = static_cast<std::uint32_t>(*sn);
            }
        }
    }
    return d;
}

Endpoint::Endpoint(IDatagram& port, std::uint8_t tag) : port_(port), tag_(tag) {
    port_.set_handler([this](ByteView in, const ksim::Endpoint& from) { on_datagram(in, from); });
}

std::uint32_t Endpoint::bind(OnData rx) {
    std::uint32_t teid = 0;
    do {
        teid = (std::uint32_t{tag_} << 24) | (next_++ & 0xFFFFFF);
    } while (teid == 0 || tunnels_.count(teid) != 0);
    tunnels_.emplace(teid, std::move(rx));
    return teid;
}

void Endpoint::unbind(std::uint32_t teid) { tunnels_.erase(teid); }

Result<void> Endpoint::send(const ksim::Endpoint& peer, const UserData& d) {
    auto wire = encode(d);
    if (!wire) {
        return wire.error();
    }
    ++stats_.tx;
    return port_.send_to(*wire, peer);
}

Result<void> Endpoint::echo(const ksim::Endpoint& peer, std::function<void()> on_response) {
    codec::Pdu p;
    p.octet1 = 0x32;   // version 1, PT 1, S: Echo carries a sequence number (7.2.1)
    p.type = static_cast<std::uint8_t>(codec::MsgType::echo_request);
    p.sequence = ++echo_seq_;
    auto wire = codec::encode(p);
    if (!wire) {
        return wire.error();
    }
    echoes_[p.sequence] = std::move(on_response);
    return port_.send_to(*wire, peer);
}

void Endpoint::error_indication(std::uint32_t teid, const ksim::Endpoint& to) {
    // 7.3.1: TEID Data I (the TEID of the G-PDU) and GTP-U Peer Address (ours).
    const ksim::Endpoint me = port_.local();
    Bytes addr(me.addr.begin(), me.addr.begin() + (me.family == ksim::Endpoint::Family::v4 ? 4 : 16));
    std::vector<codec::Ie> ies{
        codec::Ie{codec::ie_teid_data_i, Bytes{static_cast<std::uint8_t>(teid >> 24), static_cast<std::uint8_t>(teid >> 16),
                                               static_cast<std::uint8_t>(teid >> 8), static_cast<std::uint8_t>(teid)}},
        codec::Ie{codec::ie_peer_address, addr}};
    auto payload = codec::encode_ies(ies);
    if (!payload) {
        return;
    }
    codec::Pdu p;
    p.octet1 = 0x32;
    p.type = static_cast<std::uint8_t>(codec::MsgType::error_indication);
    p.payload = std::move(*payload);
    if (auto wire = codec::encode(p)) {
        (void)port_.send_to(*wire, to);
    }
}

void Endpoint::on_datagram(ByteView in, const ksim::Endpoint& from) {
    auto p = codec::decode(in);
    if (!p) {
        ++stats_.malformed;
        return;
    }
    switch (static_cast<codec::MsgType>(p->type)) {
    case codec::MsgType::g_pdu: {
        auto d = decode_gpdu(in);
        if (!d) {
            ++stats_.malformed;
            return;
        }
        auto it = tunnels_.find(d->teid);
        if (it == tunnels_.end()) {
            ++stats_.unknown_teid;
            error_indication(d->teid, from);
            return;
        }
        ++stats_.rx;
        it->second(*d, from);   // may unbind this tunnel
        return;
    }
    case codec::MsgType::echo_request: {
        ++stats_.echo_requests;
        codec::Pdu r;
        r.octet1 = 0x32;
        r.type = static_cast<std::uint8_t>(codec::MsgType::echo_response);
        r.sequence = p->sequence;
        auto ies = codec::encode_ies({codec::Ie{codec::ie_recovery, Bytes{0}}});   // Recovery 0 (7.2.2)
        if (ies) {
            r.payload = std::move(*ies);
        }
        if (auto wire = codec::encode(r)) {
            (void)port_.send_to(*wire, from);
        }
        return;
    }
    case codec::MsgType::echo_response: {
        ++stats_.echo_responses;
        auto it = echoes_.find(p->sequence);
        if (it != echoes_.end()) {
            auto f = std::move(it->second);
            echoes_.erase(it);
            if (f) {
                f();
            }
        }
        return;
    }
    case codec::MsgType::error_indication: {
        ++stats_.error_indications;
        auto ies = codec::decode_ies(p->payload);
        std::uint32_t teid = 0;
        if (ies) {
            for (const auto& ie : *ies) {
                if (ie.type == codec::ie_teid_data_i && ie.value.size() == 4) {
                    teid = (std::uint32_t{ie.value[0]} << 24) | (std::uint32_t{ie.value[1]} << 16) |
                           (std::uint32_t{ie.value[2]} << 8) | ie.value[3];
                }
            }
        }
        if (on_error_) {
            on_error_(teid, from);
        }
        return;
    }
    default:
        return;   // End Marker and the rest: not P1's
    }
}

} // namespace ksim::entity::gtpu
