// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/air/kair.hpp"

#include <algorithm>

namespace ksim::air {

namespace {

Error bad(std::size_t at, const char* what) { return Error{Errc::malformed, static_cast<std::uint32_t>(at), what}; }

void tlv(ByteWriter& w, TlvType t, ByteView v) {
    w.u8(static_cast<std::uint8_t>(t));
    w.u16(static_cast<std::uint16_t>(v.size()));
    w.bytes(v);
}

bool sdu_frame(FrameType t) {
    return t == FrameType::bch || t == FrameType::si || t == FrameType::pcch || t == FrameType::msg3 ||
           t == FrameType::msg4 || t == FrameType::dl_sdu || t == FrameType::ul_sdu;
}

/// What a frame of this type must carry.
Result<void> check_required(const Frame& f) {
    switch (f.type) {
    case FrameType::cell_announce:
        if (!f.cell) {
            return bad(0, "KAIR: CELL_ANNOUNCE without its cell");
        }
        break;
    case FrameType::bch:
    case FrameType::si:
        if (f.sdus.size() != 1) {
            return bad(0, "KAIR: BCH and SI carry exactly one SDU");
        }
        break;
    case FrameType::pcch:
        if (f.sdus.size() != 1 || !f.paging) {
            return bad(0, "KAIR: PCCH carries one SDU and its paging stamp");
        }
        break;
    case FrameType::prach:
        if (!f.prach) {
            return bad(0, "KAIR: PRACH without its preamble");
        }
        break;
    case FrameType::rar:
        if (!f.rar) {
            return bad(0, "KAIR: RAR without its response");
        }
        break;
    case FrameType::msg3:
        if (f.sdus.empty()) {
            return bad(0, "KAIR: MSG3 without an SDU");
        }
        break;
    case FrameType::msg4:
        if (!f.contention_id || f.sdus.size() != 1) {
            return bad(0, "KAIR: MSG4 carries the contention resolution identity and one SDU");
        }
        break;
    case FrameType::dl_sdu:
    case FrameType::ul_sdu:
        if (f.sdus.empty()) {
            return bad(0, "KAIR: an SDU frame without an SDU");
        }
        break;
    case FrameType::mac_ce:
        if (f.ces.empty()) {
            return bad(0, "KAIR: MAC_CE without a CE");
        }
        break;
    case FrameType::subscribe:
    case FrameType::keepalive:
        break;
    }
    if (!f.sdus.empty() && !sdu_frame(f.type)) {
        return bad(0, "KAIR: SDUs in a frame type that carries none");
    }
    for (const Sdu& s : f.sdus) {
        if (s.lcid > 63 || static_cast<std::uint8_t>(s.mode) > 2) {
            return bad(0, "KAIR: an SDU's LCID or RLC mode is out of range");
        }
    }
    if (f.prach && (f.prach->preamble > 63 || f.prach->s_id > 13 || f.prach->t_id > 79 || f.prach->f_id > 7 ||
                    f.prach->ul_carrier_id > 1)) {
        return bad(0, "KAIR: a PRACH field is out of range");
    }
    if (f.cell && (f.cell->nci >> 36 != 0 || f.cell->pci > 1007 || f.cell->tac >> 24 != 0)) {
        return bad(0, "KAIR: a cell field is out of range");
    }
    return {};
}

} // namespace

const char* frame_type_name(FrameType t) noexcept {
    switch (t) {
    case FrameType::cell_announce: return "CELL_ANNOUNCE";
    case FrameType::subscribe: return "SUBSCRIBE";
    case FrameType::bch: return "BCH";
    case FrameType::si: return "SI";
    case FrameType::pcch: return "PCCH";
    case FrameType::prach: return "PRACH";
    case FrameType::rar: return "RAR";
    case FrameType::msg3: return "MSG3";
    case FrameType::msg4: return "MSG4";
    case FrameType::dl_sdu: return "DL_SDU";
    case FrameType::ul_sdu: return "UL_SDU";
    case FrameType::mac_ce: return "MAC_CE";
    case FrameType::keepalive: return "KEEPALIVE";
    }
    return "?";
}

std::uint16_t Prach::ra_rnti() const noexcept {
    return static_cast<std::uint16_t>(1 + s_id + 14 * t_id + 14 * 80 * f_id + 14 * 80 * 8 * ul_carrier_id);
}

std::array<std::uint8_t, 6> contention_id_of(ByteView ccch_sdu) noexcept {
    std::array<std::uint8_t, 6> id{};
    std::copy_n(ccch_sdu.begin(), std::min<std::size_t>(6, ccch_sdu.size()), id.begin());
    return id;
}

Result<Frame> decode(ByteView in) {
    ByteReader r(in);
    if (in.size() < kHeaderSize) {
        return Error{Errc::truncated, static_cast<std::uint32_t>(in.size()), "KAIR: shorter than the header"};
    }
    Frame f;
    if (*r.u16() != kMagic) {
        return bad(0, "KAIR: bad magic");
    }
    if (*r.u8() != kVersion) {
        return Error{Errc::unsupported, 2, "KAIR: version is not 1"};
    }
    const std::uint8_t type = *r.u8();
    if (type < 1 || type > 13) {
        return bad(3, "KAIR: unknown frame type");
    }
    f.type = static_cast<FrameType>(type);
    f.flags = *r.u16();
    const std::uint16_t length = *r.u16();
    f.cell_handle = *r.u32();
    f.radio_id = *r.u32();
    f.tx_time_ns = *r.u64();
    f.sfn_slot = *r.u32();
    f.rnti = *r.u16();
    f.seq = *r.u16();
    if (r.remaining() != length) {
        return bad(6, "KAIR: the TLV length does not match the frame");
    }
    while (!r.empty()) {
        const std::size_t at = r.offset();
        if (r.remaining() < 3) {
            return Error{Errc::truncated, static_cast<std::uint32_t>(at), "KAIR: a TLV header is cut short"};
        }
        const std::uint8_t t = *r.u8();
        const std::uint16_t n = *r.u16();
        auto v = r.take(n);
        if (!v) {
            return Error{Errc::truncated, static_cast<std::uint32_t>(at), "KAIR: a TLV value is cut short"};
        }
        ByteReader tv(*v);
        switch (static_cast<TlvType>(t)) {
        case TlvType::sdu: {
            if (n < 2) {
                return bad(at, "KAIR: an SDU TLV without LCID and mode");
            }
            Sdu s;
            s.lcid = *tv.u8();
            const std::uint8_t mode = *tv.u8();
            if (mode > 2) {
                return bad(at, "KAIR: an unknown RLC mode");
            }
            s.mode = static_cast<RlcMode>(mode);
            const ByteView rest = tv.rest();
            s.data.assign(rest.begin(), rest.end());
            f.sdus.push_back(std::move(s));
            break;
        }
        case TlvType::mac_ce: {
            if (n < 1) {
                return bad(at, "KAIR: a MAC CE TLV without its LCID");
            }
            MacCe c;
            c.lcid = *tv.u8();
            const ByteView rest = tv.rest();
            c.data.assign(rest.begin(), rest.end());
            f.ces.push_back(std::move(c));
            break;
        }
        case TlvType::scene:
            if (n != 4) {
                return bad(at, "KAIR: a SCENE TLV is four octets");
            }
            f.scene = *tv.u32();
            break;
        case TlvType::cell: {
            if (n != 8 + 2 + 4 + 3 + 3) {
                return bad(at, "KAIR: a CELL TLV is twenty octets");
            }
            CellInfo c;
            c.nci = *tv.u64();
            c.pci = *tv.u16();
            c.arfcn = *tv.u32();
            for (auto& o : c.plmn) {
                o = *tv.u8();
            }
            c.tac = *tv.u24();
            f.cell = c;
            break;
        }
        case TlvType::prach:
            if (n != 5) {
                return bad(at, "KAIR: a PRACH TLV is five octets");
            }
            f.prach = Prach{*tv.u8(), *tv.u8(), *tv.u8(), *tv.u8(), *tv.u8()};
            break;
        case TlvType::rar: {
            if (n != 6) {
                return bad(at, "KAIR: a RAR TLV is six octets");
            }
            Rar a;
            a.rapid = *tv.u8();
            a.tc_rnti = *tv.u16();
            a.backoff = *tv.u8();
            a.ta = *tv.u16();
            f.rar = a;
            break;
        }
        case TlvType::contention_id: {
            if (n != 6) {
                return bad(at, "KAIR: a contention resolution identity is six octets");
            }
            std::array<std::uint8_t, 6> id{};
            std::copy(v->begin(), v->end(), id.begin());
            f.contention_id = id;
            break;
        }
        case TlvType::paging: {
            if (n != 4) {
                return bad(at, "KAIR: a PAGING TLV is four octets");
            }
            PagingStamp p;
            p.pf_sfn = *tv.u16();
            p.i_s = *tv.u8();
            p.si_change = (*tv.u8() & 0x01) != 0;
            f.paging = p;
            break;
        }
        default:
            break;   // a TLV a later version adds
        }
    }
    auto ok = check_required(f);
    if (!ok) {
        return ok.error();
    }
    return f;
}

Result<Bytes> encode(const Frame& f) {
    auto ok = check_required(f);
    if (!ok) {
        return ok.error();
    }
    ByteWriter body(64);
    if (f.cell) {
        ByteWriter v(20);
        v.u64(f.cell->nci);
        v.u16(f.cell->pci);
        v.u32(f.cell->arfcn);
        v.bytes(f.cell->plmn);
        v.u24(f.cell->tac);
        tlv(body, TlvType::cell, v.data());
    }
    if (f.prach) {
        const Bytes v{f.prach->preamble, f.prach->s_id, f.prach->t_id, f.prach->f_id, f.prach->ul_carrier_id};
        tlv(body, TlvType::prach, v);
    }
    if (f.rar) {
        ByteWriter v(6);
        v.u8(f.rar->rapid);
        v.u16(f.rar->tc_rnti);
        v.u8(f.rar->backoff);
        v.u16(f.rar->ta);
        tlv(body, TlvType::rar, v.data());
    }
    if (f.contention_id) {
        tlv(body, TlvType::contention_id, *f.contention_id);
    }
    if (f.paging) {
        ByteWriter v(4);
        v.u16(f.paging->pf_sfn);
        v.u8(f.paging->i_s);
        v.u8(f.paging->si_change ? 1 : 0);
        tlv(body, TlvType::paging, v.data());
    }
    if (f.scene) {
        ByteWriter v(4);
        v.u32(*f.scene);
        tlv(body, TlvType::scene, v.data());
    }
    for (const MacCe& c : f.ces) {
        if (c.data.size() + 1 > 0xFFFF) {
            return Error{Errc::overflow, 0, "KAIR: a MAC CE over 65534 octets"};
        }
        ByteWriter v(c.data.size() + 1);
        v.u8(c.lcid);
        v.bytes(c.data);
        tlv(body, TlvType::mac_ce, v.data());
    }
    for (const Sdu& s : f.sdus) {
        if (s.data.size() + 2 > 0xFFFF) {
            return Error{Errc::overflow, 0, "KAIR: an SDU over 65533 octets"};
        }
        ByteWriter v(s.data.size() + 2);
        v.u8(s.lcid);
        v.u8(static_cast<std::uint8_t>(s.mode));
        v.bytes(s.data);
        tlv(body, TlvType::sdu, v.data());
    }
    if (body.size() > 0xFFFF) {
        return Error{Errc::overflow, 0, "KAIR: TLVs over 65535 octets"};
    }
    ByteWriter w(kHeaderSize + body.size());
    w.u16(kMagic);
    w.u8(kVersion);
    w.u8(static_cast<std::uint8_t>(f.type));
    w.u16(f.flags);
    w.u16(static_cast<std::uint16_t>(body.size()));
    w.u32(f.cell_handle);
    w.u32(f.radio_id);
    w.u64(f.tx_time_ns);
    w.u32(f.sfn_slot);
    w.u16(f.rnti);
    w.u16(f.seq);
    w.bytes(body.data());
    return std::move(w).take();
}

} // namespace ksim::air
