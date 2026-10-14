// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/up/frames.hpp"

#include <algorithm>
#include <array>

namespace ksim::up {

namespace {

constexpr std::uint8_t A = FieldSpec::kAlways;

// TS 38.415 figure 5.5.2.1-1. Octet 1: PDU type, QMP (3), SNP (2), MSNP (1).
// Octet 2: PPP (7), RQI (6), QFI. The octet after them, present when PPP is
// set, holds PPI and the BSSI (1) and TTNBI (0) flags (KS-UP-S1).
constexpr std::array kPscDl = {
    FieldSpec{"PPI octet", 1, 7, 1, 0, true},
    FieldSpec{"DL Sending Time Stamp", 0, 3, 8},
    FieldSpec{"DL QFI Sequence Number", 0, 2, 3},
    FieldSpec{"DL MBS QFI Sequence Number", 0, 1, 4},
    FieldSpec{"BSSize", 2, 1, 3},
    FieldSpec{"TTNB", 2, 0, 2},
};

// TS 38.415 figure 5.5.2.2-1. Octet 1: PDU type, QMP (3), DL Delay Ind (2), UL
// Delay Ind (1), SNP (0). Octet 2: N3/N9 Delay Ind (7), New IE Flag (6), QFI.
constexpr std::array kPscUl = {
    FieldSpec{"DL Sending Time Stamp Repeated", 0, 3, 8},
    FieldSpec{"DL Received Time Stamp", 0, 3, 8},
    FieldSpec{"UL Sending Time Stamp", 0, 3, 8},
    FieldSpec{"DL Delay Result", 0, 2, 4},
    FieldSpec{"UL Delay Result", 0, 1, 4},
    FieldSpec{"UL QFI Sequence Number", 0, 0, 3},
    FieldSpec{"N3/N9 Delay Result", 1, 7, 4},
    FieldSpec{"New IE Flags", 1, 6, 1, 0, true},
    FieldSpec{"D1 UL PDCP Delay Result Ind", 2, 0, 1},
    FieldSpec{"UL Congestion Information", 2, 1, 2},
    FieldSpec{"DL Congestion Information", 2, 2, 2},
    FieldSpec{"UL Available Bitrate", 2, 3, 4},
    FieldSpec{"DL Available Bitrate", 2, 4, 4},
};

// TS 38.425 figure 5.5.2.1-1. Octet 1: PDU type, spare (3), DL Discard Blocks
// (2), DL Flush (1), Report polling (0). Octet 2: New IE Flag (7), BSSI (6),
// TTNBI (5), Request OutofSeq Report (4), Report Delivered (3), User data
// existence (2), Assistance Info. Report Polling (1), Retransmission (0).
constexpr std::array kNruDlUserData = {
    FieldSpec{"NR-U Sequence Number", A, 0, 3},
    FieldSpec{"DL discard NR PDCP PDU SN", 0, 1, 3},
    FieldSpec{"DL discard Number of blocks", 0, 2, 1, 4},   // blocks: SN start (3), block size (1)
    FieldSpec{"DL report NR PDCP PDU SN", 1, 3, 3},
    FieldSpec{"BSSize", 1, 6, 3},
    FieldSpec{"TTNB", 1, 5, 2},
    FieldSpec{"New IE Flags", 1, 7, 1, 0, true},
    FieldSpec{"DL retransmission NR PDCP PDU SN", 2, 0, 3},
    FieldSpec{"DL retransmission Number of blocks", 2, 1, 1, 4},
    FieldSpec{"DL Remaining Time based Polling Indicator", 2, 2, 1},
};

// TS 38.425 figure 5.5.2.2-1. Octet 1: PDU type, Highest Transmitted NR PDCP SN
// Ind (3), Highest Delivered NR PDCP SN Ind (2), Final Frame Ind (1), Lost
// Packet Report (0). Octet 2: spare (7), Feedback Delay Ind (6), NR-U SN Ind
// (5), Delivered NR PDCP SN Range Ind (4), Data rate Ind (3), Retransmitted NR
// PDCP SN Ind (2), Delivered Retransmitted NR PDCP SN Ind (1), Cause Report (0).
constexpr std::array kNruDdds = {
    FieldSpec{"Desired buffer size for the data radio bearer", A, 0, 4},
    FieldSpec{"Desired Data Rate", 1, 3, 4},
    FieldSpec{"Number of lost NR-U Sequence Number ranges reported", 0, 0, 1, 6},   // start (3), end (3)
    FieldSpec{"Highest successfully delivered NR PDCP Sequence Number", 0, 2, 3},
    FieldSpec{"Highest transmitted NR PDCP Sequence Number", 0, 3, 3},
    FieldSpec{"Cause Value", 1, 0, 1},
    FieldSpec{"Successfully delivered retransmitted NR PDCP Sequence Number", 1, 1, 3},
    FieldSpec{"Retransmitted NR PDCP Sequence Number", 1, 2, 3},
    FieldSpec{"Number of successfully delivered out of sequence PDCP Sequence Number range", 1, 4, 1, 6},
    FieldSpec{"NR-U Sequence Number of Polling Frame", 1, 5, 3},
    FieldSpec{"Feedback Delay Result", 1, 6, 4},
};

constexpr std::array kFrames = {
    FrameSpec{Protocol::psc, 0, "DL PDU SESSION INFORMATION", kPscDl},
    FrameSpec{Protocol::psc, 1, "UL PDU SESSION INFORMATION", kPscUl},
    FrameSpec{Protocol::nru, 0, "DL USER DATA", kNruDlUserData},
    FrameSpec{Protocol::nru, 1, "DL DATA DELIVERY STATUS", kNruDdds},
};

Error err(Errc c, std::size_t off, const char* what) {
    return make_error(c, static_cast<std::uint32_t>(off), what);
}

bool present(const FieldSpec& fs, const std::vector<std::uint8_t>& flags) {
    if (fs.flag_octet == FieldSpec::kAlways) {
        return true;
    }
    return fs.flag_octet < flags.size() && ((flags[fs.flag_octet] >> fs.flag_bit) & 1U) != 0;
}

std::uint64_t number(ByteView b) {
    std::uint64_t v = 0;
    for (std::uint8_t o : b) {
        v = (v << 8) | o;
    }
    return v;
}

const FieldSpec* field_spec(const FrameSpec& s, std::string_view name) {
    for (const FieldSpec& fs : s.fields) {
        if (name == fs.name) {
            return &fs;
        }
    }
    return nullptr;
}

/// Make flag octet `idx` exist, setting the bit that announces it.
Result<void> ensure_flag_octet(Frame& f, std::uint8_t idx) {
    if (idx < f.flags.size()) {
        return {};
    }
    std::uint8_t k = 2;
    for (const FieldSpec& fs : f.spec->fields) {
        if (!fs.flags) {
            continue;
        }
        if (k == idx) {
            if (auto ok = ensure_flag_octet(f, fs.flag_octet); !ok) {
                return ok.error();
            }
            f.flags[fs.flag_octet] |= static_cast<std::uint8_t>(1U << fs.flag_bit);
            if (idx != f.flags.size()) {
                return err(Errc::invalid_argument, 0, "frame: flag octets out of order");
            }
            f.flags.push_back(0);
            return {};
        }
        ++k;
    }
    return err(Errc::invalid_argument, 0, "frame: no such flag octet");
}

} // namespace

const FrameSpec* find_frame(Protocol p, std::uint8_t pdu_type) noexcept {
    for (const FrameSpec& s : kFrames) {
        if (s.protocol == p && s.pdu_type == pdu_type) {
            return &s;
        }
    }
    return nullptr;
}

const Field* Frame::find(std::string_view name) const noexcept {
    for (const Field& f : fields) {
        if (name == f.spec->name) {
            return &f;
        }
    }
    return nullptr;
}

std::optional<std::uint64_t> Frame::value(std::string_view name) const noexcept {
    const Field* f = find(name);
    if (f == nullptr || f->spec->block != 0 || f->octets.size() > 8) {
        return std::nullopt;
    }
    return number(f->octets);
}

Result<Frame> decode(Protocol p, ByteView in) {
    if (in.size() < 2) {
        return err(Errc::truncated, in.size(), "frame: shorter than its two flag octets");
    }
    Frame f;
    f.spec = find_frame(p, static_cast<std::uint8_t>(in[0] >> 4));
    if (f.spec == nullptr) {
        return err(Errc::unsupported, 0, "frame: PDU type not in P0's tables");
    }
    f.flags = {in[0], in[1]};
    std::size_t pos = 2;
    for (const FieldSpec& fs : f.spec->fields) {
        if (!present(fs, f.flags)) {
            continue;
        }
        if (pos + fs.size > in.size()) {
            return err(Errc::truncated, pos, fs.name);
        }
        std::size_t len = fs.size;
        if (fs.block != 0) {
            len += static_cast<std::size_t>(number(in.subspan(pos, fs.size))) * fs.block;
            if (pos + len > in.size()) {
                return err(Errc::truncated, pos, fs.name);
            }
        }
        if (fs.flags) {
            f.flags.push_back(in[pos]);
        } else {
            f.fields.push_back({&fs, Bytes(in.begin() + static_cast<std::ptrdiff_t>(pos),
                                          in.begin() + static_cast<std::ptrdiff_t>(pos + len)), pos});
        }
        pos += len;
    }
    f.tail = Bytes(in.begin() + static_cast<std::ptrdiff_t>(pos), in.end());
    return f;
}

Result<Bytes> encode(const Frame& f) {
    if (f.spec == nullptr || f.flags.size() < 2) {
        return err(Errc::invalid_argument, 0, "frame: no layout or flag octets");
    }
    if ((f.flags[0] >> 4) != f.spec->pdu_type) {
        return err(Errc::invalid_argument, 0, "frame: octet 1 does not carry the PDU type");
    }
    ByteWriter w(32);
    w.u8(f.flags[0]);
    w.u8(f.flags[1]);
    std::size_t next_flags = 2;
    std::size_t used = 0;
    for (const FieldSpec& fs : f.spec->fields) {
        if (!present(fs, f.flags)) {
            continue;
        }
        if (fs.flags) {
            if (next_flags >= f.flags.size()) {
                return err(Errc::invalid_argument, w.size(), "frame: a flag announces a flag octet that is missing");
            }
            w.u8(f.flags[next_flags++]);
            continue;
        }
        const auto it = std::find_if(f.fields.begin(), f.fields.end(), [&](const Field& x) { return x.spec == &fs; });
        if (it == f.fields.end()) {
            return err(Errc::invalid_argument, w.size(), fs.name);   // its flag is set, the field is missing
        }
        const std::size_t want = fs.block == 0 ? fs.size
                                               : fs.size + static_cast<std::size_t>(number(ByteView(it->octets).first(
                                                               std::min<std::size_t>(fs.size, it->octets.size())))) *
                                                               fs.block;
        if (it->octets.size() != want) {
            return err(Errc::invalid_argument, w.size(), fs.name);   // its octets do not fit its size
        }
        w.bytes(it->octets);
        ++used;
    }
    if (used != f.fields.size()) {
        return err(Errc::invalid_argument, w.size(), "frame: a field whose flag is not set");
    }
    if (f.tail) {
        w.bytes(*f.tail);
    } else {
        for (std::size_t pad = (4 - (w.size() + 2) % 4) % 4; pad > 0; --pad) {
            w.u8(0);
        }
    }
    return std::move(w).take();
}

Result<Frame> make(Protocol p, std::uint8_t pdu_type) {
    Frame f;
    f.spec = find_frame(p, pdu_type);
    if (f.spec == nullptr) {
        return err(Errc::unsupported, 0, "frame: PDU type not in P0's tables");
    }
    f.flags = {static_cast<std::uint8_t>(pdu_type << 4), 0};
    return f;
}

Result<void> set_flag(Frame& f, std::uint8_t octet, std::uint8_t bit, bool on) {
    if (bit > 7 || (octet == 0 && bit > 3)) {
        return err(Errc::invalid_argument, 0, "frame: no such flag bit");
    }
    if (auto ok = ensure_flag_octet(f, octet); !ok) {
        return ok.error();
    }
    const auto mask = static_cast<std::uint8_t>(1U << bit);
    f.flags[octet] = on ? static_cast<std::uint8_t>(f.flags[octet] | mask)
                        : static_cast<std::uint8_t>(f.flags[octet] & ~mask);
    return {};
}

namespace {
Result<void> put(Frame& f, const FieldSpec& fs, Bytes octets) {
    if (fs.flag_octet != FieldSpec::kAlways) {
        if (auto ok = set_flag(f, fs.flag_octet, fs.flag_bit); !ok) {
            return ok.error();
        }
    }
    const auto order = [&](const FieldSpec* s) { return s - f.spec->fields.data(); };
    auto it = std::find_if(f.fields.begin(), f.fields.end(), [&](const Field& x) { return order(x.spec) >= order(&fs); });
    if (it != f.fields.end() && it->spec == &fs) {
        it->octets = std::move(octets);
    } else {
        f.fields.insert(it, Field{&fs, std::move(octets), 0});
    }
    return {};
}
} // namespace

Result<void> set(Frame& f, std::string_view name, std::uint64_t value) {
    const FieldSpec* fs = f.spec != nullptr ? field_spec(*f.spec, name) : nullptr;
    if (fs == nullptr || fs->flags || fs->block != 0) {
        return err(Errc::invalid_argument, 0, "frame: no such numeric field");
    }
    if (fs->size < 8 && (value >> (8 * fs->size)) != 0) {
        return err(Errc::out_of_range, 0, "frame: value wider than its field");
    }
    Bytes octets(fs->size);
    for (std::size_t i = 0; i < fs->size; ++i) {
        octets[fs->size - 1 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
    return put(f, *fs, std::move(octets));
}

Result<void> set_blocks(Frame& f, std::string_view name, ByteView blocks) {
    const FieldSpec* fs = f.spec != nullptr ? field_spec(*f.spec, name) : nullptr;
    if (fs == nullptr || fs->block == 0) {
        return err(Errc::invalid_argument, 0, "frame: no such block list");
    }
    if (blocks.size() % fs->block != 0 || blocks.size() / fs->block > 0xFF) {
        return err(Errc::invalid_argument, 0, "frame: blocks are not whole or too many");
    }
    Bytes octets{static_cast<std::uint8_t>(blocks.size() / fs->block)};
    octets.insert(octets.end(), blocks.begin(), blocks.end());
    return put(f, *fs, std::move(octets));
}

std::string to_json(const Frame& f) {
    std::string s = std::string("{\"protocol\":\"") + (f.spec->protocol == Protocol::psc ? "psc" : "nru") +
                    "\",\"frame\":\"" + f.spec->name + "\",\"pdu_type\":" + std::to_string(f.spec->pdu_type) +
                    ",\"flags\":[";
    for (std::size_t i = 0; i < f.flags.size(); ++i) {
        s += (i != 0 ? "," : "") + std::to_string(f.flags[i]);
    }
    s += "],\"fields\":[";
    for (std::size_t i = 0; i < f.fields.size(); ++i) {
        s += (i != 0 ? "," : "") + std::string("{\"name\":\"") + f.fields[i].spec->name + "\",\"hex\":\"" +
             to_hex(f.fields[i].octets) + "\",\"at\":" + std::to_string(f.fields[i].offset) + "}";
    }
    s += "],\"tail\":\"" + (f.tail ? to_hex(*f.tail) : std::string()) + "\"}";
    return s;
}

} // namespace ksim::up
