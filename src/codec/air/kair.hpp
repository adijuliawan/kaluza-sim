// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// KAIR v1, the simulated Uu link (P1 N6; architecture.md §2.3, ADR 0003): a
// 32-octet header in network byte order, then TLVs {u8 type, u16 length,
// value}.
//
//   0  u16 magic 0x4B41 'KA' | 2 u8 version 1 | 3 u8 frame type | 4 u16 flags
//   6  u16 TLV length        | 8 u32 cell_handle | 12 u32 radio_id
//   16 u64 tx_time_ns        | 24 u32 sfn_slot (SFN << 8 | slot)
//   28 u16 rnti              | 30 u16 seq
//
// KAIR is kaluza-sim's own framing, not a 3GPP protocol: what it carries (RRC
// messages, PDCP PDUs as RLC SDUs) is real, while RLC and MAC are an ideal
// link (abstraction ledger). decode() checks the header and that each frame
// type carries the TLVs it needs; a TLV of a type this version does not know
// is skipped, so a later version can add some.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::air {

inline constexpr std::uint16_t kMagic = 0x4B41;
inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::size_t kHeaderSize = 32;

enum class FrameType : std::uint8_t {
    cell_announce = 1,   // DU -> farm: a cell, its identity and carrier
    subscribe = 2,       // farm -> DU: deliver this cell's broadcast and paging
    bch = 3,             // the MIB (BCCH-BCH)
    si = 4,              // SIB1 or an SI message (BCCH-DL-SCH)
    pcch = 5,            // a Paging message with its paging frame and occasion
    prach = 6,           // a random access preamble
    rar = 7,             // the random access response (header rnti = RA-RNTI)
    msg3 = 8,            // a UL-CCCH SDU, or a C-RNTI MAC CE and DCCH
    msg4 = 9,            // the contention resolution identity and a DL-CCCH SDU
    dl_sdu = 10,         // RLC SDUs per LCID, downlink
    ul_sdu = 11,         // RLC SDUs per LCID, uplink
    mac_ce = 12,
    keepalive = 13,
};
const char* frame_type_name(FrameType t) noexcept;

enum class RlcMode : std::uint8_t { tm = 0, um = 1, am = 2 };

enum class TlvType : std::uint8_t {
    sdu = 0x01,              // u8 LCID, u8 RLC mode, the SDU
    mac_ce = 0x02,           // u8 LCID of the CE (TS 38.321 Table 6.2.1-2), its octets
    scene = 0x03,            // u32 the radio scene version
    cell = 0x10,             // u64 NCI (36 bits), u16 PCI, u32 ARFCN, 3 octets PLMN, u24 TAC
    prach = 0x11,            // u8 preamble, u8 s_id, u8 t_id, u8 f_id, u8 ul_carrier_id
    rar = 0x12,              // u8 RAPID, u16 TC-RNTI, u8 backoff index, u16 timing advance
    contention_id = 0x13,    // the first 48 bits of the UL-CCCH SDU (TS 38.321 §6.1.3.4)
    paging = 0x14,           // u16 the paging frame's SFN, u8 i_s, u8 flags (bit 0: SI change)
};

struct Sdu {
    std::uint8_t lcid = 0;
    RlcMode mode = RlcMode::am;
    Bytes data;
    friend bool operator==(const Sdu&, const Sdu&) = default;
};

struct MacCe {
    std::uint8_t lcid = 0;
    Bytes data;
    friend bool operator==(const MacCe&, const MacCe&) = default;
};

struct CellInfo {
    std::uint64_t nci = 0;    // 36 bits
    std::uint16_t pci = 0;    // 0..1007
    std::uint32_t arfcn = 0;  // NR-ARFCN of the SSB
    std::array<std::uint8_t, 3> plmn{};   // TS 24.008 coding, as in NAS
    std::uint32_t tac = 0;    // 24 bits
    friend bool operator==(const CellInfo&, const CellInfo&) = default;
};

struct Prach {
    std::uint8_t preamble = 0;     // 0..63
    std::uint8_t s_id = 0;         // first OFDM symbol, 0..13
    std::uint8_t t_id = 0;         // first slot in the frame, 0..79
    std::uint8_t f_id = 0;         // frequency index, 0..7
    std::uint8_t ul_carrier_id = 0;   // 0 NUL, 1 SUL
    /// RA-RNTI = 1 + s_id + 14·t_id + 14·80·f_id + 14·80·8·ul_carrier_id (TS 38.321 §5.1.3).
    std::uint16_t ra_rnti() const noexcept;
    friend bool operator==(const Prach&, const Prach&) = default;
};

struct Rar {
    std::uint8_t rapid = 0;
    std::uint16_t tc_rnti = 0;
    std::uint8_t backoff = 0;   // the backoff indicator's index (TS 38.321 Table 7.2-1)
    std::uint16_t ta = 0;
    friend bool operator==(const Rar&, const Rar&) = default;
};

struct PagingStamp {
    std::uint16_t pf_sfn = 0;
    std::uint8_t i_s = 0;
    bool si_change = false;
    friend bool operator==(const PagingStamp&, const PagingStamp&) = default;
};

struct Frame {
    FrameType type = FrameType::keepalive;
    std::uint16_t flags = 0;
    std::uint32_t cell_handle = 0;
    std::uint32_t radio_id = 0;
    std::uint64_t tx_time_ns = 0;
    std::uint32_t sfn_slot = 0;
    std::uint16_t rnti = 0;
    std::uint16_t seq = 0;

    std::vector<Sdu> sdus;
    std::vector<MacCe> ces;
    std::optional<std::uint32_t> scene;
    std::optional<CellInfo> cell;
    std::optional<Prach> prach;
    std::optional<Rar> rar;
    std::optional<std::array<std::uint8_t, 6>> contention_id;
    std::optional<PagingStamp> paging;

    std::uint16_t sfn() const noexcept { return static_cast<std::uint16_t>(sfn_slot >> 8); }
    std::uint8_t slot() const noexcept { return static_cast<std::uint8_t>(sfn_slot & 0xFF); }
    friend bool operator==(const Frame&, const Frame&) = default;
};

/// The TLVs each frame type requires (and the header rules): Errc::malformed
/// with the offending offset when a frame lacks one.
Result<Frame> decode(ByteView in);
Result<Bytes> encode(const Frame& f);

/// The contention resolution identity of a UL-CCCH SDU: its first 48 bits
/// (TS 38.321 §5.1.5), zero-padded if the SDU is shorter.
std::array<std::uint8_t, 6> contention_id_of(ByteView ccch_sdu) noexcept;

} // namespace ksim::air
