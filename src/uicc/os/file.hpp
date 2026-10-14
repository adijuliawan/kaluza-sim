// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The card's file system (P1 N3; ETSI TS 102 221 §8; sim-uicc.md §2): MF, DFs,
// ADFs and EFs (transparent, linear fixed, cyclic), each with its FCP
// attributes. A file whose contents are key material (EF.USIM_AUTH_KEY, AF20)
// holds them as SecretBytes and is never read out (rule of §3.6).

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "platform/buf.hpp"
#include "platform/secret.hpp"

namespace ksim::uicc::os {

enum class Kind : std::uint8_t { mf, df, adf, transparent, linear_fixed, cyclic };

inline bool is_df(Kind k) noexcept { return k == Kind::mf || k == Kind::df || k == Kind::adf; }
inline bool is_record(Kind k) noexcept { return k == Kind::linear_fixed || k == Kind::cyclic; }

/// The FCP's security attributes in the referenced expanded format (tag '8B',
/// TS 102 221 §11.1.1.4.7.3): the EF.ARR's file id and a record of it.
struct ArrRef {
    std::uint16_t fid = 0;   // 0: none (no access rule: everything allowed)
    std::uint8_t record = 0;
};

/// Life cycle status (TS 102 221 §11.1.1.4.9).
inline constexpr std::uint8_t kLcsActivated = 0x05;
inline constexpr std::uint8_t kLcsDeactivated = 0x04;

struct File {
    Kind kind = Kind::transparent;
    std::uint16_t fid = 0;
    std::string name;                     // "EF.IMSI": for people and logs
    Bytes aid;                            // an ADF's DF name (tag '84')
    std::optional<std::uint8_t> sfi;      // a short file identifier, 1..30
    std::uint8_t lcs = kLcsActivated;
    ArrRef arr;

    // An EF's contents.
    Bytes data;                           // transparent
    std::vector<Bytes> records;           // record files; for a cyclic EF records[0] is record 1, the newest
    std::uint16_t record_len = 0;
    bool secret = false;                  // key material: data lives in secret_data
    SecretBytes secret_data;

    File* parent = nullptr;
    std::vector<std::unique_ptr<File>> children;

    File* child(std::uint16_t id) const noexcept {
        for (const auto& c : children) {
            if (c->fid == id) {
                return c.get();
            }
        }
        return nullptr;
    }
    File* child_by_sfi(std::uint8_t s) const noexcept {
        for (const auto& c : children) {
            if (!is_df(c->kind) && c->sfi && *c->sfi == s) {
                return c.get();
            }
        }
        return nullptr;
    }
    File& add(std::unique_ptr<File> f) {
        f->parent = this;
        children.push_back(std::move(f));
        return *children.back();
    }
    /// A transparent EF's size; a record file's total size.
    std::size_t size() const noexcept {
        if (is_record(kind)) {
            return static_cast<std::size_t>(record_len) * records.size();
        }
        return secret ? secret_data.size() : data.size();
    }
    /// The DF this file is in (itself for a DF).
    File* df() noexcept { return is_df(kind) ? this : parent; }
};

} // namespace ksim::uicc::os
