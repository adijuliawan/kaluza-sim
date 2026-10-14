// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Reads spec/kat/<name>.tsv (spec/tools/kat_extract.py): one row per
// (set, field) with the value in hex, its length in bits, or a text value.

#pragma once

#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "platform/buf.hpp"
#include "platform/secret.hpp"

namespace ksim::kat {

struct Field {
    std::string hex;
    std::string bits;
    std::string text;
};

class Set {
public:
    std::map<std::string, Field> fields;

    bool has(const std::string& f) const { return fields.count(f) != 0; }

    const Field& at(const std::string& f) const {
        auto it = fields.find(f);
        if (it == fields.end()) {
            ADD_FAILURE() << "KAT field missing: " << f;
            static const Field empty;
            return empty;
        }
        return it->second;
    }
    std::string hex(const std::string& f) const { return at(f).hex; }
    std::string text(const std::string& f) const { return at(f).text; }
    Bytes bytes(const std::string& f) const {
        std::string h = hex(f);
        if (h.size() % 2 != 0) {
            h += '0';  // a value with an odd number of hex digits is left-aligned
        }
        auto r = from_hex(h);
        return r ? *r : Bytes{};
    }
    SecretBytes secret(const std::string& f) const { return SecretBytes::copy_of(bytes(f)); }
    /// A number: a parameter row (hex, no bit length) or a right-aligned field.
    std::uint64_t num(const std::string& f) const { return std::stoull(hex(f), nullptr, 16); }
};

/// set name -> set, in file order of first appearance.
inline std::vector<std::pair<std::string, Set>> load(const std::string& name) {
    std::ifstream in(std::string(KSIM_SOURCE_DIR) + "/spec/kat/" + name + ".tsv");
    std::vector<std::pair<std::string, Set>> out;
    std::map<std::string, std::size_t> index;
    std::string line;
    bool header = false;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (!header) {
            header = true;  // set field hex bits text clause
            continue;
        }
        std::vector<std::string> col;
        std::stringstream ss(line);
        std::string c;
        while (std::getline(ss, c, '\t')) {
            col.push_back(c);
        }
        col.resize(6);
        auto [it, fresh] = index.emplace(col[0], out.size());
        if (fresh) {
            out.emplace_back(col[0], Set{});
        }
        out[it->second].second.fields[col[1]] = Field{col[2], col[3], col[4]};
    }
    return out;
}

/// The first `bits` bits of v, the rest of the last octet zeroed.
inline Bytes first_bits(Bytes v, std::size_t bits) {
    v.resize((bits + 7) / 8);
    if (bits % 8 != 0 && !v.empty()) {
        v.back() &= static_cast<std::uint8_t>(0xFF00U >> (bits % 8));
    }
    return v;
}

inline std::string hx(const SecretBytes& s) {
    return to_hex(s.expose());
}

} // namespace ksim::kat
