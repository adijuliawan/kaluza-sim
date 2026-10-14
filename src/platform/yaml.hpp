// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Reading YAML configuration (topologies, personas, card images, core profiles;
// P1 N1) over yaml-cpp. Every error names where it is, as file:line:column and
// a path like `ues[2].persona`, so a bad topology says which line to fix.
// Integers accept decimal and 0x hex (gNB ids, TACs), with range checks;
// booleans are only `true` and `false`. A map can be checked for unknown keys,
// so a misspelt key is an error, not a silent default.

#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ksim {

class YamlError : public std::runtime_error {
public:
    YamlError(std::string where, std::string path, const std::string& message);
    const std::string& where() const noexcept { return where_; }
    const std::string& path() const noexcept { return path_; }

private:
    std::string where_;
    std::string path_;
};

class Yaml {
public:
    /// Parses a file or a text. Both throw YamlError on a syntax error.
    static Yaml load_file(const std::string& file);
    static Yaml parse(std::string_view text, std::string name = "<text>");

    bool is_map() const;
    bool is_seq() const;
    bool is_scalar() const;
    bool is_null() const;   // absent or null
    std::size_t size() const;

    bool has(std::string_view key) const;
    /// The value at `key` of a map, or element `i` of a sequence. Absent is an error.
    Yaml at(std::string_view key) const;
    Yaml at(std::size_t i) const;
    std::vector<std::string> keys() const;

    /// The scalar as T: std::string, bool, double, or an integer type.
    template <class T>
    T as() const;
    /// The value at `key` as T, or `fallback` when the key is absent or null.
    template <class T>
    T get(std::string_view key, T fallback) const {
        return has(key) && !at(key).is_null() ? at(key).as<T>() : std::move(fallback);
    }

    /// Fails when the map holds a key not in `allowed`.
    void only(std::initializer_list<std::string_view> allowed) const;
    /// An error naming this node, for checks the caller makes itself.
    [[noreturn]] void fail(const std::string& message) const;

    const std::string& path() const noexcept { return path_; }
    /// "file:line:column" of this node (line and column 1-based).
    std::string where() const;

private:
    struct Impl;
    Yaml(std::shared_ptr<const Impl> impl, std::string path);

    std::shared_ptr<const Impl> impl_;
    std::string path_;
};

// The scalar conversions there are (defined in yaml.cpp).
template <> std::string Yaml::as<std::string>() const;
template <> bool Yaml::as<bool>() const;
template <> double Yaml::as<double>() const;
template <> std::int64_t Yaml::as<std::int64_t>() const;
template <> std::uint64_t Yaml::as<std::uint64_t>() const;
template <> std::int32_t Yaml::as<std::int32_t>() const;
template <> std::uint32_t Yaml::as<std::uint32_t>() const;
template <> std::uint16_t Yaml::as<std::uint16_t>() const;
template <> std::uint8_t Yaml::as<std::uint8_t>() const;

} // namespace ksim
