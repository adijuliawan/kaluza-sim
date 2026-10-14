// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/yaml.hpp"

#include <charconv>
#include <cstdint>
#include <limits>
#include <type_traits>

#include <yaml-cpp/yaml.h>

namespace ksim {

struct Yaml::Impl {
    YAML::Node node;
    std::shared_ptr<const std::string> name;   // the file name or "<text>"
};

namespace {

std::string mark_text(const std::string& name, const YAML::Mark& m) {
    if (m.is_null()) {
        return name;
    }
    return name + ":" + std::to_string(m.line + 1) + ":" + std::to_string(m.column + 1);
}

std::string join(const std::string& path, std::string_view key) {
    return path.empty() ? std::string(key) : path + "." + std::string(key);
}

template <class T>
bool parse_int(std::string_view s, T& out) {
    bool neg = false;
    std::string_view digits = s;
    if (!digits.empty() && (digits.front() == '-' || digits.front() == '+')) {
        neg = digits.front() == '-';
        digits.remove_prefix(1);
    }
    int base = 10;
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.remove_prefix(2);
    }
    if (digits.empty()) {
        return false;
    }
    std::uint64_t mag = 0;
    const auto [p, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), mag, base);
    if (ec != std::errc{} || p != digits.data() + digits.size()) {
        return false;
    }
    if constexpr (std::is_signed_v<T>) {
        const auto max = static_cast<std::uint64_t>(std::numeric_limits<T>::max());
        if (neg) {
            if (mag > max + 1) {
                return false;
            }
            out = mag == max + 1 ? std::numeric_limits<T>::min() : static_cast<T>(-static_cast<T>(mag));
        } else {
            if (mag > max) {
                return false;
            }
            out = static_cast<T>(mag);
        }
    } else {
        if (neg && mag != 0) {
            return false;
        }
        if (mag > static_cast<std::uint64_t>(std::numeric_limits<T>::max())) {
            return false;
        }
        out = static_cast<T>(mag);
    }
    return true;
}

} // namespace

YamlError::YamlError(std::string where, std::string path, const std::string& message)
    : std::runtime_error(where + ": " + (path.empty() ? std::string() : path + ": ") + message),
      where_(std::move(where)), path_(std::move(path)) {}

Yaml::Yaml(std::shared_ptr<const Impl> impl, std::string path) : impl_(std::move(impl)), path_(std::move(path)) {}

Yaml Yaml::load_file(const std::string& file) {
    try {
        return Yaml(std::make_shared<const Impl>(Impl{YAML::LoadFile(file), std::make_shared<const std::string>(file)}),
                    "");
    } catch (const YAML::BadFile&) {
        throw YamlError(file, "", "cannot be read");
    } catch (const YAML::Exception& e) {
        throw YamlError(mark_text(file, e.mark), "", e.msg);
    }
}

Yaml Yaml::parse(std::string_view text, std::string name) {
    try {
        return Yaml(std::make_shared<const Impl>(
                        Impl{YAML::Load(std::string(text)), std::make_shared<const std::string>(std::move(name))}),
                    "");
    } catch (const YAML::Exception& e) {
        throw YamlError(mark_text(name, e.mark), "", e.msg);
    }
}

bool Yaml::is_map() const { return impl_->node.IsMap(); }
bool Yaml::is_seq() const { return impl_->node.IsSequence(); }
bool Yaml::is_scalar() const { return impl_->node.IsScalar(); }
bool Yaml::is_null() const { return !impl_->node.IsDefined() || impl_->node.IsNull(); }
std::size_t Yaml::size() const { return impl_->node.IsMap() || impl_->node.IsSequence() ? impl_->node.size() : 0; }

std::string Yaml::where() const { return mark_text(*impl_->name, impl_->node.Mark()); }

void Yaml::fail(const std::string& message) const { throw YamlError(where(), path_, message); }

bool Yaml::has(std::string_view key) const {
    if (!impl_->node.IsMap()) {
        return false;
    }
    for (const auto& kv : impl_->node) {
        if (kv.first.IsScalar() && kv.first.Scalar() == key) {
            return true;
        }
    }
    return false;
}

Yaml Yaml::at(std::string_view key) const {
    if (!impl_->node.IsMap()) {
        fail("is not a map (looking for '" + std::string(key) + "')");
    }
    for (const auto& kv : impl_->node) {
        if (kv.first.IsScalar() && kv.first.Scalar() == key) {
            return Yaml(std::make_shared<const Impl>(Impl{kv.second, impl_->name}), join(path_, key));
        }
    }
    fail("has no key '" + std::string(key) + "'");
}

Yaml Yaml::at(std::size_t i) const {
    if (!impl_->node.IsSequence()) {
        fail("is not a sequence");
    }
    if (i >= impl_->node.size()) {
        fail("has no element " + std::to_string(i) + " (size " + std::to_string(impl_->node.size()) + ")");
    }
    return Yaml(std::make_shared<const Impl>(Impl{impl_->node[i], impl_->name}), path_ + "[" + std::to_string(i) + "]");
}

std::vector<std::string> Yaml::keys() const {
    std::vector<std::string> out;
    if (impl_->node.IsMap()) {
        for (const auto& kv : impl_->node) {
            out.push_back(kv.first.Scalar());
        }
    }
    return out;
}

void Yaml::only(std::initializer_list<std::string_view> allowed) const {
    if (!impl_->node.IsMap()) {
        fail("is not a map");
    }
    for (const auto& kv : impl_->node) {
        const std::string& k = kv.first.Scalar();
        bool ok = false;
        for (std::string_view a : allowed) {
            ok = ok || a == k;
        }
        if (!ok) {
            Yaml(std::make_shared<const Impl>(Impl{kv.first, impl_->name}), join(path_, k)).fail("is not a known key");
        }
    }
}

template <>
std::string Yaml::as<std::string>() const {
    if (!impl_->node.IsScalar()) {
        fail("is not a scalar");
    }
    return impl_->node.Scalar();
}

template <>
bool Yaml::as<bool>() const {
    const std::string s = as<std::string>();
    if (s == "true") {
        return true;
    }
    if (s == "false") {
        return false;
    }
    fail("'" + s + "' is not true or false");
}

template <>
double Yaml::as<double>() const {
    const std::string s = as<std::string>();
    double v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size()) {
        fail("'" + s + "' is not a number");
    }
    return v;
}

#define KSIM_YAML_INT(T)                                                         \
    template <>                                                                  \
    T Yaml::as<T>() const {                                                      \
        const std::string s = as<std::string>();                                 \
        T v{};                                                                   \
        if (!parse_int<T>(s, v)) {                                               \
            fail("'" + s + "' is not an integer in the range of " #T);           \
        }                                                                        \
        return v;                                                                \
    }
KSIM_YAML_INT(std::int64_t)
KSIM_YAML_INT(std::uint64_t)
KSIM_YAML_INT(std::int32_t)
KSIM_YAML_INT(std::uint32_t)
KSIM_YAML_INT(std::uint16_t)
KSIM_YAML_INT(std::uint8_t)
#undef KSIM_YAML_INT

} // namespace ksim
