// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Result<T>: a value or an Error, for code that must not throw on bad input
// (every decoder: "no network input may end a sim process", requirements.md
// §3.1 L15). C++20 has no std::expected, so this is a small equivalent.
//
// Error carries a code, the byte (or bit) offset where decoding stopped, and a
// static description. `what` must point at a string literal: errors are cheap
// to create and never allocate.

#pragma once

#include <cassert>
#include <cstdint>
#include <type_traits>
#include <utility>
#include <variant>

namespace ksim {

enum class Errc : std::uint16_t {
    truncated = 1,     // input ended before the structure did
    malformed,         // the bytes violate the syntax
    out_of_range,      // a field holds a value outside its allowed range
    unsupported,       // valid, but not implemented (declared as a -G row)
    overflow,          // an output or counter would overflow
    invalid_argument,  // a caller passed something unusable
    internal,          // a bug: an invariant did not hold
};

const char* errc_name(Errc c) noexcept;

struct Error {
    Errc code;
    std::uint32_t offset = 0;      // where it went wrong: byte offset unless the API says bits
    const char* what = "";         // static string literal, never owned
};

template <class T>
class [[nodiscard]] Result {
    static_assert(!std::is_same_v<T, Error>, "Result<Error> is ambiguous");

public:
    Result(const T& v) : v_(v) {}                       // NOLINT(google-explicit-constructor)
    Result(T&& v) : v_(std::move(v)) {}                 // NOLINT(google-explicit-constructor)
    Result(Error e) : v_(e) {}                          // NOLINT(google-explicit-constructor)

    bool has_value() const noexcept { return v_.index() == 0; }
    explicit operator bool() const noexcept { return has_value(); }

    T& value() & {
        assert(has_value());
        return std::get<0>(v_);
    }
    const T& value() const& {
        assert(has_value());
        return std::get<0>(v_);
    }
    T&& value() && {
        assert(has_value());
        return std::get<0>(std::move(v_));
    }
    T& operator*() & { return value(); }
    const T& operator*() const& { return value(); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

    const Error& error() const& {
        assert(!has_value());
        return std::get<1>(v_);
    }

    template <class U>
    T value_or(U&& fallback) const& {
        return has_value() ? std::get<0>(v_) : static_cast<T>(std::forward<U>(fallback));
    }

private:
    std::variant<T, Error> v_;
};

template <>
class [[nodiscard]] Result<void> {
public:
    Result() = default;
    Result(Error e) : err_(e), ok_(false) {}  // NOLINT(google-explicit-constructor)

    bool has_value() const noexcept { return ok_; }
    explicit operator bool() const noexcept { return ok_; }
    const Error& error() const {
        assert(!ok_);
        return err_;
    }

private:
    Error err_{Errc::internal, 0, ""};
    bool ok_ = true;
};

inline Error make_error(Errc code, std::uint32_t offset, const char* what) noexcept {
    return Error{code, offset, what};
}

} // namespace ksim
