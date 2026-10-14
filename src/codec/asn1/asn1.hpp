// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The C++ face of the asn1c libraries (plan M10), protocol-agnostic: it sees
// only the runtime's type descriptors, never a protocol's headers.
//
//  - Owned<T>: one decoded or built PDU, freed through its descriptor.
//  - decode() / encode(): aligned PER (NGAP, F1AP, E1AP, XnAP) or unaligned
//    PER (RRC), the basic variant 3GPP uses; a decode must consume the input
//    up to the final octet's padding.
//  - to_jer() / from_jer(): X.697 JSON, for the oracle comparison and the
//    ksim-codec dump.
//  - push_ie(): append one ProtocolIE-Field to an AP IE container, the entry
//    type deduced from the container.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "platform/buf.hpp"
#include "platform/result.hpp"

extern "C" {
#include "asn_SEQUENCE_OF.h"
#include "constr_TYPE.h"
}

namespace ksim::asn1 {

enum class Rules : std::uint8_t {
    aper,  // ALIGNED BASIC-PER (X.691): the AP protocols
    uper,  // UNALIGNED BASIC-PER: RRC
};

/// A PDU owned through its type descriptor. T is the generated C struct
/// (void when the type is known only at run time, as in ksim-codec).
template <class T = void>
class Owned {
public:
    Owned() noexcept = default;
    Owned(const asn_TYPE_descriptor_t& td, T* p) noexcept : td_(&td), p_(p) {}
    /// A zeroed value of the type, to be filled in (typed owners only: the
    /// runtime descriptor does not carry the C struct size for every type).
    static Owned make(const asn_TYPE_descriptor_t& td)
        requires(!std::is_void_v<T>)
    {
        auto* p = static_cast<T*>(std::calloc(1, sizeof(T)));
        if (p == nullptr) {
            throw std::bad_alloc();
        }
        return Owned(td, p);
    }
    Owned(Owned&& o) noexcept : td_(o.td_), p_(std::exchange(o.p_, nullptr)) {}
    Owned& operator=(Owned&& o) noexcept {
        if (this != &o) {
            reset();
            td_ = o.td_;
            p_ = std::exchange(o.p_, nullptr);
        }
        return *this;
    }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
    ~Owned() { reset(); }

    T* get() noexcept { return p_; }
    const T* get() const noexcept { return p_; }
    T* operator->() noexcept { return p_; }
    const T* operator->() const noexcept { return p_; }
    template <class U = T>
        requires(!std::is_void_v<U>)
    U& operator*() noexcept {
        return *p_;
    }
    const asn_TYPE_descriptor_t& type() const noexcept { return *td_; }
    explicit operator bool() const noexcept { return p_ != nullptr; }

    /// Hand over to a type-erased owner.
    Owned<void> erase() && noexcept { return Owned<void>(*td_, std::exchange(p_, nullptr)); }
    /// Take back a typed view; the caller asserts the descriptor matches T.
    template <class U>
    Owned<U> as(const asn_TYPE_descriptor_t& expected) && noexcept {
        if (td_ != &expected) {
            return {};
        }
        return Owned<U>(*td_, static_cast<U*>(std::exchange(p_, nullptr)));
    }

private:
    void reset() noexcept {
        if (p_ != nullptr) {
            free_value(*td_, p_);
            p_ = nullptr;
        }
    }
    static void free_value(const asn_TYPE_descriptor_t& td, void* p) noexcept;

    const asn_TYPE_descriptor_t* td_ = nullptr;
    T* p_ = nullptr;
};

namespace detail {
void free_struct(const asn_TYPE_descriptor_t& td, void* p) noexcept;
} // namespace detail

template <class T>
void Owned<T>::free_value(const asn_TYPE_descriptor_t& td, void* p) noexcept {
    detail::free_struct(td, p);
}

/// Decode a complete encoding. Trailing octets past the final padding are an error.
Result<Owned<>> decode(const asn_TYPE_descriptor_t& td, Rules rules, ByteView in);

/// How strictly encode() checks a value.
///  - strict: asn1c's constraint check first, which admits only the root of an
///    extensible constraint. For values we build: an out-of-root value is a bug.
///  - relay: the PER encoder alone decides. It still refuses a value outside a
///    non-extensible constraint, and writes an extensible one's extension value
///    with the extension bit, as X.691 says. For re-encoding what was received
///    (a peer's newer extension value) and for ksim-codec.
enum class Check : std::uint8_t { strict, relay };

/// Encode a value.
Result<Bytes> encode(const asn_TYPE_descriptor_t& td, const void* value, Rules rules, Check check = Check::strict);
template <class T>
Result<Bytes> encode(const Owned<T>& v, Rules rules, Check check = Check::strict) {
    return encode(v.type(), v.get(), rules, check);
}

/// X.697 JSON, minified (one line) or pretty.
Result<std::string> to_jer(const asn_TYPE_descriptor_t& td, const void* value, bool minified = true);
template <class T>
Result<std::string> to_jer(const Owned<T>& v, bool minified = true) {
    return to_jer(v.type(), v.get(), minified);
}

/// Parse X.697 JSON into a value of the type.
Result<Owned<>> from_jer(const asn_TYPE_descriptor_t& td, std::string_view jer);

/// The constraint check asn1c runs before encoding, with its message.
Result<void> check_constraints(const asn_TYPE_descriptor_t& td, const void* value, std::string* why = nullptr);

/// Append one ProtocolIE-Field to an IE container (a generated struct with an
/// A_SEQUENCE_OF list of entries carrying id, criticality and a value CHOICE).
/// Returns the new entry's value, its `present` already set, for the caller to
/// fill in the matching arm.
template <class Container, class Present>
auto& push_ie(Container& c, long id, long criticality, Present present) {
    using Entry = std::remove_pointer_t<std::remove_reference_t<decltype(*c.list.array)>>;
    auto* e = static_cast<Entry*>(std::calloc(1, sizeof(Entry)));
    if (e == nullptr) {
        throw std::bad_alloc();
    }
    e->id = id;
    e->criticality = criticality;
    e->value.present = present;
    if (asn_sequence_add(&c.list, e) != 0) {
        std::free(e);
        throw std::bad_alloc();
    }
    return e->value;
}

} // namespace ksim::asn1
