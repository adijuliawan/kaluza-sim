// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// SecretBytes behaviour. The type's printing ban is a compile-time property:
// the static_asserts below fail the build if a stream or string conversion
// ever appears.

#include <gtest/gtest.h>

#include <ostream>
#include <string>
#include <type_traits>
#include <utility>

#include "platform/secret.hpp"

using namespace ksim;

namespace {

template <class T, class = void>
struct streamable : std::false_type {};
template <class T>
struct streamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

// Milenage test set 1 K (3GPP TS 35.208 §4.3): public test data, not a real key.
constexpr const char* kTestK = "465b5ce8b199b49faa5f0a2ee238a6bc";

} // namespace

static_assert(!std::is_copy_constructible_v<SecretBytes>);
static_assert(!std::is_copy_assignable_v<SecretBytes>);
static_assert(std::is_nothrow_move_constructible_v<SecretBytes>);
static_assert(!streamable<SecretBytes>::value, "SecretBytes must not be printable");
static_assert(!std::is_convertible_v<SecretBytes, ByteView>);
static_assert(!std::is_convertible_v<SecretBytes, std::string>);

TEST(SecretBytes, FromHexAndConstantTimeCompare) {
    auto k = SecretBytes::from_hex(kTestK);
    ASSERT_TRUE(k);
    EXPECT_EQ(k->size(), 16U);
    auto again = SecretBytes::from_hex(kTestK);
    EXPECT_TRUE(ct_equal(*k, *again));
    auto other = SecretBytes::from_hex("00000000000000000000000000000000");
    EXPECT_FALSE(ct_equal(*k, *other));
    EXPECT_FALSE(ct_equal(*k, SecretBytes(15)));
}

TEST(SecretBytes, RedactedNeverShowsTheBytes) {
    auto k = SecretBytes::from_hex(kTestK);
    const std::string r = k->redacted();
    EXPECT_EQ(r.find("465b5c"), std::string::npos);
    EXPECT_EQ(r.rfind("<redacted:len=16:fpr=", 0), 0U);
    EXPECT_EQ(r, k->redacted()) << "stable within a process";
    EXPECT_NE(r, SecretBytes(16).redacted());
}

TEST(SecretBytes, MoveLeavesTheSourceEmpty) {
    auto k = SecretBytes::from_hex(kTestK);
    SecretBytes moved = std::move(*k);
    EXPECT_EQ(moved.size(), 16U);
    EXPECT_TRUE(k->empty());  // NOLINT(bugprone-use-after-move): checking the moved-from state
    SecretBytes c = moved.clone();
    EXPECT_TRUE(ct_equal(c, moved));
}

TEST(SecretBytes, ExposeMutFillsDerivedKeys) {
    SecretBytes s(4);
    auto m = s.expose_mut();
    for (std::size_t i = 0; i < m.size(); ++i) {
        m[i] = static_cast<std::uint8_t>(i + 1);
    }
    const Bytes want = {1, 2, 3, 4};
    EXPECT_TRUE(ct_equal(s, want));
}
