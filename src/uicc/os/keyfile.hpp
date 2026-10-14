// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Key files (P1 N3): the only card code that touches key material, so the only
// card OS file on the expose() allowlist. EF.USIM_AUTH_KEY (AF20) and the like
// keep their contents as SecretBytes, written by UPDATE BINARY under ADM1 and
// read only by the USIM's AUTHENTICATE, never by READ BINARY.

#pragma once

#include <cstddef>

#include "platform/buf.hpp"
#include "platform/secret.hpp"
#include "uicc/os/file.hpp"

namespace ksim::uicc::os {

/// Writes `data` at `offset` into a key file's contents (the caller checked
/// the bounds and the access rule).
void write_key_file(File& f, std::size_t offset, ByteView data);
/// `len` octets of a key file from `offset`, or an empty SecretBytes when the
/// file is shorter.
SecretBytes key_slice(const File& f, std::size_t offset, std::size_t len);
/// One octet of a key file (a configuration byte), or `fallback`.
std::uint8_t key_byte(const File& f, std::size_t offset, std::uint8_t fallback);

} // namespace ksim::uicc::os
