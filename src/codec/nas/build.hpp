// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Building NAS messages for encode() (P1 N5): a message of a given type with
// its header IEs set, IEs set by the names the message tables give them, kept
// in table order so the encoder's half-octet pairing and IE order hold.

#pragma once

#include <string_view>
#include <vector>

#include "codec/nas/nas.hpp"

namespace ksim::nas {

/// A message with its header set: the extended protocol discriminator, the
/// security header type 0 (5GMM) or PDU session identity and PTI 0 (5GSM),
/// every spare half octet, and the message type.
Result<Message> make(Epd epd, std::uint8_t type);

/// Sets IE `name` to `value` (its contents; a type 1 IE's value in the low four
/// bits of one octet), replacing an earlier value. Errc::invalid_argument when
/// the message has no IE of that name.
Result<void> set(Message& m, std::string_view name, Bytes value);
/// Removes IE `name` if present.
void unset(Message& m, std::string_view name);
/// The contents of IE `name`, or nullptr.
const Bytes* get(const Message& m, std::string_view name) noexcept;

/// The mandatory IEs of the message's table that `m` lacks.
std::vector<std::string_view> missing_mandatory(const Message& m);

} // namespace ksim::nas
