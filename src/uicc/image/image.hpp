// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Card images (P1 N3; sim-uicc.md §7): a card's file tree, file contents and
// PIN states as YAML, diffable and free of secrets. Key files (`secret: true`,
// AF20) and the EFs that hold session keys (`sealed: true`: 4F03, 4F05) take
// their contents from the sealed secrets (secrets.hpp) under the name
// "ef.<FID>", and save() hands them back the same way. K and OPc may also come
// as "k" and "opc", from which AF20 is built for Milenage.
//
// The YAML (each file a map; children under `files`):
//   atr: 3B…        t0: true        channels: 4
//   pins: [{ref: 0x01, enabled: false, tries: 3, unblock_tries: 10}, …]
//   mf: {fid: 0x3F00, type: mf, arr: [0x2F06, 4], files: [ … ]}
//   EF: {fid, name, type: transparent|linear_fixed|cyclic, sfi, lcs, arr,
//        data: hex | size + fill, records: [hex…] | record_len + record_count + fill,
//        secret: bool, sealed: bool}
//   DF/ADF: {fid, name, type: df|adf, aid (ADF), arr, files}

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <string_view>

#include "platform/result.hpp"
#include "platform/yaml.hpp"
#include "uicc/os/card.hpp"
#include "uicc/secrets/secrets.hpp"

namespace ksim::uicc::image {

/// Builds a card from an image and its secrets; the USIM application is
/// attached to every USIM ADF. Throws YamlError for a malformed image.
std::unique_ptr<os::Card> load(const Yaml& image, const secrets::SecretMap& secrets);
/// The image of a card as it stands now, and its sealed EF contents in `sealed`.
std::string save(os::Card& card, secrets::SecretMap& sealed);

struct Subscriber {
    std::string imsi;      // 15 digits
    std::string iccid;     // 19 or 20 digits
    std::string msisdn;    // digits of an international number, or empty
    unsigned mnc_digits = 2;
};

/// The identity of a sim-range card (sim-uicc.md §8; P1 N8): the IMSI, ICCID
/// 8988211 00 ‖ MSIN, MSISDN 999 ‖ the MSIN's last eight digits, two MNC digits.
/// Errc::invalid_argument outside the 001/01 and 999/70 sim ranges.
Result<Subscriber> range_subscriber(std::string_view imsi);

/// Writes a subscriber's identity into a card built from a template: EF.IMSI,
/// EF.ICCID, EF.ACC, the MNC length in EF.AD, and EF.MSISDN.
Result<void> personalise(os::Card& card, const Subscriber& sub);

/// EF.IMSI (TS 31.102 §4.2.2): the length, then the digits in BCD after the
/// type and parity nibble.
Result<Bytes> encode_imsi(std::string_view digits);
/// EF.ICCID (TS 102 221 §13.2): BCD, nibble-swapped, 'F'-padded to 10 octets.
Result<Bytes> encode_iccid(std::string_view digits);
/// EF.ACC (TS 31.102 §4.2.15, TS 22.011 §4.2): the access class from the
/// IMSI's last digit.
Bytes encode_acc(std::string_view imsi);
/// One EF.MSISDN record (TS 31.102 §4.2.26) with no alpha identifier.
Result<Bytes> encode_msisdn_record(std::string_view digits, std::size_t record_len);

/// The digits of EF.IMSI, EF.ICCID and an EF.MSISDN record (the inverses of
/// the encoders above); empty for contents that hold none.
std::string decode_imsi(ByteView ef);
std::string decode_iccid(ByteView ef);
std::string decode_msisdn_record(ByteView rec);
/// The services EF.UST marks available (TS 31.102 4.2.8), in order.
std::vector<unsigned> services(ByteView ust);

/// The first ADF whose AID starts with the USIM's RID and application code.
os::File* usim_adf(os::Card& card) noexcept;

/// The ATR of an opt-in personality (`personality:` in an image, `ksim-sim
/// serve --personality`), or nullopt for a name it does not know.
std::optional<Bytes> personality_atr(std::string_view name);

} // namespace ksim::uicc::image
