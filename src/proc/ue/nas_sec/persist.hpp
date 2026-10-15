// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// What the UE keeps on the USIM across power cycles (P1 N12; TS 31.102 j60
// 4.4.11.2, 4.4.11.4, 4.4.11.6; TS 24.501 4.4.2.1, 5.5.1.2.4): EF.5GS3GPPLOCI
// (the 5G-GUTI, the last visited registered TAI, the 5GS update status),
// EF.5GS3GPPNSC (the native 5G NAS security context: ngKSI, K_AMF, the NAS
// COUNTs, the algorithms) and EF.5GAUTHKEYS (K_AUSF, K_SEAF). The layouts
// live here rather than in codec because two of them hold keys, which only
// SecretBytes may carry (rule R3).

#pragma once

#include <cstdint>
#include <optional>

#include "codec/nas/ie/ie.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"
#include "proc/ue/nas_sec/nas_sec.hpp"

namespace ksim::proc::ue::persist {

inline constexpr std::uint16_t kDf5gs = 0x5FC0;
inline constexpr std::uint16_t kLoci = 0x4F01;
inline constexpr std::uint16_t kNsc = 0x4F03;
inline constexpr std::uint16_t kAuthKeys = 0x4F05;
inline constexpr std::size_t kLociSize = 20;

/// EF.5GS3GPPLOCI (20 octets). The update status as the file codes it: 0 5U1
/// UPDATED, 1 5U2 NOT UPDATED, 2 5U3 ROAMING NOT ALLOWED.
struct Loci {
    std::optional<nas::ie::MobileIdentity> guti;   // none: all 'FF'
    std::optional<nas::ie::Tai> tai;               // none: written all 'FF'; read so when the PLMN is 'FFFFFF'
    std::uint8_t update_status = 1;
};
Bytes encode_loci(const Loci& l);
/// A file that does not hold a 5G-GUTI reads as none (no error); a malformed one is an error.
Result<Loci> decode_loci(ByteView in);

/// A record of EF.5GS3GPPNSC, `size` octets ('FF' padded). Without a context,
/// or to mark the stored one invalid (4.4.2.1.2), the ngKSI is 7 ("no key
/// available") and K_AMF empty.
SecretBytes encode_nsc(const NasSecurityContext* ctx, std::size_t size);
/// The stored context, or nullopt when the record holds none (ngKSI 7 or an
/// empty K_AMF), as TS 31.102 says the ME treats them.
Result<std::optional<NasSecurityContext>> decode_nsc(ByteView record);

/// EF.5GAUTHKEYS: K_AUSF and K_SEAF (32 octets each), `size` octets ('FF' padded).
SecretBytes encode_auth_keys(const SecretBytes* kausf, const SecretBytes* kseaf, std::size_t size);

} // namespace ksim::proc::ue::persist
