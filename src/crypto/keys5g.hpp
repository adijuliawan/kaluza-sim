// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The 5G key hierarchy of TS 33.501 Annex A, every derivation through the
// generic KDF (kdf.hpp), plus CK'/IK' (TS 33.402 A.2) for EAP-AKA'.
//
// Three places where implementations go wrong, each pinned by a KAT:
//  - K_AMF takes the SUPI as a character string of its digits (A.7.0: the IMSI
//    "as defined in TS 23.003 clause 2.2", UTF-8 per TS 33.220 B.2.1.2), not
//    BCD and not the "imsi-" URI form, which kamf() rejects;
//  - K_gNB takes the uplink NAS COUNT as four octets (A.9; TS 33.220 B.2.1.3);
//  - the serving network name pads a two-digit MNC with a leading zero
//    (TS 24.501 9.12.1).

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto::keys5g {

/// "5G:mnc<MNC>.mcc<MCC>.3gppnetwork.org" (TS 24.501 9.12.1, TS 33.501 6.1.1.4).
Result<std::string> serving_network_name(std::string_view mcc, std::string_view mnc);

/// K_AUSF for 5G AKA (A.2): KEY = CK || IK, FC 0x6A, P0 = SNN, P1 = SQN xor AK.
SecretBytes kausf(const SecretBytes& ck, const SecretBytes& ik, std::string_view snn, ByteView sqn_xor_ak);

/// RES* or XRES* (A.4): FC 0x6B, P0 = SNN, P1 = RAND, P2 = RES; the 128 least
/// significant bits of the output.
SecretBytes res_star(const SecretBytes& ck, const SecretBytes& ik, std::string_view snn, ByteView rand,
                     const SecretBytes& res);

/// HRES* or HXRES* (A.5): the 128 least significant bits of SHA-256(RAND || RES*).
Bytes hres_star(ByteView rand, const SecretBytes& res_star);

/// K_SEAF (A.6): KEY = K_AUSF, FC 0x6C, P0 = SNN.
SecretBytes kseaf(const SecretBytes& kausf, std::string_view snn);

/// K_AMF (A.7): KEY = K_SEAF, FC 0x6D, P0 = the SUPI's IMSI digits or NAI,
/// P1 = ABBA. A SUPI in its URI form ("imsi-...", "nai-...") is an error.
Result<SecretBytes> kamf(const SecretBytes& kseaf, std::string_view supi, ByteView abba);

/// Algorithm type distinguishers (A.8, table A.8-1).
enum class AlgType : std::uint8_t {
    nas_enc = 0x01,
    nas_int = 0x02,
    rrc_enc = 0x03,
    rrc_int = 0x04,
    up_enc = 0x05,
    up_int = 0x06,
};

/// An algorithm key (A.8): KEY = K_AMF (NAS) or K_gNB (RRC, UP), FC 0x69,
/// P0 = distinguisher, P1 = algorithm identity (0..15); the 128 least
/// significant bits of the output.
Result<SecretBytes> algorithm_key(const SecretBytes& key, AlgType type, std::uint8_t alg_id);

/// Access type distinguishers (A.9, table A.9-1).
enum class AccessType : std::uint8_t { three_gpp = 0x01, non_3gpp = 0x02 };

/// K_gNB (3GPP access) or K_N3IWF (non-3GPP) (A.9): KEY = K_AMF, FC 0x6E,
/// P0 = uplink NAS COUNT (4 octets), P1 = access type distinguisher.
SecretBytes kgnb(const SecretBytes& kamf, std::uint32_t ul_nas_count, AccessType access = AccessType::three_gpp);

/// NH (A.10): KEY = K_AMF, FC 0x6F, P0 = SYNC-input (K_gNB or the previous NH).
SecretBytes nh(const SecretBytes& kamf, const SecretBytes& sync_input);

/// K_NG-RAN* for a target gNB (A.11): KEY = K_gNB or NH, FC 0x70, P0 = PCI
/// (2 octets), P1 = ARFCN-DL of the target PCell's SSB (3 octets).
SecretBytes kng_ran_star(const SecretBytes& key, std::uint16_t pci, std::uint32_t arfcn_dl);

/// K_AMF' in mobility (A.13): KEY = K_AMF, FC 0x72, P0 = DIRECTION (1 octet),
/// P1 = COUNT (4 octets).
SecretBytes kamf_prime(const SecretBytes& kamf, std::uint8_t direction, std::uint32_t count);

/// K_SN for dual connectivity (A.16): KEY = K_gNB, FC 0x79, P0 = SN Counter (2 octets).
SecretBytes ksn(const SecretBytes& kgnb, std::uint16_t sn_counter);

/// CK' and IK' (TS 33.402 A.2, used per TS 33.501 A.3): KEY = CK || IK, FC 0x20,
/// P0 = access network identity (the serving network name), P1 = SQN xor AK.
struct CkIkPrime {
    SecretBytes ck_prime;  // the 128 most significant bits
    SecretBytes ik_prime;  // the 128 least significant bits
};
CkIkPrime ck_ik_prime(const SecretBytes& ck, const SecretBytes& ik, std::string_view access_network_identity,
                      ByteView sqn_xor_ak);

/// The four octets of a 24-bit NAS COUNT (overflow << 8 | sequence number) as
/// the KDF takes it: eight zero bits, then the COUNT (TS 33.501 6.4.3.1).
std::uint32_t nas_count(std::uint16_t overflow, std::uint8_t sqn);

} // namespace ksim::crypto::keys5g
