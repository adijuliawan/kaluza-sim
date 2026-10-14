// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// MILENAGE f1, f1*, f2, f3, f4, f5 and f5* (TS 35.206 §4.1), with the
// constants c1..c5 and rotations r1..r5 of that clause. Checked against the
// 20 conformance sets of TS 35.208.

#pragma once

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto::milenage {

struct Outputs {
    Bytes mac_a;          // f1, 8 octets (travels in AUTN)
    Bytes mac_s;          // f1*, 8 octets (travels in AUTS)
    SecretBytes res;      // f2, 8 octets
    SecretBytes ck;       // f3, 16 octets
    SecretBytes ik;       // f4, 16 octets
    SecretBytes ak;       // f5, 6 octets
    SecretBytes ak_star;  // f5*, 6 octets
};

/// OPc = OP xor E_K(OP).
Result<SecretBytes> opc(const SecretBytes& k, const SecretBytes& op);

/// All seven functions. k and opc are 16 octets; rand 16, sqn 6, amf 2.
Result<Outputs> compute(const SecretBytes& k, const SecretBytes& opc, ByteView rand, ByteView sqn,
                        ByteView amf);

} // namespace ksim::crypto::milenage
