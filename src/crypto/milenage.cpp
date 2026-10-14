// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/milenage.hpp"

#include <openssl/crypto.h>

#include <algorithm>

#include "crypto/aes.hpp"

namespace ksim::crypto::milenage {

namespace {

Block load(ByteView v) {
    Block b{};
    std::copy(v.begin(), v.end(), b.begin());
    return b;
}

Block xor_blocks(const Block& a, const Block& b) {
    Block r{};
    for (std::size_t i = 0; i < 16; ++i) {
        r[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
    return r;
}

/// rot(x, r): rotate the 128-bit x by r bits towards the most significant bit
/// (TS 35.206 §3: y = x[r] || x[r+1] || ... || x[r-1]). r is a multiple of 8 here.
Block rot(const Block& x, unsigned r_bits) {
    const unsigned r = r_bits / 8;
    Block y{};
    for (unsigned i = 0; i < 16; ++i) {
        y[i] = x[(i + r) % 16];
    }
    return y;
}

/// c_n: zero except bit 127 - (n - 2) set, i.e. the last octet = 1 << (n - 2), for n >= 2.
Block constant(int n) {
    Block c{};
    if (n >= 2) {
        c[15] = static_cast<std::uint8_t>(1U << (n - 2));
    }
    return c;
}

constexpr unsigned kRot[6] = {0, 64, 0, 32, 64, 96};  // r1..r5 (index 0 unused)

Error bad(const char* what) {
    return make_error(Errc::invalid_argument, 0, what);
}

void wipe(Block& b) {
    OPENSSL_cleanse(b.data(), b.size());
}

} // namespace

Result<SecretBytes> opc(const SecretBytes& k, const SecretBytes& op) {
    if (k.size() != 16 || op.size() != 16) {
        return bad("milenage: K and OP must be 16 octets");
    }
    const Aes128 aes(k.expose());
    Block opb = load(op.expose());
    Block e = aes.encrypt(opb);
    Block out = xor_blocks(e, opb);
    SecretBytes r = SecretBytes::copy_of(out);
    wipe(opb);
    wipe(e);
    wipe(out);
    return r;
}

Result<Outputs> compute(const SecretBytes& k, const SecretBytes& opc_in, ByteView rand, ByteView sqn,
                        ByteView amf) {
    if (k.size() != 16 || opc_in.size() != 16) {
        return bad("milenage: K and OPc must be 16 octets");
    }
    if (rand.size() != 16 || sqn.size() != 6 || amf.size() != 2) {
        return bad("milenage: RAND 16, SQN 6, AMF 2 octets");
    }
    const Aes128 aes(k.expose());
    const Block op_c = load(opc_in.expose());
    Block temp = aes.encrypt(xor_blocks(load(rand), op_c));

    // IN1 = SQN || AMF || SQN || AMF
    Block in1{};
    std::copy(sqn.begin(), sqn.end(), in1.begin());
    std::copy(amf.begin(), amf.end(), in1.begin() + 6);
    std::copy(sqn.begin(), sqn.end(), in1.begin() + 8);
    std::copy(amf.begin(), amf.end(), in1.begin() + 14);

    // OUT1 = E_K(TEMP xor rot(IN1 xor OPc, r1) xor c1) xor OPc
    Block out1 = xor_blocks(aes.encrypt(xor_blocks(xor_blocks(temp, rot(xor_blocks(in1, op_c), kRot[1])),
                                                   constant(1))),
                            op_c);
    // OUT2..OUT5 = E_K(rot(TEMP xor OPc, r_n) xor c_n) xor OPc
    const Block t = xor_blocks(temp, op_c);
    Block out[6]{};
    for (int n = 2; n <= 5; ++n) {
        out[n] = xor_blocks(aes.encrypt(xor_blocks(rot(t, kRot[n]), constant(n))), op_c);
    }

    Outputs o;
    o.mac_a.assign(out1.begin(), out1.begin() + 8);
    o.mac_s.assign(out1.begin() + 8, out1.end());
    o.res = SecretBytes::copy_of(ByteView(out[2]).subspan(8, 8));
    o.ak = SecretBytes::copy_of(ByteView(out[2]).subspan(0, 6));
    o.ck = SecretBytes::copy_of(out[3]);
    o.ik = SecretBytes::copy_of(out[4]);
    o.ak_star = SecretBytes::copy_of(ByteView(out[5]).subspan(0, 6));
    wipe(temp);
    wipe(out1);
    for (auto& b : out) {
        wipe(b);
    }
    return o;
}

} // namespace ksim::crypto::milenage
