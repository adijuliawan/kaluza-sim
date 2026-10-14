// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/milenage256.hpp"

#include <openssl/crypto.h>

#include <algorithm>

#include "crypto/rijndael256.hpp"

namespace ksim::crypto::milenage256 {

namespace {

Error bad(const char* what) {
    return make_error(Errc::invalid_argument, 0, what);
}

/// x xor y, the shorter operand zero-extended (§3.5).
Block32 xor32(const Block32& a, ByteView b) {
    Block32 r = a;
    for (std::size_t i = 0; i < b.size() && i < 32; ++i) {
        r[i] ^= b[i];
    }
    return r;
}

Block32 load(ByteView v) {
    Block32 b{};
    std::copy(v.begin(), v.end(), b.begin());
    return b;
}

void wipe(Block32& b) {
    OPENSSL_cleanse(b.data(), b.size());
}

/// MAKE_INS(f-index, RANDsz, Ksz) = bin3(fi) || bin4((RANDsz - 2) / 2) || bin1(Ksz >> 5).
std::uint8_t make_ins(unsigned fi, const Sizes& sz) {
    return static_cast<std::uint8_t>((fi << 5) | (((sz.rand - 2) / 2) << 1) | (sz.k >> 5));
}

Result<void> check(const SecretBytes& k, const SecretBytes& opc, std::size_t rand, const Sizes& sz) {
    if (k.size() != sz.k || (sz.k != 16 && sz.k != 32) || opc.size() != 32) {
        return bad("MILENAGE-256: K 16 or 32 octets, OPc 32");
    }
    if (rand != sz.rand || sz.rand < 16 || sz.rand > 32 || sz.rand % 2 != 0) {
        return bad("MILENAGE-256: RAND 16..32 octets, even");
    }
    if (sz.sqn < 6 || sz.sqn > 12 || sz.ak < 6 || sz.ak > 12 || sz.mac < 8 || sz.mac > 32 || sz.res < 4 ||
        sz.res > 32 || sz.ck < 16 || sz.ck > 32 || sz.ik < 16 || sz.ik > 32) {
        return bad("MILENAGE-256: a size outside table 6-1");
    }
    return {};
}

/// The common part: TEMP = PRF_K(RAND xor OPc) xor OPc.
struct Kernel {
    Rijndael256 prf;
    Block32 opc;
    Block32 temp;

    Kernel(const SecretBytes& k, const SecretBytes& opc_in, ByteView rand)
        : prf(k.expose()), opc(load(opc_in.expose())), temp{} {
        Block32 x = xor32(opc, rand);
        Block32 y = prf.encrypt(x);
        temp = xor32(y, opc);
        wipe(x);
        wipe(y);
    }
    ~Kernel() {
        wipe(opc);
        wipe(temp);
    }
    Kernel(const Kernel&) = delete;
    Kernel& operator=(const Kernel&) = delete;

    /// OUT_i = PRF_K(TEMP xor IN_i) xor OPc (EQ 2).
    Block32 out(const Block32& in) const {
        Block32 x = xor32(temp, in);
        Block32 y = prf.encrypt(x);
        Block32 r = xor32(y, opc);
        wipe(x);
        wipe(y);
        return r;
    }
};

/// IN_i for f2..f5*: IN[0] = MAKE_INS, IN[1] as given, IN[16..31] = c_i.
Block32 in_simple(unsigned fi, std::uint8_t in1, const Sizes& sz, const Constants& c) {
    Block32 in{};
    in[0] = make_ins(fi, sz);
    in[1] = in1;
    std::copy(c[fi].begin(), c[fi].end(), in.begin() + 16);
    return in;
}

Block32 in_f5ss(ByteView mac_s, const Sizes& sz, const Constants& c) {
    Block32 in = in_simple(7, static_cast<std::uint8_t>(((sz.mac - 1) << 3) | (sz.ak - 5)), sz, c);
    for (std::size_t j = 0; j <= std::min<std::size_t>(29, sz.mac - 1); ++j) {
        in[j + 2] ^= mac_s[j];
    }
    return in;
}

SecretBytes head(Block32& b, std::size_t n) {
    SecretBytes s = SecretBytes::copy_of(ByteView(b).first(n));
    wipe(b);
    return s;
}

} // namespace

Constants default_constants() {
    Constants c{};
    for (unsigned i = 1; i < 8; ++i) {
        c[i][15] = static_cast<std::uint8_t>(1U << (i - 1));
    }
    return c;
}

Result<SecretBytes> opc(const SecretBytes& k, const SecretBytes& op, std::string_view algoname) {
    if ((k.size() != 16 && k.size() != 32) || op.size() != 32 || algoname.size() > 30) {
        return bad("MILENAGE-256: K 16 or 32 octets, OP 32, ALGONAME at most 30 characters");
    }
    // V[0] = Ksz == 32, V[1..] = ALGONAME, zero-filled to 32 octets.
    Block32 v{};
    v[0] = k.size() == 32 ? 0x01 : 0x00;
    std::copy(algoname.begin(), algoname.end(), v.begin() + 1);
    const Rijndael256 prf(k.expose());
    Block32 opb = load(op.expose());
    Block32 t = prf.encrypt(opb);
    Block32 u = prf.encrypt(xor32(t, v));
    Block32 r = xor32(u, opb);
    SecretBytes out = SecretBytes::copy_of(r);
    wipe(opb);
    wipe(t);
    wipe(u);
    wipe(r);
    return out;
}

Result<Outputs> compute(const SecretBytes& k, const SecretBytes& opc_in, ByteView rand, ByteView sqn, ByteView amf,
                        const Sizes& sz, const Constants& c) {
    if (auto ok = check(k, opc_in, rand.size(), sz); !ok) {
        return ok.error();
    }
    if (sqn.size() != sz.sqn || amf.size() != 2) {
        return bad("MILENAGE-256: SQN of SQNsz octets, AMF 2");
    }
    const Kernel kr(k, opc_in, rand);
    Outputs o;
    for (unsigned fi = 0; fi <= 1; ++fi) {  // f1* (0) and f1 (1)
        Block32 in{};
        in[0] = make_ins(fi, sz);
        in[1] = static_cast<std::uint8_t>(((sz.sqn - 5) << 5) | (sz.mac - 1));
        in[2] = amf[0];
        in[3] = amf[1];
        std::copy(sqn.begin(), sqn.end(), in.begin() + 4);
        std::copy(c[fi].begin(), c[fi].end(), in.begin() + 16);
        Block32 out = kr.out(in);
        (fi == 0 ? o.mac_s : o.mac_a).assign(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(sz.mac));
        wipe(out);
    }
    Block32 b2 = kr.out(in_simple(2, static_cast<std::uint8_t>(sz.res - 1), sz, c));
    o.res = head(b2, sz.res);
    Block32 b3 = kr.out(in_simple(3, static_cast<std::uint8_t>(sz.ck - 1), sz, c));
    o.ck = head(b3, sz.ck);
    Block32 b4 = kr.out(in_simple(4, static_cast<std::uint8_t>(sz.ik - 1), sz, c));
    o.ik = head(b4, sz.ik);
    Block32 b5 = kr.out(in_simple(5, static_cast<std::uint8_t>(sz.ak - 5), sz, c));
    o.ak = head(b5, sz.ak);
    Block32 b6 = kr.out(in_simple(6, static_cast<std::uint8_t>(sz.ak - 5), sz, c));
    o.ak_star = head(b6, sz.ak);
    Block32 b7 = kr.out(in_f5ss(o.mac_s, sz, c));
    o.ak_star_star = head(b7, sz.ak);
    return o;
}

Result<SecretBytes> f5_star_star(const SecretBytes& k, const SecretBytes& opc_in, ByteView rand, ByteView mac_s,
                                 const Sizes& sz, const Constants& c) {
    if (auto ok = check(k, opc_in, rand.size(), sz); !ok) {
        return ok.error();
    }
    if (mac_s.size() != sz.mac) {
        return bad("MILENAGE-256: MAC-S of MACsz octets");
    }
    const Kernel kr(k, opc_in, rand);
    Block32 b7 = kr.out(in_f5ss(mac_s, sz, c));
    return head(b7, sz.ak);
}

} // namespace ksim::crypto::milenage256
