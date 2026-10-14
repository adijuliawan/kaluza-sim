// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Fuzz target (plan M14): the hand-written codecs, chosen by the first octet:
// NAS (plain and security protected), ePCO, SMS CP, RP and TPDU (both
// directions, with and without TP-FCS), GTP-U and its IEs, PSC and NR-U
// frames, APDUs and AUTHENTICATE data, BER-TLV and FCP. Property: each keeps
// what it reads, so what decodes encodes back to the same octets; the JSON
// writers never crash.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "codec/nas/nas.hpp"
#include "codec/nas/sms.hpp"
#include "codec/uicc/apdu.hpp"
#include "codec/uicc/fcp.hpp"
#include "codec/up/frames.hpp"
#include "codec/up/gtpu.hpp"

namespace {

using ksim::Bytes;
using ksim::ByteView;

void same(const Bytes& again, ByteView in) {
    if (again.size() != in.size() || !std::equal(again.begin(), again.end(), in.begin())) {
        std::abort();
    }
}

template <class R>
void same(const R& again, ByteView in) {
    if (!again) {
        std::abort();
    }
    same(*again, in);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace ksim;
    if (size == 0) {
        return 0;
    }
    const std::uint8_t pick = data[0];
    const ByteView in(data + 1, size - 1);
    switch (pick % 16) {
    case 0:
        if (auto m = nas::decode(in)) {
            (void)nas::to_json(*m);
            same(nas::encode(*m), in);
        }
        break;
    case 1:
        if (auto p = nas::decode_protected(in)) {
            same(nas::encode_protected(*p), in);
        }
        break;
    case 2: {
        const auto dir = (pick & 0x10) != 0 ? nas::Direction::dl : nas::Direction::ul;
        if (auto e = nas::decode_epco(in, dir)) {
            same(nas::encode_epco(*e, dir), in);
        }
        break;
    }
    case 3:
        if (auto c = sms::decode_cp(in)) {
            (void)sms::to_json(*c);
            same(sms::encode_cp(*c), in);
        }
        break;
    case 4:
        if (auto r = sms::decode_rp(in)) {
            (void)sms::to_json(*r);
            same(sms::encode_rp(*r), in);
        }
        break;
    case 5: {
        const auto dir = (pick & 0x10) != 0 ? sms::TpDir::sc_to_ms : sms::TpDir::ms_to_sc;
        if (auto t = sms::decode_tpdu(in, dir, (pick & 0x20) != 0)) {
            (void)sms::to_json(*t);
            same(sms::encode_tpdu(*t), in);
        }
        break;
    }
    case 6:
        if (auto p = gtpu::decode(in)) {
            (void)gtpu::to_json(*p);
            same(gtpu::encode(*p), in);
        }
        break;
    case 7:
        if (auto v = gtpu::decode_ies(in)) {
            same(gtpu::encode_ies(*v), in);
        }
        break;
    case 8:
    case 9: {
        const auto proto = pick % 16 == 8 ? up::Protocol::psc : up::Protocol::nru;
        if (auto f = up::decode(proto, in)) {
            (void)up::to_json(*f);
            same(up::encode(*f), in);
        }
        break;
    }
    case 10:
        if (auto c = uicc::decode_command(in)) {
            (void)uicc::to_json(*c, nullptr);
            same(uicc::encode_command(*c), in);
        }
        break;
    case 11: {
        // a command and a response: the first octet after the selector splits them
        if (in.empty()) {
            break;
        }
        const std::size_t cut = std::min<std::size_t>(in[0], in.size() - 1);
        auto c = uicc::decode_command(in.subspan(1, cut));
        auto r = uicc::decode_response(in.subspan(1 + cut));
        if (c && r) {
            (void)uicc::to_json(*c, &*r);
            same(uicc::encode_response(*r), in.subspan(1 + cut));
        }
        break;
    }
    case 12: {
        const auto ctx = (pick & 0x10) != 0 ? uicc::AuthContext::gsm : uicc::AuthContext::umts;
        if (auto a = uicc::decode_auth_result(in, ctx)) {
            Bytes again;
            if (a->kind == uicc::AuthResult::Kind::success) {
                again = uicc::encode_auth_success(a->res, a->ck.in(in), a->ik.in(in), a->kc.in(in));
            } else if (a->kind == uicc::AuthResult::Kind::sync_failure) {
                again = uicc::encode_auth_sync_failure(a->auts);
            } else {
                again = uicc::encode_auth_gsm(a->res, a->kc.in(in));
            }
            same(again, in);
        }
        if (auto ch = uicc::decode_auth_challenge(in, ctx)) {
            same(uicc::encode_auth_challenge(*ch, ctx), in);
        }
        break;
    }
    case 13:
        if (auto v = uicc::decode_ber(in)) {
            same(uicc::encode_ber(*v), in);
        }
        break;
    case 14:
        if (auto f = uicc::decode_fcp(in)) {
            (void)uicc::to_json(*f);
            (void)f->pin_key_references();
            (void)f->sfi();
            same(uicc::encode_fcp(*f), in);
        }
        break;
    default:
        (void)uicc::decode_cla(pick);
        (void)uicc::command_name(pick, in.empty() ? 0 : in[0]);
        break;
    }
    return 0;
}
