// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The Uu decoders under arbitrary input (P1 N6). The first octet picks a
// target: the KAIR codec, the PDCP header, a PDCP entity receiving with
// NIA2/NEA2 on, or one of the typed RRC readers. A value that decodes and
// encodes again must decode to the same value; nothing may crash.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "codec/air/kair.hpp"
#include "codec/asn1/msg/rrc.hpp"
#include "codec/pdcp/pdcp.hpp"
#include "entity/pdcp/pdcp.hpp"
#include "platform/sim_loop.hpp"

namespace {

using ksim::Bytes;
using ksim::ByteView;

void check(bool ok) {
    if (!ok) {
        std::abort();
    }
}

/// decode, encode, decode: the same value.
template <class Decode>
void round_trip(ByteView in, Decode decode) {
    auto v = decode(in);
    if (!v) {
        return;
    }
    auto again = ksim::rrc::encode(*v);
    if (!again) {
        return;   // a value the builders refuse (e.g. more than they write)
    }
    auto w = decode(*again);
    check(w.has_value() && *w == *v);
}

template <class Variant, class Decode>
void round_trip_variant(ByteView in, Decode decode) {
    auto v = decode(in);
    if (!v) {
        return;
    }
    auto again = std::visit([](const auto& m) { return ksim::rrc::encode(m); }, *v);
    if (!again) {
        return;
    }
    auto w = decode(*again);
    check(w.has_value() && *w == *v);
}

void pdcp_entity(ByteView in) {
    ksim::SimLoop loop;
    ksim::entity::PdcpConfig c;
    c.srb = (in.empty() ? 0 : in[0]) % 2 == 0;
    c.side = ksim::entity::PdcpSide::ue;
    c.t_reordering = 50;
    ksim::entity::Pdcp p(loop, c, [](const Bytes&) {}, [](const Bytes&) {});
    (void)p.set_keys(ksim::crypto::Nia::nia2,
                     ksim::SecretBytes::from_hex("000102030405060708090a0b0c0d0e0f").value(), ksim::crypto::Nea::nea2,
                     ksim::SecretBytes::from_hex("f0e0d0c0b0a090807060504030201000").value());
    p.set_integrity(true, (in.size() > 1 && in[1] % 2 == 1));
    p.set_ciphering(true, true);
    // The rest: PDUs, each preceded by a one-octet length.
    std::size_t i = 2;
    while (i < in.size()) {
        const std::size_t n = in[i++];
        const std::size_t take = std::min(n, in.size() - i);
        p.on_pdu(in.subspan(i, take));
        i += take;
        loop.run_for(10);
    }
    loop.run_for(100);
    check(p.rx_deliv() <= p.rx_next());
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const ByteView in(data + 1, size - 1);
    switch (data[0] % 12) {
    case 0: {
        auto f = ksim::air::decode(in);
        if (f) {
            auto e = ksim::air::encode(*f);
            check(e.has_value());
            auto g = ksim::air::decode(*e);
            check(g.has_value() && *g == *f);
        }
        break;
    }
    case 1:
        for (const bool srb : {true, false}) {
            for (const auto s : {ksim::pdcp::SnSize::len12, ksim::pdcp::SnSize::len18}) {
                auto h = ksim::pdcp::parse(srb, s, in);
                if (h && h->data) {
                    check(h->length <= in.size() && h->sn <= ksim::pdcp::sn_mask(s));
                }
            }
        }
        (void)ksim::pdcp::decode_status_report(in);
        break;
    case 2:
        pdcp_entity(in);
        break;
    case 3:
        round_trip(in, ksim::rrc::decode_mib);
        break;
    case 4:
        round_trip(in, ksim::rrc::decode_sib1);
        break;
    case 5:
        round_trip(in, ksim::rrc::decode_paging);
        break;
    case 6:
        round_trip(in, ksim::rrc::decode_ul_ccch);
        break;
    case 7:
        round_trip_variant<ksim::rrc::DlCcch>(in, ksim::rrc::decode_dl_ccch);
        break;
    case 8:
        round_trip_variant<ksim::rrc::DlDcch>(in, ksim::rrc::decode_dl_dcch);
        break;
    case 9:
        round_trip_variant<ksim::rrc::UlDcch>(in, ksim::rrc::decode_ul_dcch);
        break;
    case 10:
        round_trip(in, ksim::rrc::decode_cell_group);
        break;
    default:
        (void)ksim::rrc::to_jer("DL-DCCH", in);
        break;
    }
    return 0;
}
