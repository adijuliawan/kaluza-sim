// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The secret canary (plan M14): a known subscription key K goes through the
// paths that touch keys in P0 (Milenage, the 5G key chain, NAS integrity and
// ciphering), and the outputs those paths make (a log, a pcapng capture of the
// NAS and SIM interfaces, the APDU JSON) are written to a directory, where
// tools/secret_canary.py looks for K and every key derived from it in raw,
// hex, base64 and BCD form. With KSIM_CANARY_LEAK=1 it logs K on purpose, and
// with 2 it captures the card's response with CK and IK in it: the scanner's
// must-fail cases.
//
//   ksim_canary <output dir>

#include <cstdio>
#include <exception>
#include <cstdlib>
#include <fstream>
#include <string>
#include <string_view>

#include "codec/nas/nas.hpp"
#include "codec/uicc/apdu.hpp"
#include "crypto/keys5g.hpp"
#include "crypto/milenage.hpp"
#include "crypto/nea.hpp"
#include "platform/clock.hpp"
#include "platform/log.hpp"
#include "platform/pcapng.hpp"
#include "platform/secret.hpp"

namespace {

using namespace ksim;

// The canary's inputs (also in tools/secret_canary.py). Synthetic: K and OPc
// spell "ksim-canary-k-01" and "ksim-canary-opc1" so a leak is easy to read.
constexpr std::string_view kK = "6b73696d2d63616e6172792d6b2d3031";
constexpr std::string_view kOpc = "6b73696d2d63616e6172792d6f706331";
constexpr std::string_view kRand = "0123456789abcdef0123456789abcdef";
constexpr std::string_view kSqn = "000000000021";
constexpr std::string_view kAmf = "8000";
constexpr std::string_view kSupi = "001010000300042";

Bytes hex(std::string_view s) {
    return from_hex(s).value();
}

int fail(const char* what) {
    std::fprintf(stderr, "ksim_canary: %s\n", what);
    return 1;
}

} // namespace

namespace {
int run(const std::string& dir);
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        return fail("usage: ksim_canary <output dir>");
    }
    try {
        return run(argv[1]);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ksim_canary: %s\n", e.what());
        return 1;
    }
}

namespace {
int run(const std::string& dir) {
    std::ofstream logf(dir + "/canary.log");
    log::set_sink([&logf](std::string_view line) { logf << line; });
    log::set_level(log::Level::debug);

    auto k = SecretBytes::from_hex(kK);
    auto opc = SecretBytes::from_hex(kOpc);
    if (!k || !opc) {
        return fail("bad canary input");
    }
    const Bytes rand = hex(kRand);
    const Bytes sqn = hex(kSqn);
    const Bytes amf = hex(kAmf);
    auto m = crypto::milenage::compute(*k, *opc, rand, sqn, amf);
    if (!m) {
        return fail("milenage");
    }
    log::info("canary", "AKA for imsi-{}: RAND {} SQN {} AMF {}", kSupi, to_hex(rand), to_hex(sqn), to_hex(amf));
    log::debug("canary", "K {} OPc {} CK {} IK {}", k->redacted(), opc->redacted(), m->ck.redacted(),
               m->ik.redacted());

    using namespace crypto::keys5g;
    const auto snn = serving_network_name("001", "01").value();
    Bytes sqn_ak = sqn;
    {
        // SQN xor AK travels in AUTN; AK is not a key in the canary's sense
        const SecretBytes& ak = m->ak;
        Bytes autn_head(6);
        for (std::size_t i = 0; i < 6; ++i) {
            autn_head[i] = static_cast<std::uint8_t>(sqn[i] ^ ak.expose()[i]);
        }
        sqn_ak = autn_head;
    }
    const SecretBytes kausf_ = kausf(m->ck, m->ik, snn, sqn_ak);
    const SecretBytes kseaf_ = kseaf(kausf_, snn);
    auto kamf_ = kamf(kseaf_, kSupi, hex("0000"));
    if (!kamf_) {
        return fail("kamf");
    }
    auto knas_int = algorithm_key(*kamf_, AlgType::nas_int, 2);
    auto knas_enc = algorithm_key(*kamf_, AlgType::nas_enc, 2);
    const SecretBytes kgnb_ = kgnb(*kamf_, 0);
    if (!knas_int || !knas_enc) {
        return fail("algorithm keys");
    }
    log::info("canary", "keys: KAUSF {} KSEAF {} KAMF {} KNASint {} KNASenc {} KgNB {}", kausf_.redacted(),
              kseaf_.redacted(), kamf_->redacted(), knas_int->redacted(), knas_enc->redacted(), kgnb_.redacted());

    // The NAS a capture shows: AUTHENTICATION REQUEST, then a SECURITY MODE
    // COMMAND integrity protected with NIA2 and a ciphered message with NEA2.
    Bytes autn = sqn_ak;
    autn.insert(autn.end(), amf.begin(), amf.end());
    autn.insert(autn.end(), m->mac_a.begin(), m->mac_a.end());
    // AUTHENTICATION REQUEST (24.501 8.2.1): ngKSI 1, ABBA 0000, RAND (TV 21), AUTN (TLV 20)
    Bytes auth_req = hex("7e005601020000" "21");
    auth_req.insert(auth_req.end(), rand.begin(), rand.end());
    auth_req.insert(auth_req.end(), {0x20, 0x10});
    auth_req.insert(auth_req.end(), autn.begin(), autn.end());
    // SECURITY MODE COMMAND (8.2.25): NEA2/NIA2, ngKSI 1, replayed capabilities, IMEISV request (E-)
    const Bytes smc = hex("7e005d22010280" "80e1");
    Bytes protected_part{0x00};                     // the sequence number, then the plain message
    protected_part.insert(protected_part.end(), smc.begin(), smc.end());
    auto mac = crypto::nia(crypto::Nia::nia2, *knas_int, {0, 1, 1}, protected_part, protected_part.size() * 8);
    if (!mac) {
        return fail("nia2");
    }
    nas::Protected p;
    p.security_header_type = 3;
    p.mac = (std::uint32_t{(*mac)[0]} << 24) | (std::uint32_t{(*mac)[1]} << 16) | (std::uint32_t{(*mac)[2]} << 8) |
            (*mac)[3];
    p.payload = smc;
    const Bytes smc_wire = nas::encode_protected(p);
    auto ciphered = crypto::nea(crypto::Nea::nea2, *knas_enc, {1, 1, 1}, hex("7e005e7700090500000000000000000000"),
                                std::size_t{17} * 8);
    if (!ciphered) {
        return fail("nea2");
    }

    // The SIM interface: AUTHENTICATE, whose response carries CK and IK. The
    // capture and the JSON carry them zeroed or by length.
    uicc::AuthChallenge ch{rand, autn};
    Bytes cmd = hex("0088008122");
    const Bytes data = uicc::encode_auth_challenge(ch, uicc::AuthContext::umts);
    cmd.insert(cmd.end(), data.begin(), data.end());
    cmd.push_back(0x00);
    const Bytes res(m->res.expose().begin(), m->res.expose().end());
    const Bytes card = uicc::encode_auth_success(res, m->ck.expose(), m->ik.expose(), {});
    auto result = uicc::decode_auth_result(card, uicc::AuthContext::umts);
    if (!result) {
        return fail("authenticate result");
    }
    const Bytes card_redacted = uicc::redact_keys(card, *result);
    auto c = uicc::decode_command(cmd);
    Bytes rsp_bytes = card;
    rsp_bytes.insert(rsp_bytes.end(), {0x90, 0x00});
    auto r = uicc::decode_response(rsp_bytes);
    if (!c || !r) {
        return fail("apdu");
    }
    std::ofstream(dir + "/canary.json") << uicc::to_json(*c, &*r) << "\n" << nas::to_json(*nas::decode(smc)) << "\n";

    std::ofstream pcap(dir + "/canary.pcapng", std::ios::binary);
    pcap::PcapngWriter w([&pcap](ByteView b) { pcap.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size())); });
    const auto uu = w.add_interface(pcap::LinkType::upper_pdu, "uu");
    const auto sim = w.add_interface(pcap::LinkType::ipv4, "sim");
    const std::int64_t t = realtime_ns();
    (void)w.write(uu, t, pcap::exported_pdu("nas-5gs", auth_req), "SUPI imsi-001010000300042");
    (void)w.write(uu, t + 1000, pcap::exported_pdu("nas-5gs", smc_wire));
    (void)w.write(uu, t + 2000, pcap::exported_pdu("nas-5gs", *ciphered), "ciphered NAS (opaque)");
    pcap::Udp4 u;
    u.dst_port = pcap::kGsmtapPort;
    const char* leak = std::getenv("KSIM_CANARY_LEAK");
    const std::string_view leak_mode = leak != nullptr ? leak : "";
    Bytes sim_frame = cmd;
    sim_frame.resize(cmd.size() - 1);   // T=0 has no Le after the data
    const Bytes& shown = leak_mode == "2" ? card : card_redacted;   // 2: the must-fail capture without redaction
    sim_frame.insert(sim_frame.end(), shown.begin(), shown.end());
    sim_frame.insert(sim_frame.end(), {0x90, 0x00});
    (void)w.write(sim, t + 3000, *pcap::ipv4_udp(u, pcap::gsmtap(pcap::kGsmtapSim, 0, sim_frame)));

    if (leak_mode == "1") {
        log::warn("canary", "deliberate leak for the must-fail case: K {}", kK);
    }
    log::info("canary", "done");
    log::set_sink(nullptr);
    return 0;
}
} // namespace
