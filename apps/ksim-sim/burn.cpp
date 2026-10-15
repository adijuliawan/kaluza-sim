// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "burn.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>

#include "card.hpp"
#include "codec/uicc/apdu.hpp"
#include "codec/uicc/fcp.hpp"
#include "crypto/aead.hpp"
#include "crypto/milenage.hpp"
#include "platform/secret.hpp"
#include "uicc/image/image.hpp"
#include "uicc/os/file.hpp"
#include "uicc/secrets/secrets.hpp"
#ifdef KSIM_HAVE_PCSC
#include "uicc/transport/pcsc.hpp"
#endif

namespace ksim::sim {

namespace {

namespace secrets = uicc::secrets;

std::uint16_t sw_of(const Bytes& r) {
    return r.size() >= 2 ? static_cast<std::uint16_t>((r[r.size() - 2] << 8) | r.back()) : 0;
}

/// One exchange with T=0's procedures done here (TS 102 221 §7.3.1.1.4):
/// 61xx fetches the rest by GET RESPONSE, 6Cxx resends with that Le. The
/// command's own buffer is wiped, since VERIFY and UPDATE of AF20 carry keys.
Result<Bytes> exchange(const Xfer& x, Bytes c) {
    auto r = x(c);
    Bytes data;
    for (int guard = 0; r && guard < 32; ++guard) {
        if (r->size() < 2) {
            secure_zero(c);
            return make_error(Errc::malformed, 0, "burn: a response without SW1 SW2");
        }
        const std::uint8_t sw1 = (*r)[r->size() - 2];
        const std::uint8_t sw2 = (*r)[r->size() - 1];
        if (sw1 == 0x61) {
            data.insert(data.end(), r->begin(), r->end() - 2);
            const Bytes get{0x00, 0xC0, 0x00, 0x00, sw2};
            r = x(get);
            continue;
        }
        if (sw1 == 0x6C && c.size() >= 4) {
            if (c.size() == 4) {
                c.push_back(sw2);
            } else {
                c.back() = sw2;
            }
            r = x(c);
            continue;
        }
        data.insert(data.end(), r->begin(), r->end());
        secure_zero(c);
        return data;
    }
    secure_zero(c);
    if (!r) {
        return r.error();
    }
    return make_error(Errc::malformed, 0, "burn: the card kept answering 61xx/6Cxx");
}

bool ok(const Bytes& r) { return sw_of(r) == 0x9000 || (sw_of(r) & 0xFF00) == 0x9100; }

Result<Bytes> select_fid(const Xfer& x, std::uint16_t fid) {
    return exchange(x, Bytes{0x00, 0xA4, 0x00, 0x04, 0x02, static_cast<std::uint8_t>(fid >> 8),
                             static_cast<std::uint8_t>(fid & 0xFF)});
}

Result<Bytes> select_usim(const Xfer& x) {
    // The USIM AID's RID and application code (TS 31.110 / TS 101 220), partial name (P2 b2: first or only).
    return exchange(x, Bytes{0x00, 0xA4, 0x04, 0x04, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02});
}

std::optional<uicc::Fcp> fcp_of(const Bytes& r) {
    if (!ok(r) || r.size() <= 2) {
        return std::nullopt;
    }
    auto f = uicc::decode_fcp(ByteView(r.data(), r.size() - 2));
    if (!f) {
        return std::nullopt;
    }
    return *f;
}

/// "63Cx" from VERIFY with no data: x tries left; nullopt when the card says
/// something else (9000: verified already; 6983: blocked).
struct Tries {
    std::uint16_t sw = 0;
    std::optional<unsigned> left;
};
Result<Tries> tries(const Xfer& x, std::uint8_t ref) {
    auto r = exchange(x, Bytes{0x00, 0x20, 0x00, ref});
    if (!r) {
        return r.error();
    }
    Tries t;
    t.sw = sw_of(*r);
    if ((t.sw & 0xFFF0) == 0x63C0) {
        t.left = t.sw & 0x0F;
    }
    return t;
}

Result<Bytes> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return make_error(Errc::io, 0, "cannot read the file");
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    return Bytes(s.begin(), s.end());
}

const uicc::os::File* find(const uicc::os::File& df, std::uint16_t fid) {
    for (const auto& c : df.children) {
        if (c->fid == fid && c->kind != uicc::os::Kind::df && c->kind != uicc::os::Kind::adf) {
            return c.get();
        }
    }
    return nullptr;
}

const uicc::os::File* find_df(const uicc::os::File& df, std::uint16_t fid) {
    for (const auto& c : df.children) {
        if (c->fid == fid && (c->kind == uicc::os::Kind::df || c->kind == uicc::os::Kind::adf)) {
            return c.get();
        }
    }
    return nullptr;
}

const uicc::os::File* usim_of(const uicc::os::File& mf) {
    for (const auto& c : mf.children) {
        if (c->kind == uicc::os::Kind::adf) {
            return c.get();
        }
    }
    return nullptr;
}

std::string fid4(std::uint16_t f) {
    std::array<char, 5> b{};
    std::snprintf(b.data(), b.size(), "%04X", f);
    return b.data();
}

} // namespace

int burn(const BurnOptions& o, const Xfer& x) {
    auto sub = uicc::image::range_subscriber(o.imsi);
    if (!sub) {
        std::cerr << "ksim-sim: --imsi is not in a sim range\n";
        return 2;
    }
    // 1. the card, ADF.USIM, the ADM1 tries left and PIN1's state; nothing written yet.
    auto mf = select_fid(x, 0x3F00);
    if (!mf || !ok(*mf)) {
        std::cerr << "ksim-sim: the card does not select its MF\n";
        return 1;
    }
    auto adf = select_usim(x);
    if (!adf || !ok(*adf)) {
        std::cerr << "ksim-sim: the card has no USIM application\n";
        return 1;
    }
    auto adm = tries(x, 0x0A);
    auto pin1 = tries(x, 0x01);
    if (!adm || !pin1) {
        std::cerr << "ksim-sim: the card does not answer VERIFY's status\n";
        return 1;
    }
    std::cout << "ADM1_TRIES_LEFT=" << (adm->left ? std::to_string(*adm->left) : "unknown") << "\n";
    const bool pin1_enabled = pin1->left.has_value();
    std::cout << "PIN1=" << (pin1_enabled ? "enabled" : (pin1->sw == 0x9000 ? "disabled" : "unknown")) << "\n";
    if (adm->sw == 0x6983) {
        std::cerr << "ksim-sim: ADM1 is blocked on this card\n";
        return 3;
    }
    if (adm->left && *adm->left < 3) {
        std::cerr << "ksim-sim: ADM1 has fewer than 3 tries left; nothing was sent (your decision now)\n";
        return 3;
    }
    if (o.dry_run) {
        std::cout << "DRY_RUN=1\n";
        return 0;
    }
    // 2. ADM1, once.
    auto kek = secrets::load_kek(o.kek);
    auto sealed = read_file(o.adm1);
    if (!kek || !sealed) {
        std::cerr << "ksim-sim: " << (!kek ? "the KEK" : "the sealed ADM1") << " does not load\n";
        return 1;
    }
    auto opened = secrets::open(*kek, *sealed);
    const SecretBytes* adm1 = opened ? opened->get("adm1") : nullptr;
    if (adm1 == nullptr) {
        std::cerr << "ksim-sim: the sealed file holds no ADM1 for this KEK\n";
        return 1;
    }
    auto block = secrets::pin_block(*adm1);
    if (!block) {
        std::cerr << "ksim-sim: the sealed ADM1 is not 4 to 8 digits\n";
        return 1;
    }
    {
        Bytes v{0x00, 0x20, 0x00, 0x0A, 0x08};
        v.insert(v.end(), block->expose().begin(), block->expose().end());
        auto r = exchange(x, std::move(v));
        if (!r || sw_of(*r) != 0x9000) {
            auto t = tries(x, 0x0A);
            std::cerr << "ksim-sim: the card refused ADM1 (SW " << (r ? fid4(sw_of(*r)) : std::string("none"))
                      << "); tries left " << (t && t->left ? std::to_string(*t->left) : "unknown")
                      << ". Stopped: no second try\n";
            return 1;
        }
    }
    // 3. AF20, then the EFs.
    auto master = secrets::load_kek(o.master);
    if (!master) {
        std::cerr << "ksim-sim: the range master does not load\n";
        return 1;
    }
    const SecretBytes k = secrets::derive(*master, "K", o.imsi);
    const SecretBytes opc = secrets::derive(*master, "OPc", o.imsi);
    {
        auto sel = select_fid(x, 0xAF20);
        auto fcp = sel ? fcp_of(*sel) : std::nullopt;
        const SecretBytes af20 = secrets::milenage_auth_key(k, opc);
        if (!fcp || !fcp->file_size() || *fcp->file_size() < af20.size()) {
            std::cerr << "ksim-sim: the card's EF.USIM_AUTH_KEY (AF20) is missing or too small\n";
            return 1;
        }
        Bytes u{0x00, 0xD6, 0x00, 0x00, static_cast<std::uint8_t>(af20.size())};
        u.insert(u.end(), af20.expose().begin(), af20.expose().end());
        auto r = exchange(x, std::move(u));
        if (!r || sw_of(*r) != 0x9000) {
            std::cerr << "ksim-sim: UPDATE BINARY of AF20 refused\n";
            return 1;
        }
        std::cout << "WROTE=AF20\n";
    }
    CardSource src;
    src.tmpl = o.tmpl;
    src.imsi = o.imsi;
    src.test_keys = true;   // only for the non-secret EF contents; the keys came from the master
    std::string why;
    auto tmpl = make_card(src, why);
    const uicc::os::File* usim = tmpl ? usim_of(tmpl->mf()) : nullptr;
    if (usim == nullptr) {
        std::cerr << "ksim-sim: the template: " << why << "\n";
        return 1;
    }
    struct Want {
        std::uint16_t df;   // 0: ADF.USIM itself
        std::uint16_t fid;
    };
    const std::array<Want, 7> list{{{0, 0x6F07}, {0, 0x6FAD}, {0, 0x6F42}, {0, 0x6F7B}, {0, 0x6F7E}, {0, 0x6F73},
                                    {0x5FC0, 0x4F01}}};
    unsigned written = 0;
    for (const auto& w : list) {
        const uicc::os::File* dir = w.df == 0 ? usim : find_df(*usim, w.df);
        const uicc::os::File* ef = dir != nullptr ? find(*dir, w.fid) : nullptr;
        if (ef == nullptr) {
            continue;
        }
        if (!select_usim(x) || (w.df != 0 && !select_fid(x, w.df))) {
            std::cerr << "ksim-sim: the card lost ADF.USIM\n";
            return 1;
        }
        auto sel = select_fid(x, w.fid);
        auto fcp = sel ? fcp_of(*sel) : std::nullopt;
        if (!fcp) {
            std::cout << "SKIPPED=" << fid4(w.fid) << " (not on the card)\n";
            continue;
        }
        bool done = true;
        if (uicc::os::is_record(ef->kind)) {
            const auto fd = fcp->file_descriptor();
            for (std::size_t i = 0; i < ef->records.size() && done; ++i) {
                if (!fd || !fd->record_length || *fd->record_length != ef->records[i].size()) {
                    done = false;
                    break;
                }
                Bytes u{0x00, 0xDC, static_cast<std::uint8_t>(i + 1), 0x04, static_cast<std::uint8_t>(ef->records[i].size())};
                u.insert(u.end(), ef->records[i].begin(), ef->records[i].end());
                auto r = exchange(x, std::move(u));
                done = r && sw_of(*r) == 0x9000;
            }
        } else {
            const auto size = fcp->file_size();
            if (!size || *size < ef->data.size() || ef->data.size() > 255) {
                done = false;
            } else {
                Bytes u{0x00, 0xD6, 0x00, 0x00, static_cast<std::uint8_t>(ef->data.size())};
                u.insert(u.end(), ef->data.begin(), ef->data.end());
                auto r = exchange(x, std::move(u));
                done = r && sw_of(*r) == 0x9000;
            }
        }
        std::cout << (done ? "WROTE=" : "SKIPPED=") << fid4(w.fid) << (done ? "" : " (size or access)") << "\n";
        written += done ? 1U : 0U;
    }
    // 4. the IMSI read back.
    std::string read_imsi;
    if (select_usim(x) && select_fid(x, 0x6F07)) {
        auto r = exchange(x, Bytes{0x00, 0xB0, 0x00, 0x00, 0x09});
        if (r && ok(*r)) {
            read_imsi = uicc::image::decode_imsi(ByteView(r->data(), r->size() - 2));
        }
    }
    std::cout << "IMSI_READ=" << (read_imsi.empty() ? "none" : read_imsi) << "\n";
    // 5. AUTHENTICATE with SQN 0 (TS 33.102 §6.3.3, §6.3.5).
    std::string check = "FAIL";
    if (pin1_enabled) {
        check = "NEEDS_PIN1_DISABLED";
    } else {
        auto rnd = crypto::aead::random_bytes(16);
        const Bytes sqn(6, 0x00);
        const Bytes amf{0x80, 0x00};
        auto m = rnd ? crypto::milenage::compute(k, opc, *rnd, sqn, amf) : Result<crypto::milenage::Outputs>(rnd.error());
        if (m) {
            Bytes autn(16);
            for (std::size_t i = 0; i < 6; ++i) {
                autn[i] = static_cast<std::uint8_t>(sqn[i] ^ m->ak.expose()[i]);
            }
            autn[6] = amf[0];
            autn[7] = amf[1];
            std::copy(m->mac_a.begin(), m->mac_a.end(), autn.begin() + 8);
            Bytes c{0x00, 0x88, 0x00, 0x81};
            const Bytes ch = uicc::encode_auth_challenge(uicc::AuthChallenge{*rnd, autn}, uicc::AuthContext::umts);
            c.push_back(static_cast<std::uint8_t>(ch.size()));
            c.insert(c.end(), ch.begin(), ch.end());
            c.push_back(0x00);
            auto r = select_usim(x) ? exchange(x, std::move(c)) : Result<Bytes>(make_error(Errc::closed, 0, ""));
            if (r && ok(*r)) {
                auto res = uicc::decode_auth_result(ByteView(r->data(), r->size() - 2), uicc::AuthContext::umts);
                if (res && res->kind == uicc::AuthResult::Kind::success) {
                    check = res->res == Bytes(m->res.expose().begin(), m->res.expose().end()) ? "PASS_RES" : "FAIL_RES";
                } else if (res && res->kind == uicc::AuthResult::Kind::sync_failure && res->auts.size() == 14) {
                    // AUTS = SQN_MS xor AK* || MAC-S, MAC-S = f1*(K, SQN_MS, RAND, AMF '0000').
                    Bytes sqn_ms(6);
                    for (std::size_t i = 0; i < 6; ++i) {
                        sqn_ms[i] = static_cast<std::uint8_t>(res->auts[i] ^ m->ak_star.expose()[i]);
                    }
                    auto m2 = crypto::milenage::compute(k, opc, *rnd, sqn_ms, Bytes{0x00, 0x00});
                    const Bytes mac_s(res->auts.begin() + 6, res->auts.end());
                    check = m2 && m2->mac_s == mac_s ? "PASS_AUTS" : "FAIL_AUTS";
                }
                secure_zero(*r);
            } else if (r) {
                check = "FAIL_SW_" + fid4(sw_of(*r));   // 9862: the card's MAC check failed, so K or OPc differ
            }
        }
    }
    auto salt = crypto::aead::random_bytes(16);
    std::cout << "EFS_WRITTEN=" << written << "\nAUTH_CHECK=" << check << "\n";
    if (salt) {
        std::cout << "BATCH_SALT=" << to_hex(*salt) << "\nIMSI=" << o.imsi
                  << " K_FPR=" << secrets::key_fingerprint(*salt, k) << "\n";
    }
    const bool good = read_imsi == o.imsi && (check == "PASS_RES" || check == "PASS_AUTS" || check == "NEEDS_PIN1_DISABLED");
    std::cout << "BURN=" << (good ? "PASS" : "FAIL") << "\n";
    return good ? 0 : 1;
}

#ifdef KSIM_HAVE_PCSC
int burn_pcsc(const BurnOptions& o) {
    auto names = uicc::pcsc::readers();
    if (!names) {
        std::cerr << "ksim-sim: " << names.error().what << "\n";
        return 1;
    }
    auto reader = uicc::pcsc::pick(*names, o.reader);
    if (!reader) {
        std::cerr << "ksim-sim: --pcsc: " << reader.error().what << "\n";
        return 2;
    }
    auto card = uicc::pcsc::PcscCard::open(*reader);
    if (!card) {
        std::cerr << "ksim-sim: " << *reader << ": " << card.error().what << "\n";
        return 1;
    }
    auto atr = (*card)->atr();
    std::cout << "READER=" << *reader << "\nATR=" << (atr ? to_hex(*atr) : std::string("none")) << "\n";
    return burn(o, [&](ByteView c) { return (*card)->transmit(c); });
}
#else
int burn_pcsc(const BurnOptions&) {
    std::cerr << "ksim-sim: this build has no PC/SC (KSIM_PCSC is off)\n";
    return 2;
}
#endif

int adm1_seal(const std::string& out, const std::string& kek_file, bool from_stdin) {
    auto kek = secrets::load_kek(kek_file);
    if (!kek) {
        std::cerr << "ksim-sim: the KEK: " << kek.error().what << "\n";
        return 1;
    }
    std::string line;
    if (from_stdin) {
        std::getline(std::cin, line);
    } else {
        const int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            std::cerr << "ksim-sim: no terminal (--stdin to read a line from stdin)\n";
            return 2;
        }
        termios old{};
        ::tcgetattr(fd, &old);
        termios quiet = old;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(fd, TCSANOW, &quiet);
        const char prompt[] = "ADM1 (not shown): ";
        (void)!::write(fd, prompt, sizeof prompt - 1);
        char ch = 0;
        while (::read(fd, &ch, 1) == 1 && ch != '\n' && line.size() < 64) {
            line.push_back(ch);
        }
        ::tcsetattr(fd, TCSANOW, &old);
        (void)!::write(fd, "\n", 1);
        ::close(fd);
    }
    SecretBytes digits = SecretBytes::copy_of(ByteView(reinterpret_cast<const std::uint8_t*>(line.data()), line.size()));   // NOLINT
    secure_zero(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(line.data()), line.size()));   // NOLINT
    if (!secrets::pin_block(digits)) {
        std::cerr << "ksim-sim: ADM1 is 4 to 8 digits\n";
        return 2;
    }
    secrets::SecretMap m;
    m.set("adm1", std::move(digits));
    auto sealed = secrets::seal(*kek, m);
    if (!sealed) {
        std::cerr << "ksim-sim: " << sealed.error().what << "\n";
        return 1;
    }
    const int fd = ::open(out.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        std::cerr << "ksim-sim: " << out << ": cannot create (it exists?)\n";
        return 1;
    }
    const ssize_t n = ::write(fd, sealed->data(), sealed->size());
    ::close(fd);
    std::cout << (n == static_cast<ssize_t>(sealed->size()) ? "SEALED=" + out : std::string("SHORT_WRITE")) << "\n";
    return n == static_cast<ssize_t>(sealed->size()) ? 0 : 1;
}

} // namespace ksim::sim
