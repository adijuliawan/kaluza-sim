// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "card.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>

#include "net/tcp.hpp"
#include "platform/pcapng.hpp"
#include "platform/reactor.hpp"
#include "platform/yaml.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"
#include "uicc/trace/trace.hpp"
#include "uicc/transport/bridge.hpp"
#include "uicc/transport/vpcd.hpp"
#ifdef KSIM_HAVE_PCSC
#include "uicc/transport/pcsc.hpp"
#endif

namespace ksim::sim {

namespace {

volatile std::sig_atomic_t g_stop = 0;
extern "C" void on_signal(int /*sig*/) { g_stop = 1; }

SecretBytes ascii(const char* d) {
    return SecretBytes::copy_of(ByteView(reinterpret_cast<const std::uint8_t*>(d), std::char_traits<char>::length(d)));
}

/// TS 35.208 test set 1 and test PINs: public values, for cards that are never real.
uicc::secrets::SecretMap test_secrets() {
    uicc::secrets::SecretMap s;
    auto k = SecretBytes::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc");
    auto opc = SecretBytes::from_hex("cd63cb71954a9f4e48a5994e37a02baf");
    if (k && opc) {
        s.set("k", std::move(*k));
        s.set("opc", std::move(*opc));
    }
    s.set("pin1", ascii("1234"));
    s.set("puk1", ascii("12345678"));
    s.set("pin2", ascii("5678"));
    s.set("puk2", ascii("87654321"));
    s.set("adm1", ascii("11111111"));
    return s;
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

/// GSMTAP to UDP and/or a pcapng file.
class TraceOut {
public:
    bool open(const ServeOptions& o, std::string& why) {
        if (!o.trace_udp.empty()) {
            auto ep = Endpoint::parse(o.trace_udp);
            if (!ep || ep->family != Endpoint::Family::v4) {
                why = "--trace-udp is an IPv4 host:port";
                return false;
            }
            fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (fd_ < 0) {
                why = "no UDP socket";
                return false;
            }
            to_.sin_family = AF_INET;
            to_.sin_port = htons(ep->port);
            std::memcpy(&to_.sin_addr, ep->addr.data(), 4);
        }
        if (!o.trace_pcap.empty()) {
            const int fd = ::open(o.trace_pcap.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd < 0) {
                why = "cannot create " + o.trace_pcap;
                return false;
            }
            file_ = ::fdopen(fd, "wb");
            pcap_ = std::make_unique<pcap::PcapngWriter>([f = file_](ByteView b) { std::fwrite(b.data(), 1, b.size(), f); });
            iface_ = pcap_->add_interface(pcap::LinkType::ipv4, "sim");
        }
        return true;
    }
    ~TraceOut() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        pcap_.reset();
        if (file_ != nullptr) {
            std::fclose(file_);
        }
    }
    TraceOut() = default;
    TraceOut(const TraceOut&) = delete;
    TraceOut& operator=(const TraceOut&) = delete;

    bool any() const noexcept { return fd_ >= 0 || pcap_ != nullptr; }
    void put(std::uint8_t sub, ByteView payload) {
        const Bytes g = pcap::gsmtap(pcap::kGsmtapSim, sub, payload);
        ++count_;
        if (fd_ >= 0) {
            (void)::sendto(fd_, g.data(), g.size(), 0, reinterpret_cast<const sockaddr*>(&to_), sizeof(to_));
        }
        if (pcap_) {
            pcap::Udp4 u;
            u.src = {127, 0, 0, 1};
            u.dst = {127, 0, 0, 1};
            u.dst_port = pcap::kGsmtapPort;
            if (auto p = pcap::ipv4_udp(u, g)) {
                const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
                (void)pcap_->write(iface_, ns, *p);
                std::fflush(file_);
            }
        }
    }
    std::size_t count() const noexcept { return count_; }

private:
    int fd_ = -1;
    sockaddr_in to_{};
    std::FILE* file_ = nullptr;
    std::unique_ptr<pcap::PcapngWriter> pcap_;
    std::uint32_t iface_ = 0;
    std::size_t count_ = 0;
};

} // namespace

std::unique_ptr<uicc::os::Card> make_card(const CardSource& src, std::string& why) {
    auto sub = uicc::image::range_subscriber(src.imsi);
    if (!sub) {
        why = std::string("--imsi: ") + sub.error().what;
        return nullptr;
    }
    uicc::secrets::SecretMap secrets;
    if (src.test_keys) {
        secrets = test_secrets();
    } else {
        if (src.sealed_dir.empty() || src.kek.empty()) {
            why = "--sealed and --kek, or --test-keys";
            return nullptr;
        }
        auto kek = uicc::secrets::load_kek(src.kek);
        auto sealed = read_file(src.sealed_dir + "/imsi-" + src.imsi + ".sec");
        if (!kek || !sealed) {
            why = !kek ? "the KEK does not load" : "no sealed card secrets for imsi-" + src.imsi;
            return nullptr;
        }
        auto open = uicc::secrets::open(*kek, *sealed);
        if (!open) {
            why = "the sealed card secrets do not open with this KEK";
            return nullptr;
        }
        secrets = std::move(*open);
    }
    try {
        auto card = uicc::image::load(Yaml::load_file(src.tmpl), secrets);
        if (auto p = uicc::image::personalise(*card, *sub); !p) {
            why = p.error().what;
            return nullptr;
        }
        if (!src.personality.empty()) {
            auto atr = uicc::image::personality_atr(src.personality);
            if (!atr) {
                why = "--personality: sysmoISIM-SJA5";
                return nullptr;
            }
            card->set_atr(std::move(*atr));
            card->reset();
        }
        return card;
    } catch (const YamlError& e) {
        why = std::string("the card image: ") + e.what();
        return nullptr;
    }
}

int serve(const ServeOptions& o) {
    if (o.no_redact && !o.card.test_keys) {
        std::cerr << "ksim-sim: --no-redact goes with --test-keys only\n";
        return 2;
    }
    auto at = Endpoint::parse(o.vpcd);
    if (!at) {
        std::cerr << "ksim-sim: --vpcd is host:port\n";
        return 2;
    }
    std::string why;
    auto card = make_card(o.card, why);
    if (!card) {
        std::cerr << "ksim-sim: " << why << "\n";
        return 3;
    }
    TraceOut trace;
    if (!trace.open(o, why)) {
        std::cerr << "ksim-sim: " << why << "\n";
        return 2;
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
    Reactor reactor;
    uicc::trace::Redactor redactor(!o.no_redact);
    std::unique_ptr<IStream> stream;
    std::unique_ptr<uicc::vpcd::VpcdCard> vc;
    std::size_t apdus = 0;
    std::size_t connects = 0;
    bool announced = false;
    const auto start = std::chrono::steady_clock::now();
    auto next_try = start;
    std::cout << "CARD=imsi-" << o.card.imsi << (o.card.test_keys ? " KEYS=test" : "") << "\nVPCD=" << o.vpcd << "\n"
              << std::flush;
    while (g_stop == 0) {
        const auto now = std::chrono::steady_clock::now();
        if (o.seconds != 0 && now - start >= std::chrono::seconds(o.seconds)) {
            break;
        }
        if ((!stream || !stream->open()) && now >= next_try) {
            if (vc) {
                apdus += vc->apdus();
                vc.reset();
                if (announced) {
                    std::cout << "READER=closed\n" << std::flush;
                }
                announced = false;
            }
            stream.reset();
            auto s = net::tcp_connect(reactor, *at);
            if (s) {
                stream = std::move(*s);
                vc = std::make_unique<uicc::vpcd::VpcdCard>(
                    *stream, *card, [&](ByteView c, ByteView r) {
                        if (!announced) {
                            announced = true;
                            ++connects;
                            std::cout << "READER=connected\n" << std::flush;
                        }
                        if (trace.any()) {
                            if (c.empty()) {
                                for (const auto& rec : redactor.flush()) {
                                    trace.put(uicc::trace::kSubApdu, rec);
                                }
                                redactor.reset();
                                trace.put(uicc::trace::kSubAtr, r);
                            } else {
                                for (const auto& rec : redactor.apply(c, r)) {
                                    trace.put(uicc::trace::kSubApdu, rec);
                                }
                            }
                        }
                    });
            }
            next_try = now + std::chrono::milliseconds(500);
        }
        (void)reactor.run_once(100);
    }
    if (vc) {
        apdus += vc->apdus();
    }
    for (const auto& rec : redactor.flush()) {
        trace.put(uicc::trace::kSubApdu, rec);
    }
    vc.reset();
    stream.reset();
    std::cout << "APDUS=" << apdus << "\nCONNECTS=" << connects << "\nTRACED=" << trace.count() << "\n";
    return 0;
}

#ifdef KSIM_HAVE_PCSC
// ---- the card bridge (P2 Q1; lab.md §7) -------------------------------------------------------

int serve_bridge(const BridgeOptions& o) {
    auto at = Endpoint::parse(o.listen);
    auto allow = Endpoint::parse(o.allow, 0);
    if (!at || !allow) {
        std::cerr << "ksim-sim: --listen is host:port and --allow one numeric address\n";
        return 2;
    }
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
    ServeOptions to;
    to.trace_udp = o.trace_udp;
    to.trace_pcap = o.trace_pcap;
    TraceOut trace;
    std::string why;
    if (!trace.open(to, why)) {
        std::cerr << "ksim-sim: " << why << "\n";
        return 2;
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
    Reactor reactor;
    uicc::trace::Redactor redactor(true);
    uicc::bridge::AdminFilter filter(o.admin);
    std::unique_ptr<IStream> client;
    std::unique_ptr<uicc::vpcd::Deframer> in;
    std::size_t apdus = 0;
    std::size_t clients = 0;
    std::size_t turned_away = 0;
    auto answer = [&](ByteView payload) {
        if (client && client->open()) {
            (void)client->send(uicc::vpcd::frame(payload));
        }
    };
    auto on_message = [&](ByteView m) {
        if (m.size() == 1) {
            if (m[0] == uicc::vpcd::kPowerOn || m[0] == uicc::vpcd::kReset) {
                filter.reset();
                auto atr = (*card)->reset();
                if (trace.any() && atr) {
                    for (const auto& rec : redactor.flush()) {
                        trace.put(uicc::trace::kSubApdu, rec);
                    }
                    redactor.reset();
                    trace.put(uicc::trace::kSubAtr, *atr);
                }
            } else if (m[0] == uicc::vpcd::kAtr) {
                auto atr = (*card)->atr();
                answer(atr ? ByteView(*atr) : ByteView());
            }
            return;
        }
        ++apdus;
        Bytes rsp;
        if (auto sw = filter.check(m)) {
            rsp = {static_cast<std::uint8_t>(*sw >> 8), static_cast<std::uint8_t>(*sw & 0xFF)};
        } else if (auto r = (*card)->transmit(m)) {
            rsp = std::move(*r);
        } else {
            rsp = {0x6F, 0x00};   // no precise diagnosis (TS 102 221 §10.2.1.6)
        }
        if (trace.any()) {
            for (const auto& rec : redactor.apply(m, rsp)) {
                trace.put(uicc::trace::kSubApdu, rec);
            }
        }
        answer(rsp);
        secure_zero(rsp);
    };
    auto listener = net::TcpListener::listen(reactor, *at, [&](std::unique_ptr<IStream> s) {
        const Endpoint peer = s->peer();
        if (peer.family != allow->family || peer.addr != allow->addr || (client && client->open())) {
            ++turned_away;
            std::cout << "REFUSED=" << peer.host() << (client && client->open() ? " (a client is connected)" : "") << "\n"
                      << std::flush;
            s->close();
            return;
        }
        client = std::move(s);
        ++clients;
        in = std::make_unique<uicc::vpcd::Deframer>(on_message);
        client->set_handlers([&](ByteView d) { in->feed(d); },
                             [&] { std::cout << "CLIENT=closed\n" << std::flush; });
        std::cout << "CLIENT=" << peer.host() << "\n" << std::flush;
    });
    if (!listener) {
        std::cerr << "ksim-sim: cannot listen on " << o.listen << ": " << listener.error().what << "\n";
        return 1;
    }
    std::cout << "BRIDGE=" << o.listen << "\nREADER=" << *reader << "\nALLOW=" << o.allow << "\nADMIN=" << (o.admin ? 1 : 0)
              << "\n" << std::flush;
    const auto start = std::chrono::steady_clock::now();
    while (g_stop == 0) {
        if (o.seconds != 0 && std::chrono::steady_clock::now() - start >= std::chrono::seconds(o.seconds)) {
            break;
        }
        (void)reactor.run_once(100);
    }
    for (const auto& rec : redactor.flush()) {
        trace.put(uicc::trace::kSubApdu, rec);
    }
    if (client) {
        client->close();
    }
    std::cout << "APDUS=" << apdus << "\nREFUSED_APDUS=" << filter.refused() << "\nCLIENTS=" << clients
              << "\nTURNED_AWAY=" << turned_away << "\nTRACED=" << trace.count() << "\n";
    return 0;
}
#else
int serve_bridge(const BridgeOptions&) {
    std::cerr << "ksim-sim: this build has no PC/SC (KSIM_PCSC is off)\n";
    return 2;
}
#endif

// ---- validate, export, import ----

namespace {

using uicc::os::File;
using uicc::os::Kind;

std::string fid_hex(std::uint16_t f) {
    static const char* d = "0123456789ABCDEF";
    return {d[f >> 12 & 15], d[f >> 8 & 15], d[f >> 4 & 15], d[f & 15]};
}

/// The names from the MF down, as pySim writes paths (MF/ADF.USIM/EF.IMSI).
std::string name_path(const File& f) {
    std::vector<const File*> up;
    for (const File* q = &f; q != nullptr; q = q->parent) {
        up.push_back(q);
    }
    std::string p;
    for (auto it = up.rbegin(); it != up.rend(); ++it) {
        p += (p.empty() ? "" : "/") + (*it)->name;
    }
    return p;
}

std::string path_of(const File& f) {
    std::vector<const File*> up;
    for (const File* q = &f; q != nullptr; q = q->parent) {
        up.push_back(q);
    }
    std::string p;
    for (auto it = up.rbegin(); it != up.rend(); ++it) {
        p += (p.empty() ? "" : "/") + fid_hex((*it)->fid);
    }
    return p;
}

template <class Fn>
void walk(File& f, Fn&& fn) {
    fn(f);
    for (auto& c : f.children) {
        walk(*c, fn);
    }
}

bool service(const File* ust, unsigned n) {
    if (ust == nullptr || n == 0 || (n - 1) / 8 >= ust->data.size()) {
        return false;
    }
    return (ust->data[(n - 1) / 8] >> ((n - 1) % 8) & 1) != 0;
}

/// TS 31.102 j60 4.2.8 and 4.4.11: the EFs a service brings into ADF.USIM or DF.5GS.
struct ServiceFiles {
    unsigned service;
    std::vector<std::uint16_t> fids;
};
const std::vector<ServiceFiles>& service_files() {
    static const std::vector<ServiceFiles> t{
        {10, {0x6F3C}},  {12, {0x6F42}}, {19, {0x6F46}}, {20, {0x6F60}}, {21, {0x6F40}},
        {42, {0x6F61}},  {43, {0x6F62}}, {45, {0x6FC5}}, {71, {0x6FD9}},
        {122, {0x4F01, 0x4F02, 0x4F03, 0x4F04}},          // 4.4.11.2-5
        {123, {0x4F05}},                                    // 4.4.11.6 (with 133: 110 octets)
        {124, {0x4F0A}},                                    // 4.4.11.11
        {126, {0x4F06}},                                    // 4.4.11.7
        {129, {0x4F08}},                                    // 4.4.11.9
        {130, {0x4F09}},                                    // 4.4.11.10
    };
    return t;
}

std::size_t ef_size(const File& f) {
    if (uicc::os::is_record(f.kind)) {
        return f.records.size() * f.record_len;
    }
    return f.secret ? f.secret_data.size() : f.data.size();
}

} // namespace

int validate(const std::string& image, bool access) {
    std::unique_ptr<uicc::os::Card> card;
    try {
        card = uicc::image::load(Yaml::load_file(image), test_secrets());
    } catch (const YamlError& e) {
        std::cout << "VALID=0\nPROBLEM=" << e.what() << "\n";
        return 1;
    }
    std::vector<std::string> problems;
    auto problem = [&](const File& f, const std::string& what) {
        problems.push_back(path_of(f) + " " + (f.name.empty() ? "" : f.name + ": ") + what);
    };
    std::size_t efs = 0;
    File& mf = card->mf();
    walk(mf, [&](File& f) {
        if (!uicc::os::is_df(f.kind)) {
            ++efs;
        }
        // The access rule's EF.ARR and record (TS 102 221 11.1.1.4.7.3).
        if (f.arr.fid != 0) {
            const File& df = uicc::os::is_df(f.kind) ? f : *f.parent;
            const File* arr = card->find_ef(df, f.arr.fid);
            if (arr == nullptr) {
                problem(f, "its EF.ARR " + fid_hex(f.arr.fid) + " is not reachable");
            } else if (f.arr.record == 0 || f.arr.record > arr->records.size()) {
                problem(f, "EF.ARR has no record " + std::to_string(f.arr.record));
            }
        } else {
            problem(f, "no access rule");
        }
        if (uicc::os::is_df(f.kind)) {
            std::vector<std::uint16_t> fids;
            std::vector<std::uint8_t> sfis;
            for (const auto& c : f.children) {
                if (std::find(fids.begin(), fids.end(), c->fid) != fids.end()) {
                    problem(*c, "a second file with this FID");
                }
                fids.push_back(c->fid);
                if (c->sfi) {
                    if (*c->sfi == 0 || *c->sfi > 30) {
                        problem(*c, "SFI out of 1..30");
                    }
                    if (std::find(sfis.begin(), sfis.end(), *c->sfi) != sfis.end()) {
                        problem(*c, "a second file with this SFI");
                    }
                    sfis.push_back(*c->sfi);
                }
            }
            return;
        }
        if (uicc::os::is_record(f.kind)) {
            if (f.record_len == 0 || f.records.empty()) {
                problem(f, "a record file with no records");
            }
            for (std::size_t i = 0; i < f.records.size(); ++i) {
                if (f.records[i].size() != f.record_len) {
                    problem(f, "record " + std::to_string(i + 1) + " is not record_len long");
                }
            }
        } else if (ef_size(f) == 0) {
            problem(f, "an empty transparent EF");
        }
    });
    // EF.DIR names applications the card has (TS 102 221 13.1).
    if (File* dir = mf.child(0x2F00)) {
        for (const auto& r : dir->records) {
            if (r.size() < 4 || r[0] != 0x61 || r[2] != 0x4F) {
                continue;
            }
            const auto n = static_cast<std::ptrdiff_t>(std::min<std::size_t>(r[3], r.size() - 4));
            const Bytes aid(r.begin() + 4, r.begin() + 4 + n);
            bool found = false;
            for (const auto& c : mf.children) {
                found = found || (c->kind == Kind::adf && c->aid == aid);
            }
            if (!found) {
                problem(*dir, "names AID " + to_hex(aid) + " the card does not have");
            }
        }
    }
    // The files of the USIM's services (TS 31.102 4.2.8, 4.4.11).
    File* adf = uicc::image::usim_adf(*card);
    if (adf == nullptr) {
        problems.emplace_back("3F00: no ADF.USIM");
    } else {
        File* ust = adf->child(0x6F38);
        if (ust == nullptr) {
            problem(*adf, "no EF.UST");
        }
        if (!service(ust, 33)) {
            problem(*adf, "UST service 33 shall be set (4.2.8)");
        }
        if (service(ust, 123) && !service(ust, 133)) {
            problem(*adf, "UST 123 without 133 (4.2.8)");
        }
        if (service(ust, 129) && !service(ust, 45)) {
            problem(*adf, "UST 129 without 45 (4.2.8)");
        }
        File* df5gs = adf->child(0x5FC0);
        for (const auto& sf : service_files()) {
            for (std::uint16_t fid : sf.fids) {
                File* in = (fid >> 8) == 0x4F ? (df5gs != nullptr ? df5gs->child(fid) : nullptr) : adf->child(fid);
                if (service(ust, sf.service) && in == nullptr) {
                    problem(*adf, "UST " + std::to_string(sf.service) + " is set but " + fid_hex(fid) + " is missing");
                }
            }
        }
        if (service(ust, 124) && !service(ust, 125) && (df5gs == nullptr || df5gs->child(0x4F07) == nullptr)) {
            problem(*adf, "UST 124 without 125 needs EF.SUCI_Calc_Info (4.4.11.8)");
        }
        if (df5gs != nullptr) {
            if (File* keys = df5gs->child(0x4F05); keys != nullptr && service(ust, 133) && ef_size(*keys) != 110) {
                problem(*keys, "110 octets with UST 133 (4.4.11.6), not " + std::to_string(ef_size(*keys)));
            }
            for (std::uint16_t nsc : {std::uint16_t{0x4F03}, std::uint16_t{0x4F04}}) {
                if (File* f = df5gs->child(nsc); f != nullptr && f->record_len < 57) {
                    problem(*f, "records of 57 octets at least (4.4.11.4)");
                }
            }
        }
    }
    // Key material is never readable, not even with ADM1 (sim-uicc.md §3).
    const Bytes adm = *from_hex("0020000A083131313131313131");
    (void)card->process(adm);
    walk(mf, [&](File& f) {
        if (f.secret && card->allowed(f, 0x01)) {
            problem(f, "key material readable");
        }
    });
    card->reset();
    std::cout << "VALID=" << (problems.empty() ? 1 : 0) << "\nEFS=" << efs << "\n";
    for (const auto& p : problems) {
        std::cout << "PROBLEM=" << p << "\n";
    }
    if (access) {
        walk(mf, [&](File& f) {
            if (!uicc::os::is_df(f.kind)) {
                std::cout << "EF=" << path_of(f) << " NAME=" << name_path(f)
                          << " READ=" << (card->allowed(f, 0x01) ? "granted" : "denied") << "\n";
            }
        });
    }
    return problems.empty() ? 0 : 1;
}

int export_script(const CardSource& src) {
    std::string why;
    auto card = make_card(src, why);
    if (!card) {
        std::cerr << "ksim-sim: " << why << "\n";
        return 3;
    }
    std::cout << "# pySim-shell script: the contents of imsi-" << src.imsi << " (ksim-sim export).\n"
              << "# Key files, NAS security contexts and PINs are left out: verify ADM1 before running it.\n";
    // Keys and key state, the access rules, and what those rules keep from a reader.
    auto skip = [&card](const File& f) {
        return f.secret || uicc::os::key_fid(f.fid) || f.fid == 0x2F06 || f.fid == 0x6F06 || !card->allowed(f, 0x01);
    };
    std::function<void(File&, const std::string&)> write_df = [&](File& df, const std::string& sel) {
        std::cout << sel;
        for (auto& c : df.children) {
            if (uicc::os::is_df(c->kind)) {
                continue;
            }
            if (skip(*c)) {
                std::cout << "# " << c->name << " (" << fid_hex(c->fid) << ") left out\n";
                continue;
            }
            std::cout << "select " << to_hex(Bytes{static_cast<std::uint8_t>(c->fid >> 8), static_cast<std::uint8_t>(c->fid)})
                      << "\n";
            if (uicc::os::is_record(c->kind)) {
                for (std::size_t i = 0; i < c->records.size(); ++i) {
                    std::cout << "update_record " << i + 1 << " " << to_hex(c->records[i]) << "\n";
                }
            } else {
                std::cout << "update_binary " << to_hex(c->data) << "\n";
            }
        }
        for (auto& c : df.children) {
            if (c->kind == Kind::adf) {
                write_df(*c, "select MF\nselect ADF.USIM\n");
            } else if (c->kind == Kind::df) {
                write_df(*c, sel + "select " + to_hex(Bytes{static_cast<std::uint8_t>(c->fid >> 8), static_cast<std::uint8_t>(c->fid)}) + "\n");
            }
        }
    };
    write_df(card->mf(), "select MF\n");
    return 0;
}

int import_fsdump(const std::string& fsdump, const std::string& tmpl, const std::string& out) {
    std::ifstream in(fsdump);
    if (!in) {
        std::cerr << "ksim-sim: cannot read " << fsdump << "\n";
        return 2;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();
    const auto open = text.find('{');
    const auto close = text.rfind('}');
    nlohmann::json dump;
    try {
        dump = nlohmann::json::parse(text.substr(open, close == std::string::npos ? 0 : close - open + 1));
    } catch (const std::exception&) {
        std::cerr << "ksim-sim: " << fsdump << " holds no fsdump JSON\n";
        return 2;
    }
    std::unique_ptr<uicc::os::Card> card;
    try {
        card = uicc::image::load(Yaml::load_file(tmpl), test_secrets());
    } catch (const YamlError& e) {
        std::cerr << "ksim-sim: the template: " << e.what() << "\n";
        return 2;
    }
    // pySim names files by path ("MF/ADF.USIM/EF.IMSI"); ours have names too.
    std::map<std::string, nlohmann::json> by_name;
    const nlohmann::json files = dump.value("files", nlohmann::json::object());
    for (const auto& [path, f] : files.items()) {
        std::string n = path.substr(path.rfind('/') + 1);
        std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        by_name[n] = f;
    }
    std::size_t imported = 0;
    std::size_t kept = 0;
    walk(card->mf(), [&](File& f) {
        if (uicc::os::is_df(f.kind)) {
            return;
        }
        if (f.secret || uicc::os::key_fid(f.fid)) {
            ++kept;
            return;
        }
        std::string n = f.name;
        std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        auto it = by_name.find(n);
        if (it == by_name.end() || !it->second.contains("body")) {
            ++kept;
            return;
        }
        const auto& body = it->second["body"];
        if (uicc::os::is_record(f.kind) && body.is_array()) {
            std::vector<Bytes> recs;
            for (const auto& r : body) {
                auto b = r.is_string() ? from_hex(r.get<std::string>()) : Result<Bytes>(make_error(Errc::malformed, 0, ""));
                if (!b || b->size() != f.record_len) {
                    ++kept;
                    return;
                }
                recs.push_back(std::move(*b));
            }
            f.records = std::move(recs);
            ++imported;
        } else if (!uicc::os::is_record(f.kind) && body.is_string()) {
            auto b = from_hex(body.get<std::string>());
            if (!b || b->empty()) {
                ++kept;
                return;
            }
            f.data = std::move(*b);
            ++imported;
        } else {
            ++kept;
        }
    });
    uicc::secrets::SecretMap sealed;
    const std::string yaml = uicc::image::save(*card, sealed);
    const int fd = ::open(out.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        std::cerr << "ksim-sim: cannot create " << out << "\n";
        return 2;
    }
    const auto n = ::write(fd, yaml.data(), yaml.size());
    ::close(fd);
    if (n != static_cast<ssize_t>(yaml.size())) {
        std::cerr << "ksim-sim: " << out << " was not written whole\n";
        return 2;
    }
    std::cout << "IMPORTED=" << imported << "\nKEPT=" << kept << "\nOUT=" << out << "\n";
    return 0;
}

} // namespace ksim::sim
