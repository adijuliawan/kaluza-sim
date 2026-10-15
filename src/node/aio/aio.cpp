// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/aio.hpp"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <algorithm>
#include <utility>

#include "codec/air/kair.hpp"
#include "net/netd.hpp"
#include "net/sctp.hpp"
#include "net/udp.hpp"
#include "platform/memlink.hpp"
#include "platform/yaml.hpp"
#include "proc/ran/cucp.hpp"
#include "proc/ran/cuup.hpp"
#include "proc/ran/du.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"

namespace ksim::node {

namespace {

constexpr std::size_t kEventRing = 1U << 16;
constexpr std::size_t kInbox = 1U << 16;
const Endpoint kDuAir = Endpoint::v4(10, 255, 0, 1, 41000);
// F1-U between the DU and the CU-UP, in memory (the addresses only name the ends).
const Endpoint kCuUpF1u = Endpoint::v4(10, 255, 0, 4, 2152);
const Endpoint kDuF1u = Endpoint::v4(10, 255, 0, 5, 2152);

std::array<std::uint8_t, 4> v4_of(const Endpoint& e) { return {e.addr[0], e.addr[1], e.addr[2], e.addr[3]}; }

Endpoint ue_air(std::size_t index) {
    return Endpoint::v4(10, 254, static_cast<std::uint8_t>(index >> 8), static_cast<std::uint8_t>(index & 0xFF), 41001);
}

std::string imsi_at(const std::string& first, unsigned offset) {
    std::array<char, 24> buf{};
    std::snprintf(buf.data(), buf.size(), "%015llu", std::stoull(first) + offset);
    return std::string(buf.data());
}

Result<Bytes> read_all(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return make_error(Errc::io, 0, "cannot read a sealed card file");
    }
    return Bytes{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

AllInOne::AllInOne(Topology t, std::string run_dir)
    : topo_(std::move(t)), run_dir_(std::move(run_dir)), events_(kEventRing, clock_) {}

AllInOne::~AllInOne() { stop(); }

std::unique_ptr<AllInOne> AllInOne::start(const Topology& t, const std::string& run_dir, std::string& why) {
    std::unique_ptr<AllInOne> a(new AllInOne(t, run_dir));   // NOLINT(cppcoreguidelines-owning-memory): private constructor
    auto ef = EventFile::open(run_dir + "/events.ndjson");
    if (!ef) {
        why = ef.error().what;
        return nullptr;
    }
    a->event_file_ = std::move(*ef);
    a->events_.on_emit([f = a->event_file_.get()](const Event& e) { f->write(e); });
    auto cap = Capture::open(run_dir);
    if (!cap) {
        why = cap.error().what;
        return nullptr;
    }
    a->capture_ = std::move(*cap);
    a->shard_ = std::make_unique<Shard>(0, kInbox, a->clock_);
    a->shard_->start();
    auto built = a->call<std::string>(
        [raw = a.get()] {
            std::string w;
            auto r = raw->build(w);
            if (r) {
                return std::string();
            }
            return w.empty() ? std::string(r.error().what) : w;
        },
        std::chrono::seconds(60));
    if (!built || !built->empty()) {
        why = built ? *built : "the shard did not start";
        a->stop();
        return nullptr;
    }
    return a;
}

Result<void> AllInOne::build(std::string& why) {
    auto kek = uicc::secrets::load_kek(topo_.kek_file);
    if (!kek) {
        why = std::string("the KEK: ") + kek.error().what;
        return kek.error();
    }
    // The cards first: nothing goes on air until every one is good.
    struct Card {
        std::string imsi;
        std::string group;
        const UeGroup* g;
        std::unique_ptr<uicc::os::Card> card;
    };
    std::vector<Card> cards;
    std::vector<Slice> slices;   // the gNB's: every slice a UE group asks for
    for (const auto& g : topo_.ues) {
        for (const auto& s : g.nssai) {
            if (std::find(slices.begin(), slices.end(), s) == slices.end()) {
                slices.push_back(s);
            }
        }
        for (unsigned i = 0; i < g.count; ++i) {
            const std::string imsi = imsi_at(g.first_imsi, i);
            auto sub = uicc::image::range_subscriber(imsi);
            if (!sub) {
                why = "imsi-" + imsi + ": " + sub.error().what;
                return sub.error();
            }
            auto sealed = read_all(topo_.sealed_dir + "/imsi-" + imsi + ".sec");
            if (!sealed) {
                why = "imsi-" + imsi + ": no sealed card secrets in " + topo_.sealed_dir + " (ksim-sim range derive)";
                return sealed.error();
            }
            auto secrets = uicc::secrets::open(*kek, *sealed);
            if (!secrets) {
                why = "imsi-" + imsi + ": the sealed card secrets do not open with this KEK";
                return secrets.error();
            }
            try {
                auto card = uicc::image::load(Yaml::load_file(g.card_template), *secrets);
                if (auto p = uicc::image::personalise(*card, *sub); !p) {
                    why = "imsi-" + imsi + ": " + p.error().what;
                    return p.error();
                }
                cards.push_back(Card{imsi, g.group, &g, std::move(card)});
            } catch (const YamlError& e) {
                why = std::string("the card template: ") + e.what();
                return make_error(Errc::invalid_argument, 0, "the card template is not valid");
            }
        }
    }

    // The system's side, made once: netd's namespaces, the N3 socket, the air.
    Capture* cap = capture_.get();
    link_ = MemLinkConfig{1, 0, topo_.seed};
    const MemLinkConfig link = link_;
    if (topo_.netd.enabled) {
        auto c = net::netd::Client::connect(topo_.netd.socket);
        if (!c) {
            why = "ksim-netd: " + std::string(c.error().what) + " at " + topo_.netd.socket;
            return c.error();
        }
        netd_ = std::make_unique<net::netd::Client>(std::move(*c));
        if (topo_.netd.ues) {
            ue_net_ = std::make_unique<NetdUeNet>(*netd_, shard_->reactor());
        }
    }
    if (topo_.netd.enabled && topo_.netd.nodes) {
        // The CU-CP's namespace with its address (ADR 0009 point 4); a namespace
        // left by a run that died is ours, so it is replaced.
        std::array<std::uint8_t, 4> addr{};
        std::copy(topo_.ng_bind.addr.begin(), topo_.ng_bind.addr.begin() + 4, addr.begin());
        auto up = netd_->setup_node(topo_.netd.netns, topo_.netd.parent, addr, topo_.netd.prefix);
        if (!up && netd_->last_error() == "netd: the namespace exists") {
            (void)netd_->teardown(topo_.netd.netns);
            up = netd_->setup_node(topo_.netd.netns, topo_.netd.parent, addr, topo_.netd.prefix);
        }
        if (!up) {
            why = "ksim-netd: " + netd_->last_error();
            return up.error();
        }
    }
    // N3 (P1 N10): UDP 2152 on the CU-UP's address; with netd, from its own namespace.
    std::unique_ptr<net::UdpSocket> n3;
    if (topo_.netd.enabled && topo_.netd.nodes) {
        auto up = netd_->setup_node(topo_.netd.cuup_netns, topo_.netd.parent, v4_of(topo_.n3_bind), topo_.netd.prefix);
        if (!up && netd_->last_error() == "netd: the namespace exists") {
            (void)netd_->teardown(topo_.netd.cuup_netns);
            up = netd_->setup_node(topo_.netd.cuup_netns, topo_.netd.parent, v4_of(topo_.n3_bind), topo_.netd.prefix);
        }
        if (!up) {
            why = "ksim-netd (N3): " + netd_->last_error();
            return up.error();
        }
        auto fd = netd_->socket(topo_.netd.cuup_netns, net::netd::SockKind::udp, 4);
        if (!fd) {
            why = "ksim-netd (N3 socket): " + netd_->last_error();
            return fd.error();
        }
        auto s = net::UdpSocket::bind(shard_->reactor(), std::move(*fd), topo_.n3_bind);
        if (!s) {
            why = "N3 bind " + topo_.n3_bind.to_string() + ": " + s.error().what;
            return s.error();
        }
        n3 = std::move(*s);
    } else {
        auto s = net::UdpSocket::bind(shard_->reactor(), topo_.n3_bind);
        if (!s) {
            why = "N3 bind " + topo_.n3_bind.to_string() + ": " + s.error().what;
            return s.error();
        }
        n3 = std::move(*s);
    }
    n3_ = std::make_unique<TapDatagram>(std::move(n3), [cap](const Endpoint& from, const Endpoint& to, ByteView p) {
        cap->gtpu(from, to, p);
    });
    air_ = std::make_unique<MemNet>(link);
    auto du_air = air_->bind(*shard_, kDuAir);
    if (!du_air) {
        return du_air.error();
    }
    du_air_ = std::move(*du_air);
    du_air_->set_handler([this](ByteView payload, const Endpoint&) {
        auto f = air::decode(payload);
        if (!f) {
            ++stats_.kair_errors;
            return;
        }
        ++stats_.kair_frames;
        if (du_ && shard_->now() >= air_off_until_) {
            du_->on_frame(*f);
        }
    });
    slices_ = slices;
    if (auto r = build_gnb(why); !r) {
        return r;
    }

    // The UE farm: farm index i + 1, radio ID i + 1.
    for (std::size_t i = 0; i < cards.size(); ++i) {
        auto& c = cards[i];
        auto dgram = air_->bind(*shard_, ue_air(i + 1));
        if (!dgram) {
            return dgram.error();
        }
        UeDeviceConfig uc;
        uc.index = static_cast<unsigned>(i + 1);
        uc.supi = c.imsi;
        uc.radio_id = static_cast<std::uint32_t>(i + 1);
        uc.plmn = {topo_.mcc, topo_.mnc};
        for (const auto& s : c.g->nssai) {
            uc.nssai.push_back(nas::ie::Snssai{s.sst, s.sd, std::nullopt, std::nullopt});
        }
        uc.imeisv = c.g->imeisv_tac + c.imsi.substr(9) + "01";
        uc.allow_null_integrity = topo_.allow_null;
        uc.seed = topo_.seed;
        if (ue_net_) {
            uc.netns = "ksim-ue-" + std::to_string(i + 1);
        }
        UeTaps taps;
        taps.rrc = [cap](std::string_view ch, ByteView pdu, const std::string& supi) { cap->rrc(ch, pdu, supi); };
        if (topo_.plain_nas) {
            taps.nas = [cap](bool ul, ByteView plain, const std::string& supi) { cap->nas(ul, plain, supi); };
        }
        ues_.push_back(std::make_unique<UeDevice>(*shard_, events_, std::move(uc), std::move(c.card),
                                                  [this, i](const air::Frame& f) { ue_to_air(i, f); }, taps,
                                                  ue_net_.get()));
        (*dgram)->set_handler([this, i](ByteView payload, const Endpoint&) {
            auto f = air::decode(payload);
            if (!f) {
                ++stats_.kair_errors;
                return;
            }
            ++stats_.kair_frames;
            ues_[i]->on_frame(*f);
        });
        ue_air_.push_back(std::move(*dgram));
        radio_ids_.push_back(static_cast<std::uint32_t>(i + 1));
        groups_.push_back(c.group);
    }

    connect_gnb();
    return {};
}

Result<void> AllInOne::build_gnb(std::string& why) {
    // The gNB's nodes and their links: F1 and E1 over memlink, F1-U over memlink
    // datagrams, NG-C over SCTP (from the CU-CP's namespace with netd), all captured.
    Capture* cap = capture_.get();
    const MemLinkConfig link = link_;
    const std::vector<Slice>& slices = slices_;
    f1_ = std::make_unique<MemAssocPair>(*shard_, Endpoint::v4(10, 255, 0, 2, 0), *shard_,
                                         Endpoint::v4(10, 255, 0, 1, 38472), 2, link);
    f1_tap_ = std::make_unique<TapAssoc>(f1_->b(), [cap](bool tx, ByteView m) { cap->f1ap(tx, m); });
    net::SctpOptions opt;
    opt.out_streams = topo_.ng_streams;
    net::SocketSource source;
    if (netd_ && topo_.netd.nodes) {
        source = [this](int family) { return netd_->socket(topo_.netd.netns, net::netd::SockKind::sctp, family); };
    }
    ng_ = std::make_unique<net::SctpClient>(shard_->reactor(), *shard_, std::vector<Endpoint>{topo_.ng_bind},
                                            std::vector<Endpoint>{topo_.amf}, opt, net::SctpBackoff{}, std::move(source));
    ng_tap_ = std::make_unique<TapAssoc>(*ng_, [cap](bool tx, ByteView m) { cap->ngap(tx, m); });
    auto gtpu_tap = [cap](const Endpoint& from, const Endpoint& to, ByteView p) { cap->gtpu(from, to, p); };
    e1_ = std::make_unique<MemAssocPair>(*shard_, Endpoint::v4(10, 255, 0, 3, 0), *shard_,
                                         Endpoint::v4(10, 255, 0, 1, 38462), 2, link);
    e1_tap_ = std::make_unique<TapAssoc>(e1_->b(), [cap](bool tx, ByteView m) { cap->e1ap(tx, m); });
    f1u_net_ = std::make_unique<MemNet>(link);
    auto cuup_f1u = f1u_net_->bind(*shard_, kCuUpF1u);
    auto du_f1u = f1u_net_->bind(*shard_, kDuF1u);
    if (!cuup_f1u || !du_f1u) {
        return make_error(Errc::internal, 0, "F1-U ports");
    }
    cuup_f1u_ = std::make_unique<TapDatagram>(std::move(*cuup_f1u), gtpu_tap);   // each F1-U datagram once
    du_f1u_ = std::move(*du_f1u);

    proc::ran::CuCpConfig cc;
    cc.id = "gnb:" + topo_.gnb_name;
    cc.name = topo_.gnb_name;
    cc.plmn = {topo_.mcc, topo_.mnc};
    cc.gnb_id = topo_.gnb_id;
    cc.gnb_id_bits = topo_.gnb_id_bits;
    cc.allow_null = topo_.allow_null;
    cc.slices.clear();
    for (const auto& s : slices) {
        cc.slices.push_back(ngap::Snssai{s.sst, s.sd});
    }
    cucp_ = std::make_unique<proc::ran::CuCp>(*shard_, events_, cc, *ng_tap_, *f1_tap_, e1_tap_.get());
    proc::ran::CuUpConfig upc;
    upc.id = "gnb:" + topo_.gnb_name + "-cuup";
    upc.name = topo_.gnb_name + "-cuup";
    upc.plmn = e1ap::plmn_id(topo_.mcc, topo_.mnc);
    upc.slices.clear();
    for (const auto& s : slices) {
        upc.slices.push_back(e1ap::Snssai{s.sst, s.sd});
    }
    upc.n3_addr = v4_of(topo_.n3_bind);
    upc.f1u_addr = v4_of(kCuUpF1u);
    cuup_ = std::make_unique<proc::ran::CuUp>(*shard_, events_, upc, e1_->a(), *n3_, *cuup_f1u_);

    proc::ran::DuConfig dc;
    dc.id = "gnb:" + topo_.gnb_name + "-du";
    dc.du_id = topo_.du_id;
    dc.name = topo_.gnb_name + "-du";
    dc.plmn = {topo_.mcc, topo_.mnc};
    dc.nci = (std::uint64_t{topo_.gnb_id} << (36U - topo_.gnb_id_bits)) | 1U;
    dc.pci = topo_.pci;
    dc.tac = topo_.tac;
    dc.arfcn = topo_.arfcn;
    dc.f1u_addr = v4_of(kDuF1u);
    du_ = std::make_unique<proc::ran::Du>(*shard_, events_, dc, f1_->a(), [this](const air::Frame& f) { du_to_air(f); },
                                          du_f1u_.get());

    (void)why;
    return {};
}

void AllInOne::connect_gnb() {
    f1_->connect();
    e1_->connect();
    ng_->start();
}

void AllInOne::teardown_gnb() {
    du_.reset();
    cuup_.reset();
    cucp_.reset();
    du_f1u_.reset();
    cuup_f1u_.reset();
    f1u_net_.reset();
    e1_tap_.reset();
    e1_.reset();
    if (ng_) {
        ng_->shutdown();
    }
    ng_tap_.reset();
    ng_.reset();
    f1_tap_.reset();
    f1_.reset();
}

Result<void> AllInOne::restart_gnb() {
    // ksim-ctl gnb restart (row amf-ueransim.032): the gNB's processes stop and
    // start again; the UEs find out on the air, the core from a new association.
    // The cell is off the air for a while, as a restarting gNB's is: the UEs
    // connected to it see a radio link failure (ledger A-12).
    teardown_gnb();
    air_off_until_ = shard_->now() + kRestartOffAir;
    events_.emit("ran.gnb.restart", "gnb:" + topo_.gnb_name, {{"off_air_ms", std::to_string(kRestartOffAir)}});
    std::string why;
    if (auto r = build_gnb(why); !r) {
        return r;
    }
    connect_gnb();
    return {};
}

void AllInOne::du_to_air(const air::Frame& f) {
    if (shard_->now() < air_off_until_) {
        return;   // the cell is off the air while the gNB restarts
    }
    auto wire = air::encode(f);
    if (!wire) {
        ++stats_.kair_errors;
        return;
    }
    for (std::size_t i = 0; i < ue_air_.size(); ++i) {
        if (f.radio_id == 0 || f.radio_id == radio_ids_[i]) {
            (void)du_air_->send_to(*wire, ue_air(i + 1));
        }
    }
}

void AllInOne::ue_to_air(std::size_t i, const air::Frame& f) {
    auto wire = air::encode(f);
    if (!wire) {
        ++stats_.kair_errors;
        return;
    }
    (void)ue_air_[i]->send_to(*wire, kDuAir);
}

void AllInOne::teardown() {
    ues_.clear();
    ue_air_.clear();
    teardown_gnb();
    n3_.reset();
    du_air_.reset();
    air_.reset();
    ue_net_.reset();   // after the UEs: each took its namespace down
    if (netd_) {
        if (topo_.netd.nodes) {
            (void)netd_->teardown(topo_.netd.cuup_netns);
            (void)netd_->teardown(topo_.netd.netns);
        }
        netd_.reset();
    }
}

void AllInOne::stop() {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    if (shard_) {
        (void)call<bool>(
            [this] {
                teardown();
                return true;
            },
            std::chrono::seconds(10));
        shard_->stop();
        shard_->join();
    }
    if (capture_) {
        capture_->close();
    }
}

std::vector<UeDevice*> AllInOne::ues() {
    std::vector<UeDevice*> out;
    out.reserve(ues_.size());
    for (auto& u : ues_) {
        out.push_back(u.get());
    }
    return out;
}

UeDevice* AllInOne::ue(const std::string& selector) {
    std::string s = selector;
    if (s.rfind("imsi-", 0) == 0) {
        s = s.substr(5);
    }
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) {
        return nullptr;
    }
    if (s.size() == 15) {
        for (auto& u : ues_) {
            if (u->config().supi == s) {
                return u.get();
            }
        }
        return nullptr;
    }
    if (s.size() > 6) {
        return nullptr;
    }
    const auto index = std::stoul(s);
    return index >= 1 && index <= ues_.size() ? ues_[index - 1].get() : nullptr;
}

bool AllInOne::ng_up() const { return ng_ && ng_->up(); }

} // namespace ksim::node
