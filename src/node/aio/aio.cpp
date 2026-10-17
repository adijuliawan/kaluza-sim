// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/aio.hpp"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <algorithm>
#include <ctime>
#include <thread>
#include <utility>

#include "codec/air/kair.hpp"
#include "net/netd.hpp"
#include "net/seqpacket.hpp"
#include "net/tcp.hpp"
#include "net/sctp.hpp"
#include "net/udp.hpp"
#include "platform/log.hpp"
#include "platform/memlink.hpp"
#include "platform/yaml.hpp"
#include "proc/ran/cucp.hpp"
#include "proc/ran/cuup.hpp"
#include "proc/ran/du.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"
#include "uicc/transport/vpcd.hpp"
#ifdef KSIM_HAVE_PCSC
#include "uicc/transport/pcsc.hpp"
#endif

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
    a->events_.on_emit([f = a->event_file_.get(), m = &a->metrics_](const Event& e) {
        f->write(e);
        m->count_event(e);   // P2 Q7: metrics v0
    });
    auto cap = Capture::open(run_dir, a->topo_.capture_up);
    if (!cap) {
        why = cap.error().what;
        return nullptr;
    }
    a->capture_ = std::move(*cap);
    a->shard_ = std::make_unique<Shard>(0, kInbox, a->clock_);
    // P2 Q7, the watchdog (ADR 0011 point 6): the gates ABORT on platform.loop_lag (exit 7).
    if (a->topo_.watchdog_ms > 0) {
        a->shard_->set_watchdog(a->topo_.watchdog_ms, [raw = a.get()](Millis lag) {
            raw->events_.emit("platform.loop_lag", std::string("run:") + role_name(raw->topo_.role),
                              {{"shard", "0"}, {"lag_ms", std::to_string(lag)},
                               {"threshold_ms", std::to_string(raw->topo_.watchdog_ms)}});
        });
    }
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
    // P2 Q1: only soft cards need the KEK; a pcsc: or bridge: card keeps its keys itself.
    const bool soft = hosts_ues() &&
                      std::any_of(topo_.ues.begin(), topo_.ues.end(), [](const UeGroup& g) { return !g.card_template.empty(); });
    Result<SecretBytes> kek = soft ? uicc::secrets::load_kek(topo_.kek_file) : Result<SecretBytes>(SecretBytes{});
    if (!kek) {
        why = std::string("the KEK: ") + kek.error().what;
        return kek.error();
    }
    // The cards first: nothing goes on air until every one is good.
    std::vector<FarmCard> cards;
    std::vector<Slice> slices;   // the gNB's: every slice a UE group asks for
    std::map<const UeGroup*, Persona> personas;   // N15: per group, loaded once
    for (const auto& g : topo_.ues) {
        if (!g.persona.empty() && hosts_ues()) {
            auto p = load_persona(g.persona, why);
            if (!p) {
                why.insert(0, "group " + g.group + ": ");
                return p.error();
            }
            personas.emplace(&g, std::move(*p));
        }
        for (const auto& s : g.nssai) {
            if (std::find(slices.begin(), slices.end(), s) == slices.end()) {
                slices.push_back(s);
            }
        }
        for (unsigned i = 0; hosts_ues() && i < g.count; ++i) {   // P2 Q3: the cards are the farm's
            const std::string imsi = imsi_at(g.first_imsi, i);
            auto sub = uicc::image::range_subscriber(imsi);
            if (!sub) {
                why = "imsi-" + imsi + ": " + sub.error().what;
                return sub.error();
            }
            if (g.card_template.empty()) {
                cards.push_back(FarmCard{imsi, g.group, &g, nullptr});   // P2 Q1: the card is outside the process
                continue;
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
                cards.push_back(FarmCard{imsi, g.group, &g, std::move(card)});
            } catch (const YamlError& e) {
                why = std::string("the card template: ") + e.what();
                return make_error(Errc::invalid_argument, 0, "the card template is not valid");
            }
        }
    }

    // The system's side, made once: netd's namespaces, the N3 socket, the air.
    Capture* cap = capture_.get();
    link_ = MemLinkConfig{topo_.link_delay_ms, topo_.link_jitter_ms, topo_.seed};   // P2 Q12: the topology's
    const MemLinkConfig link = link_;
    // P2 Q3: in a split run each role asks netd for what it hosts: the UEs' namespaces
    // (the farm), the CU-CP's or the CU-UP's (ADR 0011 point 1).
    const bool netd_ues = topo_.netd.enabled && topo_.netd.ues && hosts_ues();
    const bool netd_cucp = topo_.netd.enabled && topo_.netd.nodes && hosts_cucp();
    const bool netd_cuup = topo_.netd.enabled && topo_.netd.nodes && hosts_cuup();
    // P2 Q6: in a split run with node namespaces (kaluza-uesim) the DU has one too, and
    // each role's gets a ksim-mid leg carrying its split address.
    const bool split_ns = topo_.mode == Mode::split && topo_.role != Role::all && topo_.netd.enabled && topo_.netd.nodes;
    const bool netd_du = split_ns && hosts_du();
    if (netd_ues || netd_cucp || netd_cuup || netd_du) {
        auto c = net::netd::Client::connect(topo_.netd.socket);
        if (!c) {
            why = "ksim-netd: " + std::string(c.error().what) + " at " + topo_.netd.socket;
            return c.error();
        }
        netd_ = std::make_unique<net::netd::Client>(std::move(*c));
        if (netd_ues) {
            ue_net_ = std::make_unique<NetdUeNet>(*netd_, shard_->reactor());
        }
    }
    if (netd_cucp) {
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
        my_netns_.push_back(topo_.netd.netns);
        if (split_ns) {
            if (auto r = mid_leg(topo_.netd.netns, topo_.split.f1c_listen, why); !r) {
                return r;
            }
        }
    }
    if (netd_du) {
        auto up = netd_->setup_node(topo_.netd.du_netns, "", {}, 0);
        if (!up && netd_->last_error() == "netd: the namespace exists") {
            (void)netd_->teardown(topo_.netd.du_netns);
            up = netd_->setup_node(topo_.netd.du_netns, "", {}, 0);
        }
        if (!up) {
            why = "ksim-netd (DU): " + netd_->last_error();
            return up.error();
        }
        my_netns_.push_back(topo_.netd.du_netns);
        if (auto r = mid_leg(topo_.netd.du_netns, topo_.split.du, why); !r) {
            return r;
        }
    }
    // N3 (P1 N10): UDP 2152 on the CU-UP's address; with netd, from its own namespace.
    std::unique_ptr<net::UdpSocket> n3;
    if (!hosts_cuup()) {
        // no N3 in this process
    } else if (netd_cuup) {
        auto up = netd_->setup_node(topo_.netd.cuup_netns, topo_.netd.parent, v4_of(topo_.n3_bind), topo_.netd.prefix);
        if (!up && netd_->last_error() == "netd: the namespace exists") {
            (void)netd_->teardown(topo_.netd.cuup_netns);
            up = netd_->setup_node(topo_.netd.cuup_netns, topo_.netd.parent, v4_of(topo_.n3_bind), topo_.netd.prefix);
        }
        if (!up) {
            why = "ksim-netd (N3): " + netd_->last_error();
            return up.error();
        }
        my_netns_.push_back(topo_.netd.cuup_netns);
        if (split_ns) {
            if (auto r = mid_leg(topo_.netd.cuup_netns, topo_.split.cuup_f1u, why); !r) {
                return r;
            }
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
    if (n3) {
        n3_ = std::make_unique<TapDatagram>(std::move(n3), [cap](const Endpoint& from, const Endpoint& to, ByteView p) {
            cap->gtpu(from, to, p);
        });
    }
    if (topo_.role == Role::du) {
        // P2 Q3: the DU's end of KAIR, for the UE farm's shards (ADR 0011 point 2).
        auto l = net::SeqpacketListener::listen(shard_->reactor(), topo_.kair_socket,
                                                [this](std::unique_ptr<IChannel> c) { kair_accept(std::move(c)); });
        if (!l) {
            why = "KAIR " + topo_.kair_socket + ": " + l.error().what;
            return l.error();
        }
        kair_listen_ = std::move(*l);
    }
    if (topo_.role != Role::all) {
        slices_ = slices;
        if (auto r = build_gnb(why); !r) {
            return r;
        }
        if (hosts_ues()) {
            if (auto r = start_lanes(why); !r) {
                return r;
            }
            if (auto r = build_farm(std::move(cards), personas, why); !r) {
                return r;
            }
            for (std::size_t k = 0; k < lanes_.size(); ++k) {
                if (lanes_[k].owned) {
                    lanes_[k].owned->start();   // its UEs were built while it was not running
                    (void)lanes_[k].shard->post([this, k] { kair_connect(k); });
                } else {
                    kair_connect(k);
                }
            }
        }
        connect_gnb();
        return {};
    }
    air_ = std::make_unique<MemNet>(link);
    auto du_air = air_->bind(*shard_, kDuAir);
    if (!du_air) {
        return du_air.error();
    }
    du_air_ = std::move(*du_air);
    du_air_->set_handler([this](ByteView payload, const Endpoint&) {
        auto f = air::decode(payload);
        if (!f) {
            ++kair_errors_;
            return;
        }
        ++kair_frames_;
        observe_kair(Metrics::Hop::kair_ul, *f);
        if (du_ && shard_->now() >= air_off_until_) {
            du_->on_frame(*f);
        }
    });
    slices_ = slices;
    if (auto r = build_gnb(why); !r) {
        return r;
    }
    if (auto r = build_farm(std::move(cards), personas, why); !r) {
        return r;
    }
    connect_gnb();
    return {};
}

Result<void> AllInOne::build_farm(std::vector<FarmCard> cards, const std::map<const UeGroup*, Persona>& personas,
                                  std::string& why) {
    Capture* cap = capture_.get();
    // The UE farm: farm index i + 1, radio ID i + 1.
    for (std::size_t i = 0; i < cards.size(); ++i) {
        auto& c = cards[i];
        // All in one: each UE's own end of the in-memory air. Split: the farm's KAIR channel (kair_connect).
        std::unique_ptr<IDatagram> dgram;
        if (air_) {
            auto d = air_->bind(*shard_, ue_air(i + 1));
            if (!d) {
                return d.error();
            }
            dgram = std::move(*d);
        }
        UeDeviceConfig uc;
        uc.index = static_cast<unsigned>(i + 1);
        uc.supi = c.imsi;
        uc.radio_id = static_cast<std::uint32_t>(i + 1);
        uc.plmn = {topo_.mcc, topo_.mnc};
        for (const auto& s : c.g->nssai) {
            uc.nssai.push_back(nas::ie::Snssai{s.sst, s.sd, std::nullopt, std::nullopt});
        }
        if (auto it = personas.find(c.g); it != personas.end()) {
            uc.persona = it->second;
        }
        uc.imeisv = imeisv_for(uc.persona ? &*uc.persona : nullptr, c.g->imeisv_tac, c.imsi);
        uc.allow_null_integrity = topo_.allow_null;
        uc.seed = topo_.seed;
        if (ue_net_) {
            uc.netns = "ksim-ue-" + std::to_string(i + 1);
        }
        // P2 Q7: in the UE role each UE lives on its lane's shard; all in one on the node's.
        const std::size_t lane = lanes_.empty() ? 0 : i % lanes_.size();
        Shard& sh = lanes_.empty() ? *shard_ : *lanes_[lane].shard;
        IUeNet* ue_net = lanes_.empty() || lane == 0 ? static_cast<IUeNet*>(ue_net_.get()) : lanes_[lane].ue_net.get();
        if (!lanes_.empty()) {
            lanes_[lane].ues.push_back(i);
        }
        roster_.emplace_back(c.imsi, lane);
        UeTaps taps;
        taps.rrc = [cap](std::string_view ch, ByteView pdu, const std::string& supi) { cap->rrc(ch, pdu, supi); };
        if (topo_.plain_nas) {
            taps.nas = [cap](bool ul, ByteView plain, const std::string& supi) { cap->nas(ul, plain, supi); };
        }
        taps.sim = [cap](std::uint8_t sub, ByteView payload, const std::string& supi) { cap->sim(sub, payload, supi); };
        auto to_air = [this, i](const air::Frame& f) { ue_to_air(i, f); };
        if (c.card) {
            ues_.push_back(std::make_unique<UeDevice>(sh, events_, std::move(uc), std::move(c.card), std::move(to_air),
                                                      taps, ue_net));
        } else {
            auto reader = external_reader(*c.g, why);
            if (!reader) {
                return make_error(Errc::invalid_argument, 0, "a UE's card reader cannot be opened");
            }
            const std::string name = c.g->card_pcsc.empty() ? "bridge:" + c.g->card_bridge : "pcsc:" + c.g->card_pcsc;
            ues_.push_back(std::make_unique<UeDevice>(*shard_, events_, std::move(uc), std::move(reader), name,
                                                      std::move(to_air), taps, ue_net_.get()));
        }
        if (dgram) {
            dgram->set_handler([this, i](ByteView payload, const Endpoint&) {
                auto f = air::decode(payload);
                if (!f) {
                    ++kair_errors_;
                    return;
                }
                ++kair_frames_;
                observe_kair(Metrics::Hop::kair_dl, *f);
                ues_[i]->on_frame(*f);
            });
            ue_air_.push_back(std::move(dgram));
        }
        radio_ids_.push_back(static_cast<std::uint32_t>(i + 1));
        groups_.push_back(c.group);
    }

    return {};
}

std::unique_ptr<uicc::IApduTransport> AllInOne::external_reader(const UeGroup& g, std::string& why) {
    if (!g.card_bridge.empty()) {
        // The card bridge (lab.md §7): vpcd framing over TCP, this UE in the terminal role.
        auto ep = Endpoint::parse(g.card_bridge);
        auto s = ep ? net::tcp_connect(shard_->reactor(), *ep) : Result<std::unique_ptr<IStream>>(ep.error());
        if (!s) {
            why = "group " + g.group + ": the card bridge " + g.card_bridge + " cannot be reached";
            return nullptr;
        }
        return std::make_unique<uicc::vpcd::VpcdTransport>(*shard_, std::move(*s));
    }
#ifdef KSIM_HAVE_PCSC
    auto names = uicc::pcsc::readers();
    auto reader = names ? uicc::pcsc::pick(*names, g.card_pcsc) : Result<std::string>(names.error());
    if (!reader) {
        why = "group " + g.group + ": PC/SC reader " + g.card_pcsc + ": " + reader.error().what;
        return nullptr;
    }
    if (!blocking_) {
        blocking_ = std::make_unique<BlockingPool>(2);
    }
    return std::make_unique<uicc::pcsc::PcscTransport>(*shard_, *blocking_, *reader);
#else
    why = "group " + g.group + ": this build has no PC/SC (KSIM_PCSC is off, as in release-lab): use card: {bridge: …}";
    return nullptr;
#endif
}

Result<void> AllInOne::build_gnb(std::string& why) {
    // The gNB's nodes and their links. All in one: F1 and E1 over memlink, F1-U over memlink
    // datagrams. Split (P2 Q3, ADR 0011): the link to a role in another process is real, F1-C
    // and E1 over SCTP (the CU-CP listens), F1-U over UDP. NG-C is SCTP either way.
    Capture* cap = capture_.get();
    const MemLinkConfig link = link_;
    const std::vector<Slice>& slices = slices_;
    const bool all = topo_.role == Role::all;
    net::SctpOptions links;
    links.out_streams = topo_.split.streams;
    links.max_in_streams = topo_.split.streams;
    const net::SctpBackoff redial{200, 2'000};
    net::SocketSource cucp_source;
    net::SocketSource cuup_source;
    net::SocketSource du_source;
    if (netd_ && topo_.netd.nodes) {
        cucp_source = [this](int family) { return netd_->socket(topo_.netd.netns, net::netd::SockKind::sctp, family); };
        cuup_source = [this](int family) { return netd_->socket(topo_.netd.cuup_netns, net::netd::SockKind::sctp, family); };
        if (topo_.mode == Mode::split) {   // P2 Q6: the DU's F1-C from its namespace
            du_source = [this](int family) { return netd_->socket(topo_.netd.du_netns, net::netd::SockKind::sctp, family); };
        }
    }
    // P2 Q6: a split role's F1-U socket, from its namespace when it has one.
    const auto f1u_socket = [this](const std::string& netns, const Endpoint& at) -> Result<std::unique_ptr<net::UdpSocket>> {
        if (netd_ && topo_.netd.nodes && topo_.mode == Mode::split) {
            auto fd = netd_->socket(netns, net::netd::SockKind::udp, 4);
            if (!fd) {
                return fd.error();
            }
            return net::UdpSocket::bind(shard_->reactor(), std::move(*fd), at);
        }
        return net::UdpSocket::bind(shard_->reactor(), at);
    };
    auto gtpu_tap = [cap](const Endpoint& from, const Endpoint& to, ByteView p) { cap->gtpu(from, to, p); };

    // F1-C: the DU's end and the CU-CP's.
    IAssoc* f1_du = nullptr;
    IAssoc* f1_cu = nullptr;
    if (all) {
        f1_ = std::make_unique<MemAssocPair>(*shard_, Endpoint::v4(10, 255, 0, 2, 0), *shard_,
                                             Endpoint::v4(10, 255, 0, 1, 38472), 2, link);
        f1_du = &f1_->a();
        f1_cu = &f1_->b();
    }
    if (!all && hosts_cucp()) {
        f1_slot_ = std::make_unique<AssocSlot>();
        auto l = net::SctpListener::listen(
            shard_->reactor(), {topo_.split.f1c_listen}, links,
            [this](std::unique_ptr<IAssoc> a) {
                if (!f1_slot_->take(std::move(a))) {
                    events_.emit("ran.link.refused", "gnb:" + topo_.gnb_name, {{"link", "f1c"}});
                }
            },
            cucp_source);
        if (!l) {
            why = "F1-C listen " + topo_.split.f1c_listen.to_string() + ": " + l.error().what;
            return l.error();
        }
        f1_listen_ = std::move(*l);
        f1_cu = f1_slot_.get();
    }
    if (!all && hosts_du()) {
        Endpoint bind = topo_.split.du;
        bind.port = 0;
        f1_client_ = std::make_unique<net::SctpClient>(shard_->reactor(), *shard_, std::vector<Endpoint>{bind},
                                                       std::vector<Endpoint>{topo_.split.f1c_listen}, links, redial,
                                                       du_source);
        f1_du = f1_client_.get();
    }
    if (f1_cu != nullptr) {
        f1_tap_ = std::make_unique<TapAssoc>(*f1_cu, [cap](bool tx, ByteView m) { cap->f1ap(tx, m); });
    }
    if (!all && f1_du != nullptr && !topo_.peer_cucp.empty()) {
        du_f1_tap_ = std::make_unique<TapAssoc>(*f1_du, [cap](bool tx, ByteView m) { cap->f1ap(tx, m); });
        f1_du = du_f1_tap_.get();   // P2 Q4: the peer's CU-CP captures for itself, not for us
    }

    // NG-C: the CU-CP's.
    if (hosts_cucp()) {
        net::SctpOptions opt;
        opt.out_streams = topo_.ng_streams;
        opt.max_in_streams = topo_.ng_streams;
        ng_ = std::make_unique<net::SctpClient>(shard_->reactor(), *shard_, std::vector<Endpoint>{topo_.ng_bind},
                                                std::vector<Endpoint>{topo_.amf}, opt, net::SctpBackoff{}, cucp_source);
        ng_tap_ = std::make_unique<TapAssoc>(*ng_, [cap](bool tx, ByteView m) { cap->ngap(tx, m); });
    }

    // E1: the CU-UP's end and the CU-CP's.
    IAssoc* e1_up = nullptr;
    IAssoc* e1_cp = nullptr;
    if (all) {
        e1_ = std::make_unique<MemAssocPair>(*shard_, Endpoint::v4(10, 255, 0, 3, 0), *shard_,
                                             Endpoint::v4(10, 255, 0, 1, 38462), 2, link);
        e1_up = &e1_->a();
        e1_cp = &e1_->b();
    }
    if (!all && hosts_cucp()) {
        e1_slot_ = std::make_unique<AssocSlot>();
        auto l = net::SctpListener::listen(
            shard_->reactor(), {topo_.split.e1_listen}, links,
            [this](std::unique_ptr<IAssoc> a) {
                if (!e1_slot_->take(std::move(a))) {
                    events_.emit("ran.link.refused", "gnb:" + topo_.gnb_name, {{"link", "e1"}});
                }
            },
            cucp_source);
        if (!l) {
            why = "E1 listen " + topo_.split.e1_listen.to_string() + ": " + l.error().what;
            return l.error();
        }
        e1_listen_ = std::move(*l);
        e1_cp = e1_slot_.get();
    }
    if (!all && hosts_cuup()) {
        e1_client_ = std::make_unique<net::SctpClient>(shard_->reactor(), *shard_, std::vector<Endpoint>{topo_.split.cuup_e1},
                                                       std::vector<Endpoint>{topo_.split.e1_listen}, links, redial,
                                                       cuup_source);
        e1_up = e1_client_.get();
    }
    if (e1_cp != nullptr) {
        e1_tap_ = std::make_unique<TapAssoc>(*e1_cp, [cap](bool tx, ByteView m) { cap->e1ap(tx, m); });
    }
    if (!all && e1_up != nullptr && !topo_.peer_cucp.empty()) {
        cuup_e1_tap_ = std::make_unique<TapAssoc>(*e1_up, [cap](bool tx, ByteView m) { cap->e1ap(tx, m); });
        e1_up = cuup_e1_tap_.get();   // P2 Q5: the peer's CU-CP captures for itself, not for us
    }

    // F1-U: the CU-UP's end (captured, each datagram once) and the DU's.
    Endpoint cuup_f1u_addr = kCuUpF1u;
    Endpoint du_f1u_addr = kDuF1u;
    if (all) {
        f1u_net_ = std::make_unique<MemNet>(link);
        auto cuup_f1u = f1u_net_->bind(*shard_, kCuUpF1u);
        auto du_f1u = f1u_net_->bind(*shard_, kDuF1u);
        if (!cuup_f1u || !du_f1u) {
            return make_error(Errc::internal, 0, "F1-U ports");
        }
        cuup_f1u_ = std::make_unique<TapDatagram>(std::move(*cuup_f1u), gtpu_tap);
        du_f1u_ = std::move(*du_f1u);
    } else {
        cuup_f1u_addr = topo_.split.cuup_f1u;
        du_f1u_addr = topo_.split.du;
        if (hosts_cuup()) {
            auto u = f1u_socket(topo_.netd.cuup_netns, cuup_f1u_addr);
            if (!u) {
                why = "F1-U bind " + cuup_f1u_addr.to_string() + ": " + u.error().what;
                return u.error();
            }
            cuup_f1u_ = std::make_unique<TapDatagram>(std::move(*u), gtpu_tap);
        }
        if (hosts_du()) {
            auto u = f1u_socket(topo_.netd.du_netns, du_f1u_addr);
            if (!u) {
                why = "F1-U bind " + du_f1u_addr.to_string() + ": " + u.error().what;
                return u.error();
            }
            if (topo_.peer_cuup.empty()) {
                du_f1u_ = std::move(*u);
            } else {
                du_f1u_ = std::make_unique<TapDatagram>(std::move(*u), gtpu_tap);   // P2 Q4: the peer's CU-UP is not ours
            }
        }
    }

    if (hosts_cucp()) {
        proc::ran::CuCpConfig cc;
        cc.id = "gnb:" + topo_.gnb_name;
        cc.name = topo_.gnb_name;
        cc.plmn = {topo_.mcc, topo_.mnc};
        cc.gnb_id = topo_.gnb_id;
        cc.gnb_id_bits = topo_.gnb_id_bits;
        cc.allow_null = topo_.allow_null;
        cc.ue_inactivity_s = topo_.ue_inactivity_s;
        cc.nea_preference = topo_.nea_pref;   // P2 Q8
        cc.nia_preference = topo_.nia_pref;
        cc.t_reordering_ms = topo_.t_reordering_ms;
        cc.up_policy = topo_.up_policy;   // P2 Q9
        cc.drb_map = topo_.drb_map;       // P2 Q10
        cc.gbr_budget_bps = topo_.gbr_budget_kbps * 1000;   // P2 Q11
        cc.slices.clear();
        for (const auto& s : slices) {
            cc.slices.push_back(ngap::Snssai{s.sst, s.sd});
        }
        cucp_ = std::make_unique<proc::ran::CuCp>(*shard_, events_, cc, *ng_tap_, *f1_tap_, e1_tap_.get());
    }
    if (hosts_cuup()) {
        proc::ran::CuUpConfig upc;
        upc.id = "gnb:" + topo_.gnb_name + "-cuup";
        upc.name = topo_.gnb_name + "-cuup";
        upc.plmn = e1ap::plmn_id(topo_.mcc, topo_.mnc);
        upc.slices.clear();
        for (const auto& s : slices) {
            upc.slices.push_back(e1ap::Snssai{s.sst, s.sd});
        }
        upc.n3_addr = v4_of(topo_.n3_bind);
        upc.f1u_addr = v4_of(cuup_f1u_addr);
        cuup_ = std::make_unique<proc::ran::CuUp>(*shard_, events_, upc, *e1_up, *n3_, *cuup_f1u_);
    }
    if (hosts_du()) {
        proc::ran::DuConfig dc;
        dc.id = "gnb:" + topo_.gnb_name + "-du";
        dc.du_id = topo_.du_id;
        dc.name = topo_.gnb_name + "-du";
        dc.plmn = {topo_.mcc, topo_.mnc};
        dc.nci = (std::uint64_t{topo_.gnb_id} << (36U - topo_.gnb_id_bits)) | 1U;
        dc.pci = topo_.pci;
        dc.tac = topo_.tac;
        dc.arfcn = topo_.arfcn;
        dc.ssb_arfcn = topo_.ssb_arfcn;
        dc.f1u_addr = v4_of(du_f1u_addr);
        // P3 R2 (ledger A-09): every DU of a run counts SFN from the same CLOCK_REALTIME epoch.
        dc.sfn_clock_ms = [] {
            timespec ts{};
            ::clock_gettime(CLOCK_REALTIME, &ts);
            return static_cast<std::int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1'000'000;
        };
        du_ = std::make_unique<proc::ran::Du>(*shard_, events_, dc, *f1_du, [this](const air::Frame& f) { du_to_air(f); },
                                              du_f1u_.get());
    }
    return {};
}

void AllInOne::connect_gnb() {
    if (f1_) {
        f1_->connect();
    }
    if (e1_) {
        e1_->connect();
    }
    if (ng_) {
        ng_->start();
    }
    if (f1_client_) {
        f1_client_->start();
    }
    if (e1_client_) {
        e1_client_->start();
    }
}

void AllInOne::teardown_gnb() {
    du_.reset();
    cuup_.reset();
    cucp_.reset();
    du_f1u_.reset();
    cuup_f1u_.reset();
    f1u_net_.reset();
    e1_tap_.reset();
    cuup_e1_tap_.reset();   // before the client it wraps
    e1_.reset();
    e1_client_.reset();
    e1_listen_.reset();
    e1_slot_.reset();
    if (ng_) {
        ng_->shutdown();
    }
    ng_tap_.reset();
    ng_.reset();
    f1_tap_.reset();
    du_f1_tap_.reset();     // before the client it wraps
    f1_.reset();
    f1_client_.reset();
    f1_listen_.reset();
    f1_slot_.reset();
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
        ++kair_errors_;
        return;
    }
    if (topo_.role == Role::du) {
        // P2 Q3: to the farm channel the UE spoke from, or to every farm for broadcast and paging.
        auto it = f.radio_id == 0 ? kair_route_.end() : kair_route_.find(f.radio_id);
        if (it != kair_route_.end()) {
            (void)it->second->send(*wire);
            return;
        }
        for (auto& c : kair_peers_) {
            if (c->open()) {
                (void)c->send(*wire);
            }
        }
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
        ++kair_errors_;
        return;
    }
    if (topo_.role == Role::ue) {
        auto& l = lanes_[i % lanes_.size()];   // on that lane's shard
        if (l.kair && l.kair->open()) {
            (void)l.kair->send(*wire);   // out of range of the cell while the DU is away
        }
        return;
    }
    (void)ue_air_[i]->send_to(*wire, kDuAir);
}

void AllInOne::kair_accept(std::unique_ptr<IChannel> c) {
    IChannel* raw = c.get();
    raw->set_handlers(
        [this, raw](ByteView m) {
            auto f = air::decode(m);
            if (!f) {
                ++kair_errors_;
                return;
            }
            ++kair_frames_;
            observe_kair(Metrics::Hop::kair_ul, *f);
            kair_route_[f->radio_id] = raw;   // where this UE's downlink goes
            if (du_) {
                du_->on_frame(*f);
            }
        },
        [this, raw] {
            for (auto it = kair_route_.begin(); it != kair_route_.end();) {
                it = it->second == raw ? kair_route_.erase(it) : std::next(it);
            }
            // Freed after this callback returns, never inside it.
            (void)shard_->post([this, raw] {
                std::erase_if(kair_peers_, [raw](const std::unique_ptr<IChannel>& p) { return p.get() == raw; });
            });
        });
    kair_peers_.push_back(std::move(c));
    events_.emit("ran.du.kair.subscribe", "gnb:" + topo_.gnb_name + "-du", {{"farms", std::to_string(kair_peers_.size())}});
}

void AllInOne::kair_connect(std::size_t lane) {
    // P2 Q3: the farm's end of KAIR; P2 Q7: one per lane, on its shard. While the DU is not
    // there (not started yet, restarting) the lane hears no cell; it tries again every 200 ms.
    FarmLane& l = lanes_[lane];
    l.retry.reset();
    auto c = net::seqpacket_connect(l.shard->reactor(), topo_.kair_socket);
    if (!c) {
        l.retry = l.shard->start_timer(200, [this, lane] { kair_connect(lane); });
        return;
    }
    l.kair = std::move(*c);
    l.kair->set_handlers(
        [this, lane](ByteView m) {
            auto f = air::decode(m);
            if (!f) {
                ++kair_errors_;
                return;
            }
            ++kair_frames_;
            observe_kair(Metrics::Hop::kair_dl, *f);
            for (const std::size_t i : lanes_[lane].ues) {
                if (f->radio_id == 0 || f->radio_id == radio_ids_[i]) {
                    ues_[i]->on_frame(*f);
                }
            }
        },
        [this, lane] {
            FarmLane& gone = lanes_[lane];
            (void)gone.shard->post([this, lane] {
                FarmLane& x = lanes_[lane];
                x.kair.reset();
                if (!stopped_) {
                    x.retry = x.shard->start_timer(200, [this, lane] { kair_connect(lane); });
                }
            });
        });
}

Result<void> AllInOne::start_lanes(std::string& why) {
    // P2 Q7 (ADR 0011 point 5): the UE role's farm shards. Built here, on the node's shard;
    // started once their UEs are (build), so nothing runs on them before.
    const std::size_t n = std::max<std::size_t>(1, topo_.farm_shards);
    lanes_.resize(n);
    lanes_[0].shard = shard_.get();
    for (std::size_t k = 1; k < n; ++k) {
        lanes_[k].owned = std::make_unique<Shard>(static_cast<unsigned>(k), kInbox, clock_);
        lanes_[k].shard = lanes_[k].owned.get();
        if (topo_.watchdog_ms > 0) {
            lanes_[k].owned->set_watchdog(topo_.watchdog_ms, [this, k](Millis lag) {
                events_.emit("platform.loop_lag", std::string("run:") + role_name(topo_.role),
                             {{"shard", std::to_string(k)}, {"lag_ms", std::to_string(lag)},
                              {"threshold_ms", std::to_string(topo_.watchdog_ms)}});
            });
        }
        if (ue_net_) {   // the UEs in namespaces: each lane its own netd connection and reactor
            auto c = net::netd::Client::connect(topo_.netd.socket);
            if (!c) {
                why = "ksim-netd (farm shard " + std::to_string(k) + "): " + std::string(c.error().what);
                return c.error();
            }
            lanes_[k].netd = std::make_unique<net::netd::Client>(std::move(*c));
            lanes_[k].ue_net = std::make_unique<NetdUeNet>(*lanes_[k].netd, lanes_[k].shard->reactor());
        }
    }
    return {};
}

void AllInOne::stop_lanes() {
    // Each lane's UEs and KAIR end die on its shard, then the shard stops (on the node's shard).
    for (std::size_t k = 0; k < lanes_.size(); ++k) {
        FarmLane& l = lanes_[k];
        auto down = [this, &l] {
            if (l.retry) {
                l.shard->stop_timer(*l.retry);
                l.retry.reset();
            }
            l.kair.reset();
            for (const std::size_t i : l.ues) {
                ues_[i].reset();
            }
            l.ue_net.reset();
            l.netd.reset();
            return true;
        };
        if (!l.owned) {
            (void)down();
            continue;
        }
        (void)call_on<bool>(*l.shard, down, std::chrono::seconds(10));
        l.owned->stop();
        l.owned->join();
    }
    lanes_.clear();
}

Shard& AllInOne::shard_for(const std::string& selector) {
    if (lanes_.size() <= 1) {
        return *shard_;
    }
    std::string s = selector.rfind("imsi-", 0) == 0 ? selector.substr(5) : selector;
    if (s.size() == 15) {
        for (const auto& [supi, lane] : roster_) {
            if (supi == s) {
                return *lanes_[lane].shard;
            }
        }
        return *shard_;
    }
    if (!s.empty() && s.size() <= 6 && s.find_first_not_of("0123456789") == std::string::npos) {
        const std::size_t idx = std::stoul(s);
        if (idx >= 1 && idx <= roster_.size()) {
            return *lanes_[roster_[idx - 1].second].shard;
        }
    }
    return *shard_;
}

void AllInOne::teardown() {
    stop_lanes();   // P2 Q7: the farm shards' UEs and KAIR ends, each on its shard
    kair_route_.clear();
    kair_peers_.clear();
    kair_listen_.reset();
    ues_.clear();
    ue_air_.clear();
    teardown_gnb();
    n3_.reset();
    if (du_air_) {
        du_air_.reset();
    }
    air_.reset();
    ue_net_.reset();   // after the UEs: each took its namespace down
    if (netd_) {
        for (auto it = my_netns_.rbegin(); it != my_netns_.rend(); ++it) {   // P2 Q6: what this process made
            (void)netd_->teardown(*it);   // a ksim-mid leg goes with its namespace
        }
        my_netns_.clear();
        netd_.reset();
    }
}

Result<void> AllInOne::mid_leg(const std::string& netns, const Endpoint& at, std::string& why) {
    auto r = netd_->veth(netns, v4_of(at), topo_.netd.mid_prefix);
    if (!r) {
        why = "ksim-netd (ksim-mid leg of " + netns + "): " + netd_->last_error();
        return r.error();
    }
    return {};
}

void AllInOne::observe_kair(Metrics::Hop h, const air::Frame& f) {
    const auto sent = static_cast<Millis>(f.tx_time_ns / 1'000'000);
    metrics_.observe(h, shard_->now() - sent);   // one host, one CLOCK_MONOTONIC
}

std::size_t AllInOne::drain(std::chrono::milliseconds bound, std::chrono::milliseconds stall) {
    if (!shard_ || !hosts_du()) {
        return 0;
    }
    const auto count = [this] { return call<std::size_t>([this] { return du_ ? du_->ues() : std::size_t{0}; }).value_or(0); };
    const auto start = std::chrono::steady_clock::now();
    auto last_fall = start;
    std::size_t n = count();
    const std::size_t first = n;
    while (n > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now - start >= bound || now - last_fall >= stall) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const std::size_t m = count();
        if (m < n) {
            last_fall = std::chrono::steady_clock::now();
        }
        n = m;
    }
    if (first > 0) {
        log::info("ksim", "stop: {} of {} UE contexts at the DU released in {} ms", first - n, first,
                  std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
    }
    return n;
}

void AllInOne::stop() {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    if (shard_ && hosts_cucp()) {
        // P2 Q14 prep (KS-PLAT-D20): NG ends with SCTP's graceful SHUTDOWN, not the ABORT the
        // client's reset sends (the AMF saw COMM_LOST, kaluza-core's F-77): the SHUTDOWN begins
        // on the shard and completes there, in at most 3 s.
        (void)call<bool>([this] {
            if (ng_ && ng_->up()) {
                ng_->shutdown();
            }
            return true;
        });
        for (int i = 0; i < 60; ++i) {
            if (!call<bool>([this] { return ng_ && ng_->up(); }).value_or(false)) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
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
