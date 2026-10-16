// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The node layer's parts (P1 N8): the topology reader, the dev-PC guard, the
// run directory and its event file, the captures (NGAP keys zeroed, an
// undecodable PDU left out) and the tapping association.

#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>

#include "codec/asn1/msg/e1ap.hpp"
#include "codec/asn1/msg/ngap.hpp"
#include "node/aio/capture.hpp"
#include "node/aio/guard.hpp"
#include "node/aio/run_dir.hpp"
#include "node/aio/topology.hpp"
#include "platform/clock.hpp"
#include "platform/memlink.hpp"
#include "platform/sim_loop.hpp"

namespace ksim::node {
namespace {

namespace fs = std::filesystem;

std::string temp_dir() {
    std::string t = (fs::temp_directory_path() / "ksim-node-XXXXXX").string();
    char* d = ::mkdtemp(t.data());
    EXPECT_NE(d, nullptr);
    return t;
}

std::string write(const std::string& path, const std::string& text) {
    std::ofstream(path) << text;
    return path;
}

Bytes read(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return Bytes{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

const char* kTopology = R"(plmn: "00101"
seed: 7
amf: [{addr: 127.0.0.1, port: 39412}]
gnbs:
  - id: {value: 0x1A0, bits: 22}
    name: g1
    cucp: {ng_bind: 127.0.0.2}
    dus: [{id: 1, cells: [{pci: 101, tac: 1, arfcn: 632628}]}]
ues:
  - {group: phones, count: 3, range: "001010000300001", card: {template: ../cards/usim-5g.yaml}}
secrets: {sealed: cards, kek: ~/k.key}
peer: {name: stub}
)";

TEST(Topology, TheRepositorysTopologiesLoad) {
    // P1 N13: twelve UEs for the stub and Open5GS; the lab adds two from the SMS sub-block.
    const std::string root = KSIM_SOURCE_DIR;
    for (const char* f : {"aio-stub.yaml", "aio-open5gs.yaml", "aio-lab.yaml"}) {
        std::string why;
        auto t = load_topology(root + "/topologies/" + f, why);
        ASSERT_TRUE(t) << f << ": " << why;
        std::size_t n = 0;
        for (const auto& g : t->ues) {
            n += g.count;
        }
        EXPECT_EQ(n, std::string(f) == "aio-stub.yaml" ? 12u : 13u) << f;
    }
    std::string why;
    auto lab = load_topology(root + "/topologies/aio-lab.yaml", why);
    ASSERT_TRUE(lab) << why;
    ASSERT_EQ(lab->ues.size(), 3u);
    EXPECT_EQ(lab->ues[1].first_imsi, "001010000300050");
}

// P2: the split and interop topologies load, and the VM's split puts each role in a
// namespace with its ksim-mid leg (P2 Q6).
TEST(Topology, TheP2TopologiesLoad) {
    const std::string root = KSIM_SOURCE_DIR;
    for (const char* f : {"split-stub.yaml", "split-open5gs.yaml", "split-stub-e1.yaml", "split-lab.yaml",
                          "ocudu-c3-stub.yaml", "ocudu-c4-stub.yaml", "ocudu-c5-stub.yaml", "split-stub-nea1.yaml"}) {
        std::string why;
        auto t = load_topology(root + "/topologies/" + f, why);
        ASSERT_TRUE(t) << f << ": " << why;
        EXPECT_EQ(t->mode, Mode::split) << f;
    }
    std::string why;
    auto lab = load_topology(root + "/topologies/split-lab.yaml", why);
    ASSERT_TRUE(lab) << why;
    EXPECT_TRUE(lab->netd.mid);
    EXPECT_EQ(lab->netd.du_netns, "ksim-du");
    EXPECT_EQ(lab->split.du, Endpoint::v4(10, 250, 0, 2, 2152));
    auto e1 = load_topology(root + "/topologies/split-stub-e1.yaml", why);
    ASSERT_TRUE(e1) << why;
    EXPECT_EQ(e1->ue_inactivity_s, 15);
    auto c4 = load_topology(root + "/topologies/ocudu-c4-stub.yaml", why);
    ASSERT_TRUE(c4) << why;
    EXPECT_EQ(c4->peer_cuup, "ocudu");
    EXPECT_TRUE(c4->peer_cucp.empty());
}

TEST(Topology, SplitRolesInNamespacesNeedKsimMidAndOneAddressPerLeg) {
    const std::string dir = temp_dir();
    std::string base = kTopology;
    base.replace(base.find("seed: 7"), 7, "seed: 7\nmode: split");
    base.replace(base.find("    dus:"), 0,
                 "    split: {f1c: 10.250.0.1, e1: 10.250.0.1, du: 10.250.0.2, cuup: 10.250.0.3, cuup_e1: 10.250.0.3}\n");
    auto load = [&](const std::string& netd) {
        std::string why;
        return load_topology(write(dir + "/s.yaml", base + netd), why);
    };
    EXPECT_FALSE(load("netd: {nodes: true}\n"));   // the dev PC: no ksim-mid, so the roles stay in the root namespace
    EXPECT_TRUE(load("netd: {nodes: false, ues: true}\n"));
    EXPECT_TRUE(load("netd: {nodes: true, mid: true}\n"));
    EXPECT_FALSE(load("netd: {nodes: true, mid: true, du_netns: ksim-cucp}\n"));   // the DU's own
    std::string split = base;
    split.replace(split.find("e1: 10.250.0.1"), 14, "e1: 10.250.0.9");   // the CU-CP's leg has one address
    std::string why;
    EXPECT_FALSE(load_topology(write(dir + "/s2.yaml", split + "netd: {nodes: true, mid: true}\n"), why));
    fs::remove_all(dir);
}

// P2 Q8: the CU-CP's AS preference lists; ZUC is the declared gap and the NULL algorithms
// need the bisect switch.
TEST(Topology, TheCuCpsAlgorithmListsAreReadAndChecked) {
    const std::string dir = temp_dir();
    const std::string cucp = "cucp: {ng_bind: 127.0.0.2}";
    auto with = [&](const std::string& lists, const std::string& extra = "") {
        std::string s = kTopology;
        s.replace(s.find(cucp), cucp.size(), "cucp: {ng_bind: 127.0.0.2, " + lists + "}");
        std::string why;
        return load_topology(write(dir + "/a.yaml", s + extra), why);
    };
    std::string why;
    auto def = load_topology(write(dir + "/d.yaml", kTopology), why);
    ASSERT_TRUE(def) << why;
    EXPECT_EQ(def->nea_pref, (std::vector<std::uint8_t>{2, 1, 0}));   // NEA0 skipped without allow_null
    auto one = with("nea: [1, 2], nia: [1, 2]");
    ASSERT_TRUE(one);
    EXPECT_EQ(one->nea_pref, (std::vector<std::uint8_t>{1, 2}));
    EXPECT_EQ(one->nia_pref, (std::vector<std::uint8_t>{1, 2}));
    EXPECT_FALSE(with("nea: [3, 2]"));          // ZUC: KS-SEC-G1
    EXPECT_FALSE(with("nia: [2, 2]"));          // each once
    EXPECT_FALSE(with("nea: []"));
    EXPECT_FALSE(with("nea: [0, 2]"));          // NEA0 listed without the bisect switch
    EXPECT_TRUE(with("nea: [0, 2]", "security: {allow_null: true}\n"));
    auto tr = with("t_reordering_ms: 100");
    ASSERT_TRUE(tr);
    EXPECT_EQ(tr->t_reordering_ms, 100);
    EXPECT_FALSE(def->t_reordering_ms);        // infinity
    EXPECT_FALSE(with("t_reordering_ms: 99"));  // not one of PDCP-Config's values
    fs::remove_all(dir);
}

TEST(Topology, ReadsTheP1SubsetAndResolvesPaths) {
    const std::string dir = temp_dir();
    std::string why;
    auto t = load_topology(write(dir + "/t.yaml", kTopology), why);
    ASSERT_TRUE(t) << why;
    EXPECT_EQ(t->mcc, "001");
    EXPECT_EQ(t->mnc, "01");
    EXPECT_EQ(t->amf, Endpoint::v4(127, 0, 0, 1, 39412));
    EXPECT_EQ(t->gnb_id, 0x1A0u);
    EXPECT_EQ(t->ues.size(), 1u);
    EXPECT_EQ(t->ues[0].count, 3u);
    EXPECT_EQ(t->ues[0].card_template, (fs::path(dir).parent_path() / "cards/usim-5g.yaml").lexically_normal().string());
    EXPECT_EQ(t->sealed_dir, dir + "/cards");
    EXPECT_EQ(t->kek_file.substr(t->kek_file.size() - 6), "/k.key");
    EXPECT_EQ(t->peer.at("name"), "stub");
    // N3 (P1 N10): by default the CU-CP's address on GTP-U's port.
    EXPECT_EQ(t->n3_bind, Endpoint::v4(127, 0, 0, 2, 2152));
    std::string text = kTopology;
    text.replace(text.find("    dus:"), 0, "    cuup: {n3_bind: 127.0.0.31}\n");
    auto t2 = load_topology(write(dir + "/t2.yaml", text), why);
    ASSERT_TRUE(t2) << why;
    EXPECT_EQ(t2->n3_bind, Endpoint::v4(127, 0, 0, 31, 2152));
    fs::remove_all(dir);
}

TEST(Topology, RefusesWhatP1DoesNotRunOrAMistypedKey) {
    const std::string dir = temp_dir();
    const std::string base = kTopology;
    auto refused = [&](const std::string& from, const std::string& to) {
        std::string text = base;
        const auto at = text.find(from);
        EXPECT_NE(at, std::string::npos) << from;
        text.replace(at, from.size(), to);
        std::string why;
        auto t = load_topology(write(dir + "/bad.yaml", text), why);
        return !t && !why.empty();
    };
    EXPECT_TRUE(refused("seed: 7", "sead: 7"));                                    // unknown key
    EXPECT_TRUE(refused("bits: 22", "bits: 21"));                                  // gNB ID 22..32 bits
    EXPECT_TRUE(refused("value: 0x1A0", "value: 0x4000000"));                      // does not fit 22 bits
    EXPECT_TRUE(refused("plmn: \"00101\"", "plmn: \"0010\""));
    EXPECT_TRUE(refused("ng_bind: 127.0.0.2", "ng_bind: ::1"));                    // not the AMF's family
    EXPECT_TRUE(refused("range: \"001010000300001\"", "range: \"00101000030000\""));
    EXPECT_TRUE(refused("amf: [{addr: 127.0.0.1, port: 39412}]",
                        "amf: [{addr: 127.0.0.1}, {addr: 127.0.0.3}]"));          // one AMF in P1
    EXPECT_TRUE(refused("    dus:", "    cuup: {n3_bind: \"::1\"}\n    dus:"));     // N3 is IPv4 in P1
    EXPECT_TRUE(refused("    dus:", "    cuup: {n3: 127.0.0.3}\n    dus:"));        // a mistyped key
    fs::remove_all(dir);
}

TEST(Guard, RefusesTheLabNetworkOffTheLabHostAndBesideACell) {
    GuardInput in;
    in.host = "amadeus-dev";
    in.addresses = {Endpoint::v4(127, 0, 0, 1, 39412), Endpoint::v4(127, 0, 0, 2, 0)};
    EXPECT_EQ(check_guard(in), "");
    in.addresses = {Endpoint::v4(192, 168, 134, 128, 38412)};   // vmnet8: the Open5GS rig
    EXPECT_EQ(check_guard(in), "");
    in.addresses = {Endpoint::v4(172, 30, 30, 1, 38412)};       // the real AMF on this PC
    EXPECT_NE(check_guard(in), "");
    in.lab = true;                                              // --lab, but not kaluza-uesim
    EXPECT_NE(check_guard(in), "");
    in.host = "kaluza-uesim";
    EXPECT_EQ(check_guard(in), "");
    in.processes = {"bash", "gnb"};                             // the OCUDU cell runs
    EXPECT_NE(check_guard(in), "");
    in.processes = {"odu"};
    EXPECT_NE(check_guard(in), "");
    in.processes = {"du", "gnbd"};                              // names that are not a cell
    EXPECT_EQ(check_guard(in), "");
}

TEST(RunDir, IsOwnerOnlyAndMustBeNewOrEmpty) {
    const std::string dir = temp_dir();
    const std::string run = dir + "/runs/r1";
    ASSERT_TRUE(make_run_dir(run));
    struct stat st {};
    ASSERT_EQ(::stat(run.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0700u);
    ASSERT_TRUE(write_file(run + "/manifest.json", "{}\n"));
    ASSERT_EQ(::stat((run + "/manifest.json").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    EXPECT_FALSE(make_run_dir(run));   // not empty: a run never writes over another
    EXPECT_EQ(file_sha256(run + "/manifest.json").size(), 64u);
    fs::remove_all(dir);
}

TEST(RunDir, TheEventFileHasOneLinePerEvent) {
    const std::string dir = temp_dir();
    ManualClock clock;
    EventRing ring(16, clock);
    auto f = EventFile::open(dir + "/events.ndjson");
    ASSERT_TRUE(f);
    ring.on_emit([p = f->get()](const Event& e) { p->write(e); });
    ring.emit("nas.reg.accept", "ue:imsi-001010000300001", {{"guti", "g"}});
    ring.emit("nas.reg.complete", "ue:imsi-001010000300001", {});
    EXPECT_EQ((*f)->lines(), 2u);
    const Bytes text = read(dir + "/events.ndjson");
    EXPECT_EQ(std::count(text.begin(), text.end(), '\n'), 2);
    fs::remove_all(dir);
}

ngap::InitialContextSetupRequest ics_with_key(std::uint8_t fill) {
    ngap::InitialContextSetupRequest ics;
    ics.amf = 7;
    ics.ran = 1;
    ics.guami = ngap::Guami{ngap::plmn_id("001", "01"), 0xCA, 1, 1};
    ics.allowed_nssai = {ngap::Snssai{1, std::nullopt}};
    ics.nr_enc = 0xE000;
    ics.nr_int = 0xE000;
    ics.security_key = Bytes(32, fill);
    ics.nas = *from_hex("7e00420101");
    return ics;
}

TEST(Capture, ZeroesTheNgapSecurityKeyAndLeavesOutWhatItCannotRedact) {
    const std::string dir = temp_dir();
    auto c = Capture::open(dir);
    ASSERT_TRUE(c);
    auto wire = ngap::encode(ics_with_key(0x5A));
    ASSERT_TRUE(wire);
    // The key's octets are in the PDU on the wire...
    const Bytes key(8, 0x5A);
    ASSERT_NE(std::search(wire->begin(), wire->end(), key.begin(), key.end()), wire->end());
    (*c)->ngap(false, *wire);
    (*c)->ngap(false, *from_hex("ff00ff"));   // does not decode: left out
    (*c)->f1ap(true, *from_hex("0001"));
    (*c)->rrc("nr-rrc.ul.ccch", *from_hex("1234"), "001010000300001");
    (*c)->nas(true, *from_hex("7e004179"), "001010000300001");
    const auto s = (*c)->stats();
    (*c)->close();
    EXPECT_EQ(s.ngap, 1u);
    EXPECT_EQ(s.keys_zeroed, 1u);
    EXPECT_EQ(s.left_out, 1u);
    EXPECT_EQ(s.f1ap, 1u);
    EXPECT_EQ(s.uu, 2u);
    // ... and nowhere in the capture.
    const Bytes pcap = read(dir + "/ngap.pcapng");
    EXPECT_GT(pcap.size(), wire->size());
    EXPECT_EQ(std::search(pcap.begin(), pcap.end(), key.begin(), key.end()), pcap.end());
    for (const char* f : {"/ngap.pcapng", "/f1ap.pcapng", "/uu.pcapng"}) {
        struct stat st {};
        ASSERT_EQ(::stat((dir + f).c_str(), &st), 0) << f;
        EXPECT_EQ(st.st_mode & 0777, 0600u) << f;
    }
    fs::remove_all(dir);
}

// P2 Q8 (ADR 0011): a headers-only capture keeps each GTP-U frame's first 128 octets
// with its length on the wire; off keeps none. The Enhanced Packet Blocks of the file
// (type 6): captured length at +20, original length at +24.
TEST(Capture, TheUserPlanePolicyKeepsHeadersOrNothing) {
    auto epbs = [](const Bytes& f) {
        std::vector<std::pair<std::uint32_t, std::uint32_t>> out;
        auto le = [&f](std::size_t at) {
            return std::uint32_t{f[at]} | std::uint32_t{f[at + 1]} << 8 | std::uint32_t{f[at + 2]} << 16 |
                   std::uint32_t{f[at + 3]} << 24;
        };
        for (std::size_t at = 0; at + 12 <= f.size();) {
            const std::uint32_t type = le(at);
            const std::uint32_t len = le(at + 4);
            if (len < 12 || at + len > f.size()) {
                break;
            }
            if (type == 6) {
                out.emplace_back(le(at + 20), le(at + 24));
            }
            at += len;
        }
        return out;
    };
    const Bytes payload(1400, 0x42);
    for (const auto policy : {UserPlaneCapture::headers, UserPlaneCapture::off}) {
        const std::string dir = temp_dir();
        auto c = Capture::open(dir, policy);
        ASSERT_TRUE(c);
        (*c)->gtpu(Endpoint::v4(127, 0, 0, 2, 2152), Endpoint::v4(127, 0, 0, 1, 2152), payload);
        (*c)->close();
        const auto blocks = epbs(read(dir + "/gtpu.pcapng"));
        if (policy == UserPlaneCapture::headers) {
            ASSERT_EQ(blocks.size(), 1u);
            EXPECT_EQ(blocks[0].first, Capture::kHeaderOctets);
            EXPECT_EQ(blocks[0].second, 20u + 8u + 1400u);   // IPv4, UDP, the G-PDU
        } else {
            EXPECT_TRUE(blocks.empty());
        }
        fs::remove_all(dir);
    }
}

TEST(Capture, ZeroesTheE1apUpKeysAndWritesGtpuAsIpv4Udp) {
    const std::string dir = temp_dir();
    auto c = Capture::open(dir);
    ASSERT_TRUE(c);
    e1ap::BearerContextSetupRequest r;
    r.cu_cp_ue = 1;
    r.security = e1ap::Security{2, 2, Bytes(16, 0x5A), Bytes(16, 0x6B)};
    r.ue_dl_ambr = 1'000'000;
    r.serving_plmn = e1ap::plmn_id("001", "01");
    e1ap::SessionToSetup s;
    s.psi = 1;
    s.snssai = e1ap::Snssai{1, std::nullopt};
    s.security = e1ap::SecurityIndication{"not-needed", "required"};
    s.ng_ul = e1ap::GtpTunnel{{127, 0, 0, 9}, 0x51000001};
    e1ap::DrbToSetup d;
    d.drb_id = 1;
    d.flows = {e1ap::QosFlow{1, 9, 8, false, true, std::nullopt, false}};
    s.drbs = {d};
    r.sessions = {s};
    auto wire = e1ap::encode(r);
    ASSERT_TRUE(wire) << wire.error().what;
    const Bytes enc(16, 0x5A);
    const Bytes integ(16, 0x6B);
    ASSERT_NE(std::search(wire->begin(), wire->end(), enc.begin(), enc.end()), wire->end());
    (*c)->e1ap(true, *wire);
    (*c)->e1ap(false, *from_hex("ff00ff"));   // does not decode: left out
    (*c)->gtpu(Endpoint::v4(127, 0, 0, 2, 2152), Endpoint::v4(127, 0, 0, 1, 2152), *from_hex("30ff0004510000014500"));
    const auto st = (*c)->stats();
    (*c)->close();
    EXPECT_EQ(st.e1ap, 1u);
    EXPECT_EQ(st.keys_zeroed, 2u);
    EXPECT_EQ(st.left_out, 1u);
    EXPECT_EQ(st.gtpu, 1u);
    const Bytes pcap = read(dir + "/e1ap.pcapng");
    EXPECT_EQ(std::search(pcap.begin(), pcap.end(), enc.begin(), enc.end()), pcap.end());
    EXPECT_EQ(std::search(pcap.begin(), pcap.end(), integ.begin(), integ.end()), pcap.end());
    const Bytes g = read(dir + "/gtpu.pcapng");
    const Bytes udp_ports{0x08, 0x68, 0x08, 0x68};   // 2152 -> 2152
    EXPECT_NE(std::search(g.begin(), g.end(), udp_ports.begin(), udp_ports.end()), g.end());
    for (const char* f : {"/e1ap.pcapng", "/gtpu.pcapng"}) {
        struct stat sb {};
        ASSERT_EQ(::stat((dir + f).c_str(), &sb), 0) << f;
        EXPECT_EQ(sb.st_mode & 0777, 0600u) << f;
    }
    fs::remove_all(dir);
}

TEST(TapDatagram, SeesEachDatagramBothWays) {
    SimLoop loop{0};
    MemNet net;
    auto a = net.bind(loop, Endpoint::v4(10, 0, 0, 1, 2152));
    auto b = net.bind(loop, Endpoint::v4(10, 0, 0, 2, 2152));
    ASSERT_TRUE(a && b);
    std::vector<std::pair<Endpoint, Endpoint>> seen;
    TapDatagram tap(std::move(*a), [&](const Endpoint& from, const Endpoint& to, ByteView) { seen.emplace_back(from, to); });
    int got = 0;
    tap.set_handler([&](ByteView, const Endpoint&) { ++got; });
    IDatagram* peer = b->get();
    peer->set_handler([&](ByteView m, const Endpoint& from) { (void)peer->send_to(m, from); });   // echo
    ASSERT_TRUE(tap.send_to(Bytes{1}, Endpoint::v4(10, 0, 0, 2, 2152)));
    ASSERT_TRUE(loop.run_until([&] { return got == 1; }, loop.now() + 100));
    ASSERT_EQ(seen.size(), 2u);
    EXPECT_EQ(seen[0].first, Endpoint::v4(10, 0, 0, 1, 2152));
    EXPECT_EQ(seen[1].first, Endpoint::v4(10, 0, 0, 2, 2152));
}

TEST(TapAssoc, SeesEachMessageInBothDirections) {
    SimLoop loop{0};
    MemAssocPair pair{loop, Endpoint::v4(10, 0, 0, 1, 0), loop, Endpoint::v4(10, 0, 0, 2, 38412), 2};
    std::vector<std::pair<bool, Bytes>> seen;
    TapAssoc tap(pair.a(), [&](bool tx, ByteView m) { seen.emplace_back(tx, Bytes(m.begin(), m.end())); });
    int got_a = 0;
    tap.set_handlers([&](ByteView, SctpMeta) { ++got_a; }, [](LinkEvent) {});
    pair.b().set_handlers([&](ByteView m, SctpMeta meta) { (void)pair.b().send(m, meta); }, [](LinkEvent) {});   // echo
    pair.connect();
    ASSERT_TRUE(loop.run_until([&] { return tap.up(); }, loop.now() + 100));
    ASSERT_TRUE(tap.send(Bytes{1, 2, 3}, SctpMeta{60, 0}));
    ASSERT_TRUE(loop.run_until([&] { return got_a == 1; }, loop.now() + 100));
    ASSERT_EQ(seen.size(), 2u);
    EXPECT_TRUE(seen[0].first);
    EXPECT_FALSE(seen[1].first);
    EXPECT_EQ(seen[1].second, (Bytes{1, 2, 3}));
}

} // namespace
} // namespace ksim::node
