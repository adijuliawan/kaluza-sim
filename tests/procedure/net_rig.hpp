// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The whole network in virtual time (P1 N10, shared from N12): a UE device
// (5GMM, 5GSM, RRC and its soft card) over KAIR to the DU; F1-C and E1 over
// memlink as encoded F1AP and E1AP; F1-U and N3 as GTP-U datagrams over a
// MemNet; NG-C to the core stub's AMF, its SMF and its UPF with the DN
// reflector. FakeUeNet stands in for ksim-netd's side of the TUN data plane.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../unit/uicc_card/fixture.hpp"
#include "codec/asn1/msg/e1ap.hpp"
#include "ngap_amf.hpp"
#include "node/ue/device.hpp"
#include "platform/memlink.hpp"
#include "platform/mutation.hpp"
#include "platform/sim_loop.hpp"
#include "proc/ran/cucp.hpp"
#include "proc/ran/cuup.hpp"
#include "proc/ran/du.hpp"

namespace ksim::proctest {


inline const char* kSupi = "001010000300001";
inline const nas::ie::Plmn kPlmn{"001", "01"};
inline const std::string kUe = std::string("ue:imsi-") + kSupi;

inline std::unique_ptr<IDatagram> port(MemNet& net, SimLoop& loop, std::uint8_t host) {
    auto p = net.bind(loop, Endpoint::v4(127, 0, 0, host, 2152));
    return p ? std::move(*p) : nullptr;
}

inline proc::ran::CuUpConfig cuup_config() {
    proc::ran::CuUpConfig c;
    c.n3_addr = {127, 0, 0, 31};
    c.f1u_addr = {127, 0, 0, 32};
    return c;
}

inline proc::ran::DuConfig du_config() {
    proc::ran::DuConfig c;
    c.f1u_addr = {127, 0, 0, 33};
    return c;
}

/// The system's side of the TUN data plane, in memory (P1 N11): what the device
/// asked for, and each TUN's kernel side for the test to drive.
class FakeUeNet final : public node::IUeNet {
public:
    struct Tun final : IPacketPort {
        OnPacket on;
        std::vector<Bytes> written;   // what the device wrote: the downlink
        void set_handler(OnPacket h) override { on = std::move(h); }
        Result<void> write(ByteView p) override {
            written.emplace_back(p.begin(), p.end());
            return {};
        }
        std::uint64_t dropped() const noexcept override { return 0; }
        void from_kernel(const Bytes& p) const { on(p); }   // the namespace's stack sends
    };
    Result<void> setup(const std::string& n) override {
        setups.push_back(n);
        return {};
    }
    Result<std::unique_ptr<IPacketPort>> open_tun(const std::string&, const node::UeTun& t) override {
        auto port = std::make_unique<Tun>();
        tuns[t.ifname] = port.get();
        specs[t.ifname] = t;
        return std::unique_ptr<IPacketPort>(std::move(port));
    }
    void close_tun(const std::string&, const node::UeTun& t) override {
        tuns.erase(t.ifname);
        closed.push_back(t.ifname);
    }
    Result<void> resolv(const std::string&, ip::Addr dns) override {
        dnss.push_back(dns);
        return {};
    }
    void teardown(const std::string& n) override { teardowns.push_back(n); }
    Result<std::uint32_t> exec(const std::string&, const std::vector<std::string>& argv, std::vector<int>) override {
        execs.push_back(argv);
        return 77;
    }
    std::vector<std::string> setups;
    std::map<std::string, Tun*> tuns;
    std::map<std::string, node::UeTun> specs;
    std::vector<std::string> closed;
    std::vector<ip::Addr> dnss;
    std::vector<std::string> teardowns;
    std::vector<std::vector<std::string>> execs;
};

struct Net {
    explicit Net(corestub::Profile p = {}, node::IUeNet* ue_net = nullptr)
        : amf(loop, home, kPlmn, std::move(p), ng.b(), upf_port.get(), {127, 0, 0, 9}) {
        home.add(kSupi, uicc::test::sb("465b5ce8b199b49faa5f0a2ee238a6bc"), uicc::test::sb("cd63cb71954a9f4e48a5994e37a02baf"));
        node::UeDeviceConfig uc;
        uc.supi = kSupi;
        uc.radio_id = 7;
        uc.plmn = kPlmn;
        uc.nssai = {nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}};
        uc.imeisv = "8600000000000101";
        uc.seed = 5;
        if (ue_net != nullptr) {
            uc.netns = "ksim-ue-1";
        }
        ue = std::make_unique<node::UeDevice>(loop, events, uc, uicc::test::make_card(), [this](const air::Frame& f) {
            loop.start_timer(1, [this, f] {
                if (!air_down) {
                    du.on_frame(f);
                }
            });
        }, node::UeTaps{}, ue_net);
    }

    ~Net() {
    // The in-process card answers on the loop's next turn (uicc/transport): a
    // card write still in flight (N12 writes at accepts and de-registrations)
    // finishes before the UE goes, so no procedure is left suspended.
        loop.run_until([] { return false; }, loop.now() + 1);
    }
    Net(const Net&) = delete;
    Net& operator=(const Net&) = delete;

    void start() {
        f1.connect();
        e1.connect();
        ng.connect();
        ASSERT_TRUE(loop.run_until([&] { return cucp.ng_ready() && du.cell_active() && cucp.e1_ready(); }, loop.now() + 1'000));
    }
    void register_ue() {
        start();
        ASSERT_TRUE(ue->power_on());
        ASSERT_TRUE(loop.run_until([&] { return !named("nas.reg.complete").empty(); }, loop.now() + 15'000));
        ASSERT_TRUE(loop.run_until([&] { return amf.count("InitialContextSetupResponse") == 1; }, loop.now() + 1'000));
    }
    /// Asks for a session and waits for the accept and the gNB's resources.
    void establish(const std::string& dnn = "internet") {
        const auto before = named("nas.sm.est.accept").size();
        const auto setups = named("ran.session.setup").size();
        ASSERT_TRUE(ue->ps_establish(proc::ue::SessionRequest{0, dnn, nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}}));
        ASSERT_TRUE(loop.run_until([&] {
            return named("nas.sm.est.accept").size() > before && named("ran.session.setup").size() > setups &&
                   amf.count("PDUSessionResourceSetupResponse") > setups;
        }, loop.now() + 5'000)) << failures();
    }
    std::vector<Event> named(std::string_view name) const {
        std::vector<Event> out;
        for (auto& e : events.since(0, 65536)) {
            if (e.name == name) {
                out.push_back(e);
            }
        }
        return out;
    }
    std::string failures() const {
        std::string out;
        for (const auto& v : amf.failures()) {
            out += "[" + v.clause + "] " + v.what + (v.detail.empty() ? "" : " (" + v.detail + ")") + "\n";
        }
        for (const auto& e : named("nas.mm.usim_error")) {   // a write the card refused is a sim bug
            const std::string* fid = e.find("fid");
            out += "[USIM] write refused, fid " + (fid != nullptr ? *fid : std::string("?")) + "\n";
        }
        return out;
    }
    const Event* last(std::string_view name) const {
        static thread_local std::vector<Event> keep;
        keep = named(name);
        return keep.empty() ? nullptr : &keep.back();
    }

    SimLoop loop{0};
    EventRing events{65536, loop.clock()};
    corestub::Home home{Rng(7, {1})};
    MemAssocPair f1{loop, Endpoint::v4(127, 0, 0, 3, 0), loop, Endpoint::v4(127, 0, 0, 2, 38472), 2};
    MemAssocPair e1{loop, Endpoint::v4(127, 0, 0, 31, 0), loop, Endpoint::v4(127, 0, 0, 2, 38462), 2};
    MemAssocPair ng{loop, Endpoint::v4(127, 0, 0, 2, 0), loop, Endpoint::v4(127, 0, 0, 1, 38412), 3};
    MemNet net;
    std::unique_ptr<IDatagram> upf_port = port(net, loop, 9);
    std::unique_ptr<IDatagram> cuup_n3 = port(net, loop, 31);
    std::unique_ptr<IDatagram> cuup_f1u = port(net, loop, 32);
    std::unique_ptr<IDatagram> du_f1u = port(net, loop, 33);
    corestub::NgapAmf amf;
    proc::ran::CuCp cucp{loop, events, proc::ran::CuCpConfig{}, ng.a(), f1.b(), &e1.b()};
    proc::ran::CuUp cuup{loop, events, cuup_config(), e1.a(), *cuup_n3, *cuup_f1u};
    proc::ran::Du du{loop, events, du_config(), f1.a(),
                     [this](const air::Frame& f) {
                         loop.start_timer(1, [this, f] {
                             if (!air_down && (f.radio_id == 0 || f.radio_id == 7)) {
                                 ue->on_frame(f);
                             }
                         });
                     },
                     du_f1u.get()};
    std::unique_ptr<node::UeDevice> ue;
    bool air_down = false;   // N12: the cell out of reach both ways (radio link failure)
};

} // namespace ksim::proctest
