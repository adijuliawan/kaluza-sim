// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Several cells and gNBs in virtual time (P3 R2; ADR 0013 points 2, 3, 6): one
// core stub whose AMF takes every gNB's NG-C on its own link; gNB A, a CU-CP with
// two DUs (one cell each, D7) and a CU-UP; gNB B, a CU-CP with one DU and its
// CU-UP. Every DU's frames reach every UE, and a StaticView decides which a UE
// hears and how strongly; a UE's uplink goes to the DU of the cell its frame
// names. F1-C, E1 and NG-C are memlink pairs, F1-U and N3 a MemNet, as net_rig.hpp.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "net_rig.hpp"
#include "platform/assoc_pool.hpp"
#include "radio/view.hpp"

namespace ksim::proctest {

// Cells by their KAIR handles; A1 and A2 under gNB A's CU-CP, B1 under gNB B's.
inline constexpr std::uint32_t kCellA1 = 1;
inline constexpr std::uint32_t kCellA2 = 2;
inline constexpr std::uint32_t kCellB1 = 3;

inline proc::ran::DuConfig du2_config(std::uint32_t handle, std::uint32_t gnb, std::uint32_t local, std::uint16_t pci,
                                      std::uint32_t tac, std::uint8_t f1u_host) {
    proc::ran::DuConfig c;
    c.id = "gnb:du" + std::to_string(handle);
    c.du_id = handle;
    c.name = "ksim-du" + std::to_string(handle);
    c.cell_handle = handle;
    c.nci = (std::uint64_t{gnb} << 14) | local;
    c.pci = pci;
    c.tac = tac;
    c.f1u_addr = {127, 0, 0, f1u_host};
    return c;
}

/// A gNB: its CU-CP over a pool of F1 links, its CU-UP, its DUs.
struct Gnb2 {
    Gnb2(SimLoop& loop, EventRing& events, MemNet& net, IAssoc& ng, std::uint32_t gnb_id, std::uint8_t host,
         std::vector<proc::ran::DuConfig> dus, const std::function<void(const air::Frame&)>& to_ue)
        : e1(loop, Endpoint::v4(127, 0, host, 31, 0), loop, Endpoint::v4(127, 0, host, 2, 38462), 2),
          n3(port(net, loop, static_cast<std::uint8_t>(host * 10 + 1))),
          f1u(port(net, loop, static_cast<std::uint8_t>(host * 10 + 2))) {
        proc::ran::CuCpConfig cc = cucp_config();
        cc.id = "gnb:cucp" + std::to_string(host);
        cc.name = "ksim-gnb" + std::to_string(host);
        cc.gnb_id = gnb_id;
        proc::ran::CuUpConfig uc = cuup_config();
        uc.id = "gnb:cuup" + std::to_string(host);
        uc.n3_addr = {127, 0, 0, static_cast<std::uint8_t>(host * 10 + 1)};
        uc.f1u_addr = {127, 0, 0, static_cast<std::uint8_t>(host * 10 + 2)};
        cuup = std::make_unique<proc::ran::CuUp>(loop, events, uc, e1.a(), *n3, *f1u);
        for (std::size_t i = 0; i < dus.size(); ++i) {
            f1s.push_back(std::make_unique<MemAssocPair>(loop, Endpoint::v4(127, 0, host, static_cast<std::uint8_t>(3 + i), 0),
                                                         loop, Endpoint::v4(127, 0, host, 2, 38472), 2));
            du_f1u.push_back(port(net, loop, dus[i].f1u_addr[3]));
        }
        for (auto& f : f1s) {
            pool.add(f->b());
        }
        cucp = std::make_unique<proc::ran::CuCp>(loop, events, cc, ng, pool, &e1.b());
        for (std::size_t i = 0; i < dus.size(); ++i) {
            du.push_back(std::make_unique<proc::ran::Du>(loop, events, dus[i], f1s[i]->a(), to_ue, du_f1u[i].get()));
        }
    }

    MemAssocPair e1;
    std::unique_ptr<IDatagram> n3;
    std::unique_ptr<IDatagram> f1u;
    std::vector<std::unique_ptr<MemAssocPair>> f1s;
    std::vector<std::unique_ptr<IDatagram>> du_f1u;
    AssocPool pool;
    std::unique_ptr<proc::ran::CuUp> cuup;
    std::unique_ptr<proc::ran::CuCp> cucp;
    std::vector<std::unique_ptr<proc::ran::Du>> du;
};

struct Net2 {
    struct UeSpec {
        std::string supi;
        std::uint32_t radio_id = 1;
    };

    explicit Net2(corestub::Profile p = {}, std::uint32_t tac_a2 = 1, std::uint32_t tac_b1 = 1)
        : amf(loop, home, kPlmn, with_tacs(std::move(p), tac_a2, tac_b1), ng_pool, upf_port.get(), {127, 0, 0, 9}) {
        ng_pool.add(ng_a.b());
        ng_pool.add(ng_b.b());
        const auto to_ue = [this](const air::Frame& f) { to_ues(f); };
        a = std::make_unique<Gnb2>(loop, events, net, ng_a.a(), 0x1A0, 1,
                                   std::vector<proc::ran::DuConfig>{du2_config(kCellA1, 0x1A0, 1, 101, 1, 41),
                                                                    du2_config(kCellA2, 0x1A0, 2, 102, tac_a2, 42)},
                                   to_ue);
        b = std::make_unique<Gnb2>(loop, events, net, ng_b.a(), 0x1A2, 2,
                                   std::vector<proc::ran::DuConfig>{du2_config(kCellB1, 0x1A2, 1, 103, tac_b1, 43)}, to_ue);
        view.set_cell(kCellA1, -80);
        view.set_cell(kCellA2, -80);
        view.set_cell(kCellB1, -80);
    }
    ~Net2() { loop.run_until([] { return false; }, loop.now() + 1); }
    Net2(const Net2&) = delete;
    Net2& operator=(const Net2&) = delete;

    static corestub::Profile with_tacs(corestub::Profile p, std::uint32_t a2, std::uint32_t b1) {
        for (std::uint32_t t : {a2, b1}) {
            if (std::find(p.tacs.begin(), p.tacs.end(), t) == p.tacs.end()) {
                p.tacs.push_back(t);
            }
        }
        return p;
    }

    /// A UE that hears `strongest` at -60 dBm and every other cell at -80 (or not at all).
    node::UeDevice& add_ue(const std::string& supi, std::uint32_t radio_id, std::uint32_t strongest, bool hears_others = true) {
        home.add(supi, uicc::test::sb("465b5ce8b199b49faa5f0a2ee238a6bc"), uicc::test::sb("cd63cb71954a9f4e48a5994e37a02baf"));
        for (std::uint32_t c : {kCellA1, kCellA2, kCellB1}) {
            view.set_ue_cell(radio_id, c, c == strongest ? std::optional<std::int16_t>(-60)
                                          : hears_others ? std::optional<std::int16_t>(-80)
                                                         : std::nullopt);
        }
        node::UeDeviceConfig uc;
        uc.supi = supi;
        uc.radio_id = radio_id;
        uc.plmn = kPlmn;
        uc.nssai = {nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}};
        uc.imeisv = "8600000000000101";
        uc.seed = radio_id;
        uc.view = &view;
        // A sim-range card for this SUPI (sim-uicc.md §8), the rig's test K and OPc.
        auto card = uicc::image::load(Yaml::load_file(uicc::test::template_path()),
                                      uicc::test::test_secrets(uicc::test::sb("465b5ce8b199b49faa5f0a2ee238a6bc"),
                                                               uicc::test::sb("cd63cb71954a9f4e48a5994e37a02baf")));
        const auto sub = uicc::image::range_subscriber(supi);
        EXPECT_TRUE(sub && uicc::image::personalise(*card, *sub)) << supi;
        ues[radio_id] = std::make_unique<node::UeDevice>(
            loop, events, uc, std::move(card), [this](const air::Frame& f) { to_du(f); }, node::UeTaps{}, nullptr);
        return *ues[radio_id];
    }

    void start() {
        for (Gnb2* g : {a.get(), b.get()}) {
            for (auto& f : g->f1s) {
                f->connect();
            }
            g->e1.connect();
        }
        ng_a.connect();
        ng_b.connect();
        ASSERT_TRUE(loop.run_until([&] { return a->cucp->ng_ready() && b->cucp->ng_ready() && a->cucp->dus() == 2; },
                                   loop.now() + 2'000));
    }

    std::vector<Event> named(std::string_view name, std::string_view subject = {}) const {
        std::vector<Event> out;
        for (auto& e : events.since(0, 65536)) {
            if (e.name == name && (subject.empty() || e.subject == subject)) {
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
        return out;
    }

    SimLoop loop{0};
    EventRing events{65536, loop.clock()};
    corestub::Home home{Rng(7, {1})};
    MemNet net;
    std::unique_ptr<IDatagram> upf_port = port(net, loop, 9);
    MemAssocPair ng_a{loop, Endpoint::v4(127, 0, 1, 2, 0), loop, Endpoint::v4(127, 0, 0, 1, 38412), 10};
    MemAssocPair ng_b{loop, Endpoint::v4(127, 0, 2, 2, 0), loop, Endpoint::v4(127, 0, 0, 1, 38412), 10};
    AssocPool ng_pool;
    corestub::NgapAmf amf;
    radio::StaticView view;
    std::unique_ptr<Gnb2> a;
    std::unique_ptr<Gnb2> b;
    std::map<std::uint32_t, std::unique_ptr<node::UeDevice>> ues;
    bool air_down = false;

private:
    proc::ran::Du* du_of(std::uint32_t cell) {
        for (Gnb2* g : {a.get(), b.get()}) {
            for (auto& d : g->du) {
                if (d->cell_handle() == cell) {
                    return d.get();
                }
            }
        }
        return nullptr;
    }
    void to_ues(const air::Frame& f) {
        loop.start_timer(1, [this, f] {
            if (air_down) {
                return;
            }
            for (auto& [id, ue] : ues) {
                if (f.radio_id == 0 || f.radio_id == id) {
                    ue->on_frame(f);
                }
            }
        });
    }
    void to_du(const air::Frame& f) {
        loop.start_timer(1, [this, f] {
            if (air_down) {
                return;
            }
            if (proc::ran::Du* d = du_of(f.cell_handle); d != nullptr && view.level(f.radio_id, f.cell_handle)) {
                d->on_frame(f);
            }
        });
    }
};

} // namespace ksim::proctest
