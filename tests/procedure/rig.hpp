// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A UE's 5GMM entity, its soft card and the core stub on one SimLoop (P1 N5):
// the procedure tests' rig. The link between the UE and the stub models one
// N1 signalling connection at a time with a 1 ms hop each way: a message
// carries the connection it was sent on and is dropped if that connection is
// gone at the other end when it arrives; a release travels in order behind
// the messages sent before it.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "../unit/uicc_card/fixture.hpp"
#include "amf.hpp"
#include "home.hpp"
#include "platform/event.hpp"
#include "platform/sim_loop.hpp"
#include "proc/ue/nas_mm/mm.hpp"
#include "uicc/terminal/terminal.hpp"
#include "uicc/transport/transport.hpp"

namespace ksim::proctest {

class Link final : public proc::ue::INasLower {
public:
    Link(SimLoop& loop, Millis hop) : loop_(loop), hop_(hop) {}
    void bind(proc::ue::Mm* ue, corestub::Amf* amf) {
        ue_ = ue;
        amf_ = amf;
        amf_->attach({[this](Bytes b) { to_ue(std::move(b)); }, [this] { release_from_network(); }, {}, {}, {}, {}});
    }

    void send_nas(Bytes pdu) override {
        const bool initial = ue_conn_ == 0;
        if (initial) {
            ue_conn_ = ++next_;
        }
        const std::uint64_t id = ue_conn_;
        loop_.start_timer(hop_, [this, id, initial, pdu = std::move(pdu)] {
            if (initial) {
                net_conn_ = id;
            } else if (net_conn_ != id) {
                return;
            }
            amf_->on_uplink(pdu, initial);
        });
    }
    void release_local() override {
        const std::uint64_t id = ue_conn_;
        ue_conn_ = 0;
        ++local_releases;
        loop_.start_timer(hop_, [this, id] {
            if (net_conn_ == id && id != 0) {
                net_conn_ = 0;
                amf_->on_ue_released();
            }
        });
    }

    void to_ue(Bytes pdu) {
        const std::uint64_t id = net_conn_;
        loop_.start_timer(hop_, [this, id, pdu = std::move(pdu)] {
            if (id != 0 && ue_conn_ == id) {
                ue_->on_nas(pdu);
            }
        });
    }
    void release_from_network() {
        const std::uint64_t id = net_conn_;
        net_conn_ = 0;
        ++network_releases;
        loop_.start_timer(hop_, [this, id] {
            if (id != 0 && ue_conn_ == id) {
                ue_conn_ = 0;
                ue_->on_released();
            }
        });
    }

    int local_releases = 0;
    int network_releases = 0;

private:
    SimLoop& loop_;
    Millis hop_;
    proc::ue::Mm* ue_ = nullptr;
    corestub::Amf* amf_ = nullptr;
    std::uint64_t next_ = 0;
    std::uint64_t ue_conn_ = 0;
    std::uint64_t net_conn_ = 0;
};

inline const char* kSupi = "001010000300001";
inline const nas::ie::Plmn kPlmn{"001", "01"};

inline proc::ue::MmConfig ue_config() {
    proc::ue::MmConfig c;
    c.id = std::string("ue:imsi-") + kSupi;
    c.plmn = kPlmn;
    c.requested_nssai = {nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}};
    c.imeisv = "8600000000000101";
    return c;
}

struct Rig {
    explicit Rig(corestub::Profile p = {}, proc::ue::MmConfig cfg = ue_config())
        : card(uicc::test::make_card()),
          transport(loop, card.get()),
          terminal(transport),
          home(Rng(7, {1})),
          amf(loop, home, kPlmn, std::move(p)),
          link(loop, 1),
          ue(loop, terminal, link, events, std::move(cfg)) {
        home.add(kSupi, uicc::test::sb("465b5ce8b199b49faa5f0a2ee238a6bc"),
                 uicc::test::sb("cd63cb71954a9f4e48a5994e37a02baf"));
        link.bind(&ue, &amf);
    }
    ~Rig() {
    // The in-process card answers on the loop's next turn (uicc/transport): a
    // card write still in flight (N12 writes at accepts and de-registrations)
    // finishes before the UE goes, so no procedure is left suspended.
        loop.run_until([] { return false; }, loop.now() + 1);
    }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;

    /// Powers the UE on and waits for its first 5GMM-DEREGISTERED substate.
    void power_on() {
        ue.power_on();
        EXPECT_TRUE(loop.run_until([&] { return ue.state() != proc::ue::MmState::null; }, loop.now() + 10'000));
    }
    bool run_until(const std::function<bool()>& done, Millis within) { return loop.run_until(done, loop.now() + within); }
    /// Registers from power-on and waits for 5GMM-REGISTERED.NORMAL-SERVICE.
    bool registered() {
        power_on();
        ue.register_initial();
        return run_until([&] { return ue.state() == proc::ue::MmState::registered_normal_service; }, 60'000);
    }

    std::vector<Event> named(std::string_view name) const {
        std::vector<Event> out;
        for (auto& e : events.since(0)) {
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
        return out;
    }

    SimLoop loop{0};
    EventRing events{8192, loop.clock()};
    std::unique_ptr<uicc::os::Card> card;
    uicc::InProcTransport transport;
    uicc::Terminal terminal;
    corestub::Home home;
    corestub::Amf amf;
    Link link;
    proc::ue::Mm ue;
};

} // namespace ksim::proctest
