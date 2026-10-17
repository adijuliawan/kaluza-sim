// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Fault injection, off by default and recorded (P3 R3; ADR 0013 point 9; architecture.md
// section 9; KS-CTL-006, KS-L2R-001): a node's registry of the faults set on it, and the
// wrappers that apply them on its links.
//
// A rule names a link and a direction, optionally a message and a UE, and an action:
//   link     ngap f1ap e1ap (an AP message by its ASN.1 name, "InitialContextSetupRequest"),
//            uu (a KAIR frame by its type as kair.hpp names it, "UL_SDU"; the UE by its radio ID),
//            n3 f1u (a GTP-U message by its TS 29.281 name, "G-PDU")
//   dir      ul (towards the core: UE to DU, DU to CU, CU-UP to CU-CP, gNB to AMF and UPF),
//            dl, or any
//   action   drop, delay (ms) or duplicate, on the first N matches, or on every one (x*)
//   percent  of the matches it acts on: a link's loss
// On uu a rule on every match (x*) is the air link's loss: the ideal RLC's AM bearers
// retransmit (TS 38.322 §5.3.2), one t-PollRetransmit later each time, and a SDU still lost
// after maxRetxThreshold retransmissions is a radio link failure at its transmitter (TS
// 38.331 §5.3.10.3); a rule on N matches drops the frame itself.
// Every rule set, spent and cleared goes to <run>/faults.tsv with the gate row it serves, so
// a run with a fault says so (tools/p3_exit.py); FAULTS=0 when none is set. The registry is
// shared by a process's shards (a farm's lanes), so it locks; a link with no rule costs one
// atomic load.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "codec/air/kair.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/result.hpp"
#include "platform/rng.hpp"
#include "platform/transport.hpp"

namespace ksim::node {

struct FaultRule {
    enum class Action : std::uint8_t { drop, delay, duplicate };
    std::string link;                  // ngap f1ap e1ap uu n3 f1u
    std::string dir = "any";           // ul dl any
    std::string message;               // empty: any message
    std::optional<std::uint32_t> ue;   // uu: the radio ID
    Action action = Action::drop;
    Millis delay_ms = 0;
    unsigned count = 1;                // the matches it acts on; 0: every one
    unsigned percent = 100;            // of the matches it acts on
    std::string row = "-";             // the gate row it serves
};

struct FaultVerdict {
    bool drop = false;
    Millis delay_ms = 0;
    bool duplicate = false;
    unsigned loss_percent = 0;   // the highest percent of the every-match drop rules that matched
    bool rlf = false;            // uu: an AM SDU lost past maxRetxThreshold
};

const char* action_name(FaultRule::Action a) noexcept;

/// The rule a `ksim-ctl faults set` text names (cli.md): "<link>.<dir> [msg=M] [ue=N]
/// drop|dup|delay=MS [xN|x*] [pct=P]".
Result<FaultRule> parse_rule(std::string_view text);
std::string rule_text(const FaultRule& r);

class Faults {
public:
    // The ideal RLC's AM parameters, as the CU sends them (rrc.cpp, RLC-BearerConfig).
    static constexpr unsigned kMaxRetxThreshold = 8;   // t8
    static constexpr Millis kPollRetransmitMs = 45;    // ms45

    Faults(IEventSink& events, std::string subject, std::uint64_t seed);
    /// Where set, spent and cleared rules are written (none: not recorded, as in unit tests).
    void record_to(std::string path);

    /// `id` 0: the next free one; a split run's supervisor gives the same id to every role.
    Result<std::uint32_t> set(const FaultRule& r, std::uint32_t id = 0);
    bool clear(std::uint32_t id);
    std::size_t clear_all();
    std::size_t size() const noexcept { return n_.load(std::memory_order_acquire); }

    struct Active {
        std::uint32_t id = 0;
        FaultRule rule;
        std::uint64_t hits = 0;
        unsigned left = 0;
    };
    std::vector<Active> list() const;

    /// A rule names `link`: one atomic load, so a link with none pays nothing more.
    bool on(std::string_view link) const noexcept;
    /// Whether some rule on `link` names a message (else the caller need not name it).
    bool names_messages(std::string_view link) const;
    FaultVerdict check(std::string_view link, std::string_view dir, std::string_view message,
                       std::optional<std::uint32_t> ue = std::nullopt);
    /// A KAIR frame on the air (dir ul or dl): check(), then the AM bearers' retransmissions.
    FaultVerdict air(std::string_view dir, const air::Frame& f);

private:
    void log(const char* what, const Active& a);
    void update_mask();

    IEventSink& events_;
    std::string subject_;
    mutable std::mutex mu_;
    Rng rng_;
    std::string path_;
    std::vector<Active> active_;
    std::uint32_t next_ = 1;
    std::atomic<std::size_t> n_{0};
    std::atomic<std::uint32_t> mask_{0};   // a bit per link with a rule
};

/// An association whose messages go through `faults` on `link`, `tx_dir` for what this end
/// sends and `rx_dir` for what it takes; `proto` names AP messages (codec/asn1 registry).
/// It sits above the capture tap: a message dropped on send is not captured, one dropped on
/// receipt was (it reached the node's socket).
class FaultAssoc final : public IAssoc {
public:
    FaultAssoc(IAssoc& inner, Faults& faults, TimerService& timers, std::string link, const char* tx_dir,
               const char* rx_dir);
    ~FaultAssoc() override { *alive_ = false; }
    FaultAssoc(const FaultAssoc&) = delete;
    FaultAssoc& operator=(const FaultAssoc&) = delete;

    void set_handlers(OnMessage on_message, OnEvent on_event) override;
    Result<void> send(ByteView msg, SctpMeta meta) override;
    bool up() const noexcept override { return inner_.up(); }
    std::uint16_t out_streams() const noexcept override { return inner_.out_streams(); }
    std::uint16_t in_streams() const noexcept override { return inner_.in_streams(); }
    void shutdown() override { inner_.shutdown(); }
    void abort() override { inner_.abort(); }
    Endpoint peer() const override { return inner_.peer(); }

private:
    FaultVerdict verdict(const char* dir, ByteView msg);

    IAssoc& inner_;
    Faults& faults_;
    TimerService& timers_;
    std::string link_;
    const char* tx_dir_;
    const char* rx_dir_;
    OnMessage on_message_;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

/// A datagram port whose GTP-U messages go through `faults` on `link` (n3, f1u).
class FaultDatagram final : public IDatagram {
public:
    FaultDatagram(std::unique_ptr<IDatagram> inner, Faults& faults, TimerService& timers, std::string link,
                  const char* tx_dir, const char* rx_dir);
    ~FaultDatagram() override { *alive_ = false; }
    FaultDatagram(const FaultDatagram&) = delete;
    FaultDatagram& operator=(const FaultDatagram&) = delete;

    void set_handler(OnDatagram on_datagram) override;
    Result<void> send_to(ByteView payload, const Endpoint& to) override;
    Endpoint local() const override { return inner_->local(); }
    std::uint64_t dropped() const noexcept override { return inner_->dropped(); }

private:
    FaultVerdict verdict(const char* dir, ByteView payload);

    std::unique_ptr<IDatagram> inner_;
    Faults& faults_;
    TimerService& timers_;
    std::string link_;
    const char* tx_dir_;
    const char* rx_dir_;
    OnDatagram on_datagram_;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

} // namespace ksim::node
