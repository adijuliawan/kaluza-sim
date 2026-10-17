// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/faults.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <sstream>

#include "codec/asn1/msg/names.hpp"
#include "codec/up/gtpu.hpp"

namespace ksim::node {

namespace {

constexpr std::string_view kLinks[] = {"ngap", "f1ap", "e1ap", "uu", "n3", "f1u"};

int link_bit(std::string_view link) noexcept {
    for (std::size_t i = 0; i < std::size(kLinks); ++i) {
        if (kLinks[i] == link) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

std::optional<unsigned> number(std::string_view s) {
    unsigned v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc() || p != s.data() + s.size()) {
        return std::nullopt;
    }
    return v;
}

} // namespace

const char* action_name(FaultRule::Action a) noexcept {
    switch (a) {
    case FaultRule::Action::drop: return "drop";
    case FaultRule::Action::delay: return "delay";
    case FaultRule::Action::duplicate: return "dup";
    }
    return "?";
}

std::string rule_text(const FaultRule& r) {
    std::ostringstream o;
    o << r.link << '.' << r.dir;
    if (!r.message.empty()) {
        o << " msg=" << r.message;
    }
    if (r.ue) {
        o << " ue=" << *r.ue;
    }
    o << ' ' << action_name(r.action);
    if (r.action == FaultRule::Action::delay) {
        o << '=' << r.delay_ms;
    }
    o << (r.count == 0 ? std::string(" x*") : " x" + std::to_string(r.count));
    if (r.percent != 100) {
        o << " pct=" << r.percent;
    }
    return o.str();
}

Result<FaultRule> parse_rule(std::string_view text) {
    FaultRule r;
    std::istringstream in{std::string(text)};
    std::string w;
    bool have_action = false;
    if (!(in >> w) || w.find('.') == std::string::npos) {
        return make_error(Errc::invalid_argument, 0, "faults: a rule starts <link>.<dir>, e.g. uu.ul");
    }
    r.link = w.substr(0, w.find('.'));
    r.dir = w.substr(w.find('.') + 1);
    while (in >> w) {
        if (w.rfind("msg=", 0) == 0) {
            r.message = w.substr(4);
        } else if (w.rfind("ue=", 0) == 0) {
            r.ue = number(std::string_view(w).substr(3));
            if (!r.ue) {
                return make_error(Errc::invalid_argument, 0, "faults: ue=<radio id>");
            }
        } else if (w == "drop" || w == "dup") {
            r.action = w == "drop" ? FaultRule::Action::drop : FaultRule::Action::duplicate;
            have_action = true;
        } else if (w.rfind("delay=", 0) == 0) {
            const auto n = number(std::string_view(w).substr(6));
            if (!n) {
                return make_error(Errc::invalid_argument, 0, "faults: delay=<ms>");
            }
            r.action = FaultRule::Action::delay;
            r.delay_ms = static_cast<Millis>(*n);
            have_action = true;
        } else if (w == "x*") {
            r.count = 0;
        } else if (w.size() > 1 && w[0] == 'x') {
            const auto n = number(std::string_view(w).substr(1));
            if (!n || *n == 0) {
                return make_error(Errc::invalid_argument, 0, "faults: xN (N of at least 1) or x*");
            }
            r.count = *n;
        } else if (w.rfind("pct=", 0) == 0) {
            const auto n = number(std::string_view(w).substr(4));
            if (!n) {
                return make_error(Errc::invalid_argument, 0, "faults: pct=<1..100>");
            }
            r.percent = *n;
        } else {
            return make_error(Errc::invalid_argument, 0, "faults: a rule's words are msg= ue= drop dup delay= xN x* pct=");
        }
    }
    if (!have_action) {
        return make_error(Errc::invalid_argument, 0, "faults: a rule says drop, dup or delay=<ms>");
    }
    return r;
}

Faults::Faults(IEventSink& events, std::string subject, std::uint64_t seed)
    : events_(events), subject_(std::move(subject)), rng_(seed, {0xFA017}) {}

void Faults::record_to(std::string path) {
    const std::lock_guard lock(mu_);
    path_ = std::move(path);
}

Result<std::uint32_t> Faults::set(const FaultRule& r, std::uint32_t id) {
    if (link_bit(r.link) < 0) {
        return make_error(Errc::invalid_argument, 0, "faults: the link is ngap, f1ap, e1ap, uu, n3 or f1u");
    }
    if (r.dir != "ul" && r.dir != "dl" && r.dir != "any") {
        return make_error(Errc::invalid_argument, 0, "faults: the direction is ul, dl or any");
    }
    if (r.percent == 0 || r.percent > 100) {
        return make_error(Errc::invalid_argument, 0, "faults: pct is 1..100");
    }
    if (r.action == FaultRule::Action::delay && (r.delay_ms <= 0 || r.delay_ms > 60'000)) {
        return make_error(Errc::invalid_argument, 0, "faults: a delay is 1..60000 ms");
    }
    if (r.ue && r.link != "uu") {
        return make_error(Errc::invalid_argument, 0, "faults: ue= is for the air (uu)");
    }
    Active a;
    {
        const std::lock_guard lock(mu_);
        if (id == 0) {
            id = next_;
        }
        if (std::any_of(active_.begin(), active_.end(), [id](const Active& x) { return x.id == id; })) {
            return make_error(Errc::invalid_argument, 0, "faults: that id is set already");
        }
        next_ = std::max(next_, id + 1);
        a = Active{id, r, 0, r.count};
        active_.push_back(a);
        log("set", a);
        update_mask();
    }
    events_.emit("fault.set", subject_, {{"id", std::to_string(id)}, {"rule", rule_text(r)}, {"row", r.row}});
    return id;
}

bool Faults::clear(std::uint32_t id) {
    Active a;
    {
        const std::lock_guard lock(mu_);
        auto it = std::find_if(active_.begin(), active_.end(), [id](const Active& x) { return x.id == id; });
        if (it == active_.end()) {
            return false;
        }
        a = *it;
        active_.erase(it);
        log("clear", a);
        update_mask();
    }
    events_.emit("fault.clear", subject_, {{"id", std::to_string(id)}, {"hits", std::to_string(a.hits)}});
    return true;
}

std::size_t Faults::clear_all() {
    std::size_t n = 0;
    for (const auto& a : list()) {
        n += clear(a.id) ? 1 : 0;
    }
    return n;
}

std::vector<Faults::Active> Faults::list() const {
    const std::lock_guard lock(mu_);
    return active_;
}

bool Faults::on(std::string_view link) const noexcept {
    const int b = link_bit(link);
    return b >= 0 && (mask_.load(std::memory_order_acquire) & (1U << b)) != 0;
}

bool Faults::names_messages(std::string_view link) const {
    const std::lock_guard lock(mu_);
    return std::any_of(active_.begin(), active_.end(),
                       [&](const Active& a) { return a.rule.link == link && !a.rule.message.empty(); });
}

FaultVerdict Faults::check(std::string_view link, std::string_view dir, std::string_view message,
                           std::optional<std::uint32_t> ue) {
    FaultVerdict v;
    std::vector<std::pair<Active, bool>> hit;   // (the rule, spent): evented once the lock is gone
    {
        const std::lock_guard lock(mu_);
        for (auto it = active_.begin(); it != active_.end();) {
            Active& a = *it;
            const FaultRule& r = a.rule;
            const bool match = r.link == link && (r.dir == "any" || r.dir == dir) &&
                               (r.message.empty() || r.message == message) && (!r.ue || (ue && *ue == *r.ue));
            if (!match || (r.percent < 100 && rng_.uniform(1, 100) > r.percent)) {
                ++it;
                continue;
            }
            ++a.hits;
            switch (r.action) {
            case FaultRule::Action::drop:
                v.drop = true;
                if (r.count == 0) {
                    v.loss_percent = std::max(v.loss_percent, r.percent);
                }
                break;
            case FaultRule::Action::delay: v.delay_ms = std::max(v.delay_ms, r.delay_ms); break;
            case FaultRule::Action::duplicate: v.duplicate = true; break;
            }
            const bool spent = r.count != 0 && --a.left == 0;
            if (r.count != 0) {
                hit.emplace_back(a, spent);   // a link's loss (x*) is counted, not evented per hit
            }
            if (spent) {
                log("spent", a);
                it = active_.erase(it);
                continue;
            }
            ++it;
        }
        if (!hit.empty()) {
            update_mask();
        }
    }
    for (const auto& [a, spent] : hit) {
        events_.emit("fault.hit", subject_,
                     {{"id", std::to_string(a.id)}, {"link", std::string(link)}, {"dir", std::string(dir)},
                      {"message", std::string(message)}, {"action", action_name(a.rule.action)},
                      {"hits", std::to_string(a.hits)}, {"spent", spent ? "1" : "0"}});
    }
    return v;
}

FaultVerdict Faults::air(std::string_view dir, const air::Frame& f) {
    const char* name = air::frame_type_name(f.type);
    FaultVerdict v = check("uu", dir, name != nullptr ? name : "?", f.radio_id != 0 ? std::optional(f.radio_id) : std::nullopt);
    const bool am = std::any_of(f.sdus.begin(), f.sdus.end(), [](const air::Sdu& s) { return s.mode == air::RlcMode::am; });
    if (!v.drop || v.loss_percent == 0 || !am) {
        return v;
    }
    // TS 38.322 §5.3.2 on the ideal link: each retransmission comes one t-PollRetransmit
    // later and is lost again with the link's loss; past maxRetxThreshold the transmitter
    // gives up (§5.3.2.1: an indication to RRC, a radio link failure, TS 38.331 §5.3.10.3).
    const std::lock_guard lock(mu_);
    for (unsigned retx = 1; retx <= kMaxRetxThreshold; ++retx) {
        if (rng_.uniform(1, 100) > static_cast<std::int64_t>(v.loss_percent)) {
            v.drop = false;
            v.delay_ms += static_cast<Millis>(retx) * kPollRetransmitMs;
            return v;
        }
    }
    v.rlf = true;
    return v;
}

void Faults::log(const char* what, const Active& a) {
    if (path_.empty()) {
        return;
    }
    std::ofstream f(path_, std::ios::app);
    f << what << '\t' << a.id << '\t' << a.rule.row << '\t' << a.hits << '\t' << rule_text(a.rule) << '\n';
}

void Faults::update_mask() {
    std::uint32_t m = 0;
    for (const auto& a : active_) {
        m |= 1U << link_bit(a.rule.link);
    }
    mask_.store(m, std::memory_order_release);
    n_.store(active_.size(), std::memory_order_release);
}

// ---- the wrappers ------------------------------------------------------------------------------

FaultAssoc::FaultAssoc(IAssoc& inner, Faults& faults, TimerService& timers, std::string link, const char* tx_dir,
                       const char* rx_dir)
    : inner_(inner), faults_(faults), timers_(timers), link_(std::move(link)), tx_dir_(tx_dir), rx_dir_(rx_dir) {}

FaultVerdict FaultAssoc::verdict(const char* dir, ByteView msg) {
    if (!faults_.on(link_)) {
        return {};
    }
    const std::string name = faults_.names_messages(link_) ? asn1::message_name(link_, msg) : std::string();
    return faults_.check(link_, dir, name);
}

void FaultAssoc::set_handlers(OnMessage on_message, OnEvent on_event) {
    on_message_ = std::move(on_message);
    inner_.set_handlers(
        [this](ByteView msg, SctpMeta meta) {
            const FaultVerdict v = verdict(rx_dir_, msg);
            if (v.drop || !on_message_) {
                return;
            }
            if (v.delay_ms > 0) {
                timers_.start_timer(v.delay_ms, [this, alive = alive_, m = Bytes(msg.begin(), msg.end()), meta] {
                    if (*alive && on_message_) {
                        on_message_(m, meta);
                    }
                });
                return;
            }
            on_message_(msg, meta);
            if (v.duplicate) {
                on_message_(msg, meta);
            }
        },
        std::move(on_event));
}

Result<void> FaultAssoc::send(ByteView msg, SctpMeta meta) {
    const FaultVerdict v = verdict(tx_dir_, msg);
    if (v.drop) {
        return {};   // lost on the way: the sender cannot tell
    }
    if (v.delay_ms > 0) {
        timers_.start_timer(v.delay_ms, [this, alive = alive_, m = Bytes(msg.begin(), msg.end()), meta] {
            if (*alive) {
                (void)inner_.send(m, meta);
            }
        });
        return {};
    }
    auto r = inner_.send(msg, meta);
    if (r && v.duplicate) {
        (void)inner_.send(msg, meta);
    }
    return r;
}

FaultDatagram::FaultDatagram(std::unique_ptr<IDatagram> inner, Faults& faults, TimerService& timers, std::string link,
                             const char* tx_dir, const char* rx_dir)
    : inner_(std::move(inner)), faults_(faults), timers_(timers), link_(std::move(link)), tx_dir_(tx_dir),
      rx_dir_(rx_dir) {}

FaultVerdict FaultDatagram::verdict(const char* dir, ByteView payload) {
    if (!faults_.on(link_)) {
        return {};
    }
    const char* name = payload.size() >= 2 ? gtpu::message_name(payload[1]) : nullptr;
    return faults_.check(link_, dir, name != nullptr ? name : "?");
}

void FaultDatagram::set_handler(OnDatagram on_datagram) {
    on_datagram_ = std::move(on_datagram);
    inner_->set_handler([this](ByteView payload, const Endpoint& from) {
        const FaultVerdict v = verdict(rx_dir_, payload);
        if (v.drop || !on_datagram_) {
            return;
        }
        if (v.delay_ms > 0) {
            timers_.start_timer(v.delay_ms, [this, alive = alive_, p = Bytes(payload.begin(), payload.end()), from] {
                if (*alive && on_datagram_) {
                    on_datagram_(p, from);
                }
            });
            return;
        }
        on_datagram_(payload, from);
        if (v.duplicate) {
            on_datagram_(payload, from);
        }
    });
}

Result<void> FaultDatagram::send_to(ByteView payload, const Endpoint& to) {
    const FaultVerdict v = verdict(tx_dir_, payload);
    if (v.drop) {
        return {};
    }
    if (v.delay_ms > 0) {
        timers_.start_timer(v.delay_ms, [this, alive = alive_, p = Bytes(payload.begin(), payload.end()), to] {
            if (*alive) {
                (void)inner_->send_to(p, to);
            }
        });
        return {};
    }
    auto r = inner_->send_to(payload, to);
    if (r && v.duplicate) {
        (void)inner_->send_to(payload, to);
    }
    return r;
}

} // namespace ksim::node
