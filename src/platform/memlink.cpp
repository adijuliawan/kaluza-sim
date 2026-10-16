// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/memlink.hpp"

#include <atomic>
#include <string>
#include <utility>

namespace ksim {

namespace {

Millis hop_of(const MemLinkConfig& cfg, Rng& rng) {
    return cfg.delay_ms + (cfg.jitter_ms > 0 ? rng.uniform(0, cfg.jitter_ms) : 0);
}

class MemEnd;

} // namespace

// ---- associations ----------------------------------------------------------

struct MemAssocPair::Shared : std::enable_shared_from_this<MemAssocPair::Shared> {
    Shared(const MemLinkConfig& c, std::uint16_t s) : cfg(c), rng(c.seed, {Rng::label("memlink.assoc")}), streams(s) {}

    Millis hop() {
        const std::lock_guard lock(mu);
        return hop_of(cfg, rng);
    }

    std::mutex mu;   // the jitter stream and `generation`
    MemLinkConfig cfg;
    Rng rng;
    std::uint16_t streams;
    std::uint64_t generation = 0;
    std::unique_ptr<MemEnd> ends[2];
};

namespace {

class MemEnd final : public IAssoc {
public:
    MemEnd(MemAssocPair::Shared& s, int index, Executor& exec, Endpoint addr)
        : s_(s), index_(index), exec_(exec), addr_(addr) {}

    void set_handlers(OnMessage on_message, OnEvent on_event) override {
        on_message_ = std::move(on_message);
        on_event_ = std::move(on_event);
    }

    Result<void> send(ByteView msg, SctpMeta meta) override {
        if (!up_) {
            return make_error(Errc::closed, 0, "memlink: the association is not up");
        }
        if (meta.stream >= s_.streams) {
            return make_error(Errc::out_of_range, meta.stream, "memlink: stream beyond the negotiated count");
        }
        const std::uint64_t gen = gen_;
        peer_end().after_hops(1, [gen, bytes = Bytes(msg.begin(), msg.end()), meta](MemEnd& e) {
            if (e.up_ && e.gen_ == gen && e.on_message_) {
                e.on_message_(bytes, meta);
            }
        });
        return {};
    }

    bool up() const noexcept override { return up_; }
    std::uint16_t out_streams() const noexcept override { return up_ ? s_.streams : 0; }
    std::uint16_t in_streams() const noexcept override { return up_ ? s_.streams : 0; }

    void shutdown() override {
        if (!up_) {
            return;
        }
        up_ = false;
        const std::uint64_t gen = gen_;
        peer_end().after_hops(1, [gen](MemEnd& e) { e.end_by_peer(gen, LinkEvent::shutdown); });
        // The initiator learns of the completed shutdown after the round trip.
        after_hops(2, [gen](MemEnd& e) {
            if (e.gen_ == gen && !e.up_ && e.ended_gen_ != gen && e.on_event_) {
                e.ended_gen_ = gen;
                e.on_event_(LinkEvent::shutdown);
            }
        });
    }

    void abort() override {
        if (!up_) {
            return;
        }
        up_ = false;
        ended_gen_ = gen_;
        const std::uint64_t gen = gen_;
        peer_end().after_hops(1, [gen](MemEnd& e) { e.end_by_peer(gen, LinkEvent::lost); });
    }

    Endpoint peer() const override { return s_.ends[1 - index_]->addr_; }

    /// Brings this end up (or restarts it) one hop from now, as association `gen`.
    void come_up(std::uint64_t gen) {
        after_hops(1, [gen](MemEnd& e) {
            const bool restart = e.up_;
            e.up_ = true;
            e.gen_ = gen;
            e.ended_gen_ = 0;
            if (e.on_event_) {
                e.on_event_(restart ? LinkEvent::restart : LinkEvent::up);
            }
        });
    }

private:
    MemEnd& peer_end() { return *s_.ends[1 - index_]; }

    /// Runs `fn` on this end's executor `hops` hops from now, after whatever
    /// this end has scheduled already (so a direction never reorders). Safe
    /// from any thread; dropped if the pair is gone by then.
    void after_hops(int hops, std::function<void(MemEnd&)> fn) {
        std::weak_ptr<MemAssocPair::Shared> w = s_.weak_from_this();
        const int me = index_;
        Millis hop = 0;
        for (int i = 0; i < hops; ++i) {
            hop += s_.hop();
        }
        exec_.post([w, me, hop, fn = std::move(fn)]() mutable {
            const auto s = w.lock();
            if (!s) {
                return;
            }
            MemEnd& e = *s->ends[me];
            const Millis now = e.exec_.now();
            const Millis due = now + hop > e.last_due_ ? now + hop : e.last_due_;
            e.last_due_ = due;
            if (due <= now && e.in_flight_ == 0) {
                fn(e);   // P2 Q12: due now and nothing still waiting before it: no timer
                return;
            }
            // An absolute deadline: a delay would be added to a later clock
            // reading, and a tick in between could put this message behind
            // the next one.
            ++e.in_flight_;
            e.exec_.start_timer_at(due, [w, me, fn = std::move(fn)]() mutable {
                if (const auto t = w.lock()) {
                    --t->ends[me]->in_flight_;
                    fn(*t->ends[me]);
                }
            });
        });
    }

    void end_by_peer(std::uint64_t gen, LinkEvent why) {
        if (up_ && gen_ == gen) {
            up_ = false;
            ended_gen_ = gen;
            if (on_event_) {
                on_event_(why);
            }
        }
    }

    MemAssocPair::Shared& s_;
    const int index_;
    Executor& exec_;
    const Endpoint addr_;
    // The rest lives on exec_'s thread.
    bool up_ = false;
    std::uint64_t gen_ = 0;
    std::uint64_t ended_gen_ = 0;
    Millis last_due_ = 0;
    int in_flight_ = 0;   // messages waiting in a timer on this end (P2 Q12)
    OnMessage on_message_;
    OnEvent on_event_;
};

} // namespace

MemAssocPair::MemAssocPair(Executor& a_exec, Endpoint a_addr, Executor& b_exec, Endpoint b_addr,
                           std::uint16_t streams, MemLinkConfig config)
    : s_(std::make_shared<Shared>(config, streams > 0 ? streams : 1)) {
    s_->ends[0] = std::make_unique<MemEnd>(*s_, 0, a_exec, a_addr);
    s_->ends[1] = std::make_unique<MemEnd>(*s_, 1, b_exec, b_addr);
}

MemAssocPair::~MemAssocPair() = default;

IAssoc& MemAssocPair::a() noexcept { return *s_->ends[0]; }
IAssoc& MemAssocPair::b() noexcept { return *s_->ends[1]; }

void MemAssocPair::connect() {
    std::uint64_t gen = 0;
    {
        const std::lock_guard lock(s_->mu);
        gen = ++s_->generation;
    }
    s_->ends[0]->come_up(gen);
    s_->ends[1]->come_up(gen);
}

// ---- datagrams -------------------------------------------------------------

namespace {

struct SockState {
    SockState(Executor& e, Endpoint l) : exec(e), local(l) {}
    Executor& exec;
    const Endpoint local;
    // On exec's thread:
    Millis last_due = 0;
    int in_flight = 0;    // datagrams waiting in a timer (P2 Q12)
    IDatagram::OnDatagram handler;
};

} // namespace

namespace {

/// A bound address as a key: family, address and port as octets. P2 Q12: the lookup is
/// per datagram, and Endpoint::to_string formatted a string for each.
struct EndpointKey {
    std::array<std::uint8_t, 19> b{};
    friend bool operator==(const EndpointKey&, const EndpointKey&) = default;
};
struct EndpointKeyHash {
    std::size_t operator()(const EndpointKey& k) const noexcept {
        std::uint64_t h = 1469598103934665603ULL;   // FNV-1a
        for (std::uint8_t x : k.b) {
            h = (h ^ x) * 1099511628211ULL;
        }
        return static_cast<std::size_t>(h);
    }
};
EndpointKey key_of(const Endpoint& e) {
    EndpointKey k;
    k.b[0] = static_cast<std::uint8_t>(e.family);
    std::copy(e.addr.begin(), e.addr.end(), k.b.begin() + 1);
    k.b[17] = static_cast<std::uint8_t>(e.port >> 8);
    k.b[18] = static_cast<std::uint8_t>(e.port);
    return k;
}

} // namespace

struct MemNet::Shared {
    explicit Shared(const MemLinkConfig& c) : cfg(c), rng(c.seed, {Rng::label("memlink.net")}) {}

    std::mutex mu;
    MemLinkConfig cfg;
    Rng rng;
    std::unordered_map<EndpointKey, std::weak_ptr<SockState>, EndpointKeyHash> bound;
    std::atomic<std::uint64_t> dropped{0};
};

namespace {

class MemSock final : public IDatagram {
public:
    MemSock(std::shared_ptr<MemNet::Shared> net, std::shared_ptr<SockState> st)
        : net_(std::move(net)), st_(std::move(st)) {}
    ~MemSock() override {
        const std::lock_guard lock(net_->mu);
        const auto it = net_->bound.find(key_of(st_->local));
        if (it != net_->bound.end() && it->second.lock() == st_) {
            net_->bound.erase(it);
        }
    }

    void set_handler(OnDatagram on_datagram) override { st_->handler = std::move(on_datagram); }

    Result<void> send_to(ByteView payload, const Endpoint& to) override {
        if (to.family != st_->local.family) {
            return make_error(Errc::invalid_argument, 0, "memlink: address family mismatch");
        }
        std::shared_ptr<SockState> dst;
        Millis hop = 0;
        {
            const std::lock_guard lock(net_->mu);
            const auto it = net_->bound.find(key_of(to));
            if (it != net_->bound.end()) {
                dst = it->second.lock();
            }
            hop = hop_of(net_->cfg, net_->rng);
        }
        if (!dst) {
            net_->dropped.fetch_add(1, std::memory_order_relaxed);
            ++dropped_;
            return {};
        }
        std::weak_ptr<SockState> w = dst;
        const Endpoint from = st_->local;
        // dst->last_due is read and written only on dst's executor, in the posted task.
        auto& exec = dst->exec;
        exec.post([w, from, hop, bytes = Bytes(payload.begin(), payload.end())]() mutable {
            auto s = w.lock();
            if (!s) {
                return;
            }
            const Millis now = s->exec.now();
            Millis due = now + hop;
            if (due < s->last_due) {
                due = s->last_due;
            }
            s->last_due = due;
            if (due <= now && s->in_flight == 0) {
                // P2 Q12: due now and nothing still waiting in a timer before it: delivered
                // in order, with no timer.
                if (s->handler) {
                    s->handler(bytes, from);
                }
                return;
            }
            ++s->in_flight;
            s->exec.start_timer_at(due, [w, from, bytes = std::move(bytes)] {
                if (auto t = w.lock()) {
                    --t->in_flight;
                    if (t->handler) {
                        t->handler(bytes, from);
                    }
                }
            });
        });
        return {};
    }

    Endpoint local() const override { return st_->local; }
    std::uint64_t dropped() const noexcept override { return dropped_; }

private:
    std::shared_ptr<MemNet::Shared> net_;
    std::shared_ptr<SockState> st_;
    std::uint64_t dropped_ = 0;
};

} // namespace

MemNet::MemNet(MemLinkConfig config) : s_(std::make_shared<Shared>(config)) {}
MemNet::~MemNet() = default;

Result<std::unique_ptr<IDatagram>> MemNet::bind(Executor& exec, const Endpoint& local) {
    auto st = std::make_shared<SockState>(exec, local);
    {
        const std::lock_guard lock(s_->mu);
        auto& slot = s_->bound[key_of(local)];
        if (slot.lock()) {
            return make_error(Errc::invalid_argument, 0, "memlink: the address is bound already");
        }
        slot = st;
    }
    return std::unique_ptr<IDatagram>(std::make_unique<MemSock>(s_, std::move(st)));
}

std::uint64_t MemNet::dropped() const noexcept { return s_->dropped.load(std::memory_order_relaxed); }

} // namespace ksim
