// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/ue/device.hpp"

#include "platform/mutation.hpp"
#include "proc/ue/qos_classifier.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <cctype>

#include "uicc/image/image.hpp"

namespace ksim::node {

namespace {

constexpr Millis kPollMs = 10;
constexpr int kPollTries = 1000;   // 10 s for the card read

} // namespace

std::string guti_text(const nas::ie::MobileIdentity& g) {
    return fmt::format("{}{}-{:02x}-{:03x}-{:02x}-{:08x}", g.plmn.mcc, g.plmn.mnc, g.amf_region, g.amf_set, g.amf_pointer,
                       g.tmsi);
}

UeDevice::UeDevice(Executor& ex, IEventSink& events, UeDeviceConfig cfg, std::unique_ptr<uicc::os::Card> card,
                   std::function<void(air::Frame)> to_air, const UeTaps& taps, IUeNet* net)
    : UeDevice(ex, events, std::move(cfg), std::move(card), nullptr, "inproc", std::move(to_air), taps, net) {}

UeDevice::UeDevice(Executor& ex, IEventSink& events, UeDeviceConfig cfg, std::unique_ptr<uicc::IApduTransport> reader,
                   std::string reader_name, std::function<void(air::Frame)> to_air, const UeTaps& taps, IUeNet* net)
    : UeDevice(ex, events, std::move(cfg), nullptr, std::move(reader), std::move(reader_name), std::move(to_air), taps,
               net) {}

UeDevice::UeDevice(Executor& ex, IEventSink& events, UeDeviceConfig cfg, std::unique_ptr<uicc::os::Card> card,
                   std::unique_ptr<uicc::IApduTransport> reader, std::string reader_name,
                   std::function<void(air::Frame)> to_air, const UeTaps& taps, IUeNet* net)
    : ex_(ex), cfg_(std::move(cfg)), card_(std::move(card)),
      reader_(reader ? std::move(reader) : std::make_unique<uicc::InProcTransport>(ex, card_.get())),
      reader_name_(std::move(reader_name)), slot_(ex, reader_.get()), tracer_(slot_, {}), terminal_(tracer_),
      sim_tap_(taps.sim), events_(events), net_(cfg_.netns.empty() ? nullptr : net) {
    const std::string subject = "ue:imsi-" + cfg_.supi;
    proc::ue::RrcConfig rc;
    rc.id = subject;
    rc.plmn = {cfg_.plmn.mcc, cfg_.plmn.mnc};
    rc.mac.radio_id = cfg_.radio_id;
    rc.allow_null_integrity = cfg_.allow_null_integrity;
    rc.view = cfg_.view;
    if (cfg_.persona) {
        rc.nr_capability = cfg_.persona->nr_capability();   // N15: the phone's UE-NR-Capability, as it came
    }
    if (taps.rrc) {
        rc.tap = [tap = taps.rrc, supi = cfg_.supi](std::string_view channel, ByteView pdu) { tap(channel, pdu, supi); };
    }
    proc::ue::RrcUpper up;
    up.nas = [this](Bytes b) { mm_->on_nas(b); };
    up.connection_failure = [this](std::uint16_t up_psis) { mm_->on_connection_failure(up_psis); };
    up.released = [this] { mm_->on_released(); };
    up.establishment_failed = [this] { mm_->on_establishment_failed(); };
    up.camped = [this](std::uint32_t tac) { mm_->on_camped(tac); };
    up.kgnb = [this] { return mm_->kgnb(); };
    up.s_tmsi = [this] { return mm_->s_tmsi(); };
    up.paged = [this] { mm_->on_paged(); };
    up.bearers_up = [this] {
        mm_->on_user_plane();
        flush_held();
    };
    up.dl_data = [this](std::uint8_t psi, std::optional<sdap::DlHeader> h, Bytes sdu) { on_dl(psi, h, std::move(sdu)); };
    rrc_ = std::make_unique<proc::ue::UeRrc>(ex_, Rng(cfg_.seed, {cfg_.index, 1}), events, rc, up, std::move(to_air));
    proc::ue::MmConfig mc;
    mc.id = subject;
    mc.plmn = cfg_.plmn;
    mc.seed = cfg_.seed;
    if (cfg_.mm_timers) {
        mc.timers = *cfg_.mm_timers;
    }
    mc.requested_nssai = cfg_.nssai;
    mc.imeisv = cfg_.imeisv;
    if (cfg_.persona) {
        mc.security = cfg_.persona->security();
        mc.mm_capability = cfg_.persona->mm_capability_sent();
    }
    if (taps.nas) {
        mc.tap = [tap = taps.nas, supi = cfg_.supi](bool uplink, ByteView plain) { tap(uplink, plain, supi); };
    }
    mc.sm = [this](const proc::ue::SmDownlink& d) { sm_->on_downlink(d); };
    mc.sm_hooks.active = [this] { return sm_->active_bitmap(); };
    mc.sm_hooks.sync = [this](std::uint16_t network) { sm_->sync(network); };
    mc.sm_hooks.release_all = [this] { sm_->release_all_local("network"); };
    mc.sms = [this](ByteView cp) { sms_->on_downlink(cp); };
    mm_ = std::make_unique<proc::ue::Mm>(ex_, terminal_, *rrc_, events, mc);
    proc::ue::SmsConfig smc;
    smc.id = subject;
    proc::ue::SmsPorts sp;
    sp.send = [this](Bytes cp) { return mm_->send_sms(std::move(cp)); };
    sp.allowed = [this] { return mm_->sms_allowed(); };
    sp.service_centre = [this] { return mm_->sms_service_centre(); };
    sp.store = [this](std::uint8_t record, Bytes data) { mm_->store_sms_record(record, std::move(data)); };
    sp.store_smss = [this](Bytes data) { mm_->store_smss(std::move(data)); };
    sp.smss = [this] { return mm_->smss(); };
    sms_ = std::make_unique<proc::ue::Sms>(ex_, events, smc, std::move(sp));
    proc::ue::SmConfig sc;
    sc.id = subject;
    if (cfg_.persona && cfg_.persona->integrity_max_data_rate && cfg_.persona->integrity_max_data_rate->size() == 2) {
        sc.ip_max_rate_ul = (*cfg_.persona->integrity_max_data_rate)[0];   // P2 Q9: as the phone sent it
        sc.ip_max_rate_dl = (*cfg_.persona->integrity_max_data_rate)[1];
    }
    if (cfg_.persona && cfg_.persona->sm_capability) {
        sc.sm_capability = *cfg_.persona->sm_capability;   // P2 Q11: the 5GSM capability as the phone sent it
    }
    proc::ue::SmUpper su;
    su.up = [this](const proc::ue::SessionInfo& s) { session_up(s); };
    su.down = [this](std::uint8_t psi) {
        if (ping_ && ping_->psi == psi) {
            ping_done("session released");
        }
        // P2 Q10: the classifier's counts and once-only events are the session's.
        for (auto it = ul_per_qfi_.begin(); it != ul_per_qfi_.end();) {
            it = it->first.first == psi ? ul_per_qfi_.erase(it) : std::next(it);
        }
        for (auto it = classified_.begin(); it != classified_.end();) {
            it = it->first == psi ? classified_.erase(it) : std::next(it);
        }
        unmatched_.erase(psi);
        ul_unmatched_.erase(psi);
        for (auto it = dl_per_qfi_.begin(); it != dl_per_qfi_.end();) {   // P2 Q11
            it = it->first.first == psi ? dl_per_qfi_.erase(it) : std::next(it);
        }
        for (auto it = unknown_told_.begin(); it != unknown_told_.end();) {
            it = it->first == psi ? unknown_told_.erase(it) : std::next(it);
        }
        for (auto it = derived_classified_.begin(); it != derived_classified_.end();) {
            it = it->first == psi ? derived_classified_.erase(it) : std::next(it);
        }
        dl_unknown_qfi_.erase(psi);
        session_down(psi);
    };
    sm_ = std::make_unique<proc::ue::Sm>(ex_, events, sc, [this](const proc::ue::SmUplink& u) { return mm_->send_sm(u); }, su);
}

UeDevice::~UeDevice() {
    *alive_ = false;
    if (ping_ && ping_->timer) {
        ex_.stop_timer(*ping_->timer);
    }
    for (auto& [psi, t] : tuns_) {
        t.port.reset();
        if (net_ != nullptr) {
            net_->close_tun(cfg_.netns, t.spec);
        }
    }
    tuns_.clear();
    if (net_ != nullptr && netns_up_) {
        net_->teardown(cfg_.netns);
    }
}

// ---- the TUN data plane (P1 N11) ---------------------------------------------------------------

Result<void> UeDevice::ensure_netns() {
    if (net_ == nullptr) {
        return make_error(Errc::unsupported, 0, "the UE runs in inject mode (no ksim-netd in this run)");
    }
    if (netns_up_) {
        return {};
    }
    auto r = net_->setup(cfg_.netns);
    if (!r) {
        events_.emit("ue.dataplane.error", subject(), {{"what", std::string("namespace: ") + r.error().what}});
        return r;
    }
    netns_up_ = true;
    events_.emit("ue.netns.up", subject(), {{"netns", cfg_.netns}});
    return {};
}

void UeDevice::session_up(const proc::ue::SessionInfo& s) {
    if (net_ == nullptr || !s.ipv4 || tuns_.count(s.psi) != 0) {
        return;
    }
    if (!ensure_netns()) {
        return;
    }
    Tun t;
    t.spec.ifname = "pdu" + std::to_string(s.psi);
    t.spec.addr = *s.ipv4;
    t.spec.mtu = s.mtu.value_or(1500);
    t.spec.table = static_cast<std::uint8_t>(100 + s.psi);
    t.spec.main_default = tuns_.empty();   // the first session takes the namespace's default route
    auto port = net_->open_tun(cfg_.netns, t.spec);
    if (!port) {
        events_.emit("ue.dataplane.error", subject(), {{"psi", std::to_string(s.psi)}, {"what", port.error().what}});
        return;
    }
    t.port = std::move(*port);
    const std::uint8_t psi = s.psi;
    t.port->set_handler([this, alive = alive_, psi](ByteView packet) {
        if (*alive) {
            on_ul_ip(psi, packet);
        }
    });
    if (s.dns) {
        // One resolv.conf per namespace: the first session's server, as a phone uses its default APN's.
        if (tuns_.empty()) {
            (void)net_->resolv(cfg_.netns, *s.dns);
        }
        t.dns = s.dns;
    }
    const std::string ip = fmt::format("{}.{}.{}.{}", t.spec.addr[0], t.spec.addr[1], t.spec.addr[2], t.spec.addr[3]);
    events_.emit("ue.dataplane.up", subject(),
                 {{"psi", std::to_string(psi)},
                  {"ifname", t.spec.ifname},
                  {"ip", ip},
                  {"mtu", std::to_string(t.spec.mtu)},
                  {"table", std::to_string(t.spec.table)},
                  {"netns", cfg_.netns}});
    tuns_.emplace(psi, std::move(t));
}

void UeDevice::session_down(std::uint8_t psi) {
    auto it = tuns_.find(psi);
    if (it == tuns_.end()) {
        return;
    }
    it->second.port.reset();   // the device goes with the descriptor
    net_->close_tun(cfg_.netns, it->second.spec);
    events_.emit("ue.dataplane.down", subject(), {{"psi", std::to_string(psi)}, {"ifname", it->second.spec.ifname}});
    tuns_.erase(it);
}

void UeDevice::on_ul_ip(std::uint8_t psi, ByteView packet) {
    auto t = tuns_.find(psi);
    const proc::ue::SessionInfo* s = sm_->session(psi);
    if (t == tuns_.end() || s == nullptr) {
        return;
    }
    // Only IPv4 from the session's own address goes: anything else the kernel
    // sends on the device (IPv6, another source) is noise, counted and dropped.
    if (packet.size() < 20 || (packet[0] >> 4) != 4 ||
        !std::equal(t->second.spec.addr.begin(), t->second.spec.addr.end(), packet.begin() + 12)) {
        if (noise_++ == 0) {
            events_.emit("ue.dataplane.noise", subject(),
                         {{"psi", std::to_string(psi)}, {"version", std::to_string(packet.empty() ? 0 : packet[0] >> 4)}});
        }
        return;
    }
    const auto qfi = ul_qfi(*s, packet);
    if (!qfi) {
        return;   // no QoS rule matches it (TS 23.501 5.7.1.5)
    }
    if (rrc_->send_data(psi, *qfi, Bytes(packet.begin(), packet.end()))) {
        ++ul_packets_;
        ++t->second.ul;
    } else {
        (void)send_ul(psi, Bytes(packet.begin(), packet.end()));   // held for a service request
    }
}

std::vector<UeIface> UeDevice::ifaces() const {
    std::vector<UeIface> out;
    out.reserve(tuns_.size());
    for (const auto& [psi, t] : tuns_) {
        out.push_back(UeIface{t.spec.ifname, psi, t.spec.addr, t.spec.mtu, t.dns, t.ul, t.dl});
    }
    return out;
}

Result<std::uint32_t> UeDevice::exec(const std::vector<std::string>& argv, std::vector<int> fds) {
    if (auto r = ensure_netns(); !r) {
        return r.error();
    }
    return net_->exec(cfg_.netns, argv, std::move(fds));
}

void UeDevice::on_frame(const air::Frame& f) { rrc_->on_frame(f); }

Result<void> UeDevice::power_on() {
    if (powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is already on");
    }
    if (net_ != nullptr) {
        if (auto r = ensure_netns(); !r) {
            return r;
        }
    }
    powered_ = true;
    rrc_->power(true);
    mm_->power_on();
    poll_registration(kPollTries);
    return {};
}

void UeDevice::poll_registration(int left, proc::ue::MmState waiting) {
    // The card read is asynchronous; registration starts once 5GMM leaves
    // `waiting` with a valid USIM. The RRC holds it until the UE camps.
    if (mm_->state() != waiting) {
        if (mm_->usim_valid()) {
            mm_->register_initial();
        }
        return;
    }
    if (left == 0) {
        return;
    }
    ex_.start_timer(kPollMs, [this, alive = alive_, left, waiting] {
        if (*alive) {
            poll_registration(left - 1, waiting);
        }
    });
}

Result<void> UeDevice::register_initial() {
    if (!powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is off");
    }
    if (!mm_->usim_valid() || !proc::ue::is_deregistered(mm_->state())) {
        return make_error(Errc::invalid_argument, 0, "the UE is not deregistered with a valid USIM");
    }
    mm_->register_initial();
    return {};
}

Result<void> UeDevice::deregister(bool switch_off) {
    if (mm_->state() != proc::ue::MmState::registered_initiated && !proc::ue::is_registered(mm_->state())) {
        return make_error(Errc::invalid_argument, 0, "the UE is not registered");
    }
    mm_->deregister(switch_off);
    // TS 24.501 §5.5.2.2.1: the UE's PDU sessions go with its registration.
    sm_->release_all_local(switch_off ? "switch-off" : "deregistration");
    held_.clear();
    sms_->reset();   // SMS transactions end with the registration (TS 24.011 5.3.2.1)
    if (switch_off) {
        powered_ = false;   // 5GMM-NULL at once: the UE is off (§5.5.2.2.1)
        rrc_->power_off_after_nas();   // from CM-IDLE the request still has to reach the AMF (F-46)
    }
    return {};
}

Result<void> UeDevice::power_off_abrupt() {
    if (!powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is off");
    }
    // The battery pulled: no signalling at all, nothing written to the card.
    rrc_->power(false);
    mm_->power_off_abrupt();
    sm_->release_all_local("switch-off");
    held_.clear();
    sms_->reset();
    powered_ = false;
    events_.emit("ue.power", subject(), {{"state", "off"}, {"mode", "abrupt"}});
    return {};
}

Result<void> UeDevice::sim(bool present) {
    if (present == sim_present_) {
        return make_error(Errc::invalid_argument, 0, present ? "the UICC is in already" : "the UICC is out already");
    }
    sim_present_ = present;
    events_.emit("ue.sim", subject(), {{"present", present ? "1" : "0"}});
    if (!present) {
        slot_.insert(nullptr);
        if (powered_) {
            if (proc::ue::is_registered(mm_->state()) || mm_->state() == proc::ue::MmState::registered_initiated) {
                sm_->release_all_local("deregistration");   // the de-registration takes the sessions
                held_.clear();
            }
            sms_->reset();
            mm_->usim_removed();
        }
        return {};
    }
    slot_.insert(reader_.get());
    if (powered_) {
        const bool was_no_supi = mm_->state() == proc::ue::MmState::deregistered_no_supi;
        mm_->usim_inserted();
        if (was_no_supi) {
            poll_registration(kPollTries, proc::ue::MmState::deregistered_no_supi);
        }
    }
    return {};
}

Result<void> UeDevice::sim_trace(bool on) {
    if (on && !sim_tap_) {
        return make_error(Errc::unsupported, 0, "this run has no SIM capture");
    }
    if (on == tracer_.tracing()) {
        return make_error(Errc::invalid_argument, 0, on ? "the trace is on already" : "the trace is off already");
    }
    if (on) {
        tracer_.set_sink([tap = sim_tap_, supi = cfg_.supi](std::uint8_t sub, Bytes payload) { tap(sub, payload, supi); });
    } else {
        tracer_.set_sink({});
    }
    events_.emit("ue.sim.trace", subject(), {{"on", on ? "1" : "0"}});
    return {};
}

namespace {

std::string fid4(std::uint16_t f) { return fmt::format("{:04X}", f); }

std::string ef_path(const uicc::os::File& f) {
    std::vector<const uicc::os::File*> up;
    for (const uicc::os::File* q = &f; q != nullptr; q = q->parent) {
        up.push_back(q);
    }
    std::string p;
    for (auto it = up.rbegin(); it != up.rend(); ++it) {
        p += (p.empty() ? "" : "/") + fid4((*it)->fid);
    }
    return p;
}

const uicc::os::File* find_ef(const uicc::os::File& df, const std::function<bool(const uicc::os::File&)>& match) {
    for (const auto& c : df.children) {
        if (!uicc::os::is_df(c->kind) && match(*c)) {
            return c.get();
        }
    }
    for (const auto& c : df.children) {
        if (uicc::os::is_df(c->kind)) {
            if (const auto* f = find_ef(*c, match)) {
                return f;
            }
        }
    }
    return nullptr;
}

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace

SimInfo UeDevice::sim_info() const {
    SimInfo s;
    s.present = sim_present_;
    s.reader = reader_name_;
    if (!card_) {
        s.imsi = cfg_.supi;   // a card outside the process: what the terminal read from it at power-up
        return s;
    }
    s.atr = to_hex(card_->atr());
    const uicc::os::File& mf = card_->mf();
    auto ef = [&](std::uint16_t fid) { return find_ef(mf, [fid](const uicc::os::File& f) { return f.fid == fid; }); };
    if (const auto* f = ef(0x2FE2)) {
        s.iccid = uicc::image::decode_iccid(f->data);
    }
    if (const auto* f = ef(0x6F07)) {
        s.imsi = uicc::image::decode_imsi(f->data);
    }
    if (const auto* f = ef(0x6F40); f != nullptr && !f->records.empty()) {
        s.msisdn = uicc::image::decode_msisdn_record(f->records[0]);
    }
    if (const auto* f = ef(0x6F38)) {
        s.ust = uicc::image::services(f->data);
    }
    if (const auto* f = ef(0x4F07); f != nullptr && f->data.size() >= 2 && f->data[0] == 0xA0) {
        // TS 31.102 4.4.11.8: 'A0' L, then (identifier, key index) pairs.
        const std::size_t n = std::min<std::size_t>(f->data[1], f->data.size() - 2);
        for (std::size_t i = 0; i + 1 < n; i += 2) {
            s.suci_schemes += (s.suci_schemes.empty() ? "" : ",") + std::to_string(f->data[2 + i]);
        }
    }
    if (const auto* f = ef(0x4F0A); f != nullptr && f->data.size() >= 2) {
        for (std::size_t i = 0; i < 2; ++i) {   // 4.4.11.11: four BCD digits, 'F' when fewer
            for (std::uint8_t n : {static_cast<std::uint8_t>(f->data[i] & 0x0F), static_cast<std::uint8_t>(f->data[i] >> 4)}) {
                if (n <= 9) {
                    s.routing_indicator.push_back(static_cast<char>('0' + n));
                }
            }
        }
    }
    return s;
}

Result<UeDevice::SimEf> UeDevice::sim_read(std::string_view want) const {
    if (!card_) {
        return make_error(Errc::unsupported, 0, "the card is outside the process: read it with pySim where it sits");
    }
    const std::string w = lower(want);
    const uicc::os::File* f = nullptr;
    const uicc::os::File& mf = card_->mf();
    if (w.find('/') != std::string::npos) {
        f = find_ef(mf, [&](const uicc::os::File& x) {
            const std::string p = lower(ef_path(x));
            return p == w || (p.size() > w.size() && p.compare(p.size() - w.size(), w.size(), w) == 0 &&
                              p[p.size() - w.size() - 1] == '/');
        });
    } else {
        f = find_ef(mf, [&](const uicc::os::File& x) {
            const std::string n = lower(x.name);
            return n == w || n == "ef." + w || lower(fid4(x.fid)) == w;
        });
    }
    if (f == nullptr) {
        return make_error(Errc::invalid_argument, 0, "no such EF on the card");
    }
    // Key material and the NAS security state stay in the card (sim-uicc.md §6),
    // and what the card's access rules keep from a reader stays too.
    if (f->secret || uicc::os::key_fid(f->fid)) {
        return make_error(Errc::invalid_argument, 0, "that EF holds keys: sim read refuses it");
    }
    if (!card_->allowed(*f, 0x01)) {
        return make_error(Errc::invalid_argument, 0, "the card's access rule does not let that EF be read");
    }
    SimEf out;
    out.name = f->name;
    out.path = ef_path(*f);
    out.records = uicc::os::is_record(f->kind);
    if (out.records) {
        out.contents = f->records;
    } else {
        out.contents.push_back(f->data);
    }
    return out;
}

Result<void> UeDevice::airplane(bool on) {
    if (on == airplane_) {
        return make_error(Errc::invalid_argument, 0, on ? "airplane mode is on already" : "airplane mode is off already");
    }
    if (on) {
        if (!powered_) {
            return make_error(Errc::invalid_argument, 0, "the UE is off");
        }
        airplane_ = true;
        events_.emit("ue.airplane", subject(), {{"on", "1"}});
        if (proc::ue::is_registered(mm_->state()) || mm_->state() == proc::ue::MmState::registered_initiated) {
            return deregister(true);   // the switch-off de-registration, the radio off once it is out
        }
        rrc_->power(false);
        mm_->power_off_abrupt();   // nothing registered: nothing to signal or to write
        powered_ = false;
        return {};
    }
    airplane_ = false;
    events_.emit("ue.airplane", subject(), {{"on", "0"}});
    return power_on();
}

Result<std::size_t> UeDevice::sms_send(const proc::ue::SmsSubmit& m) {
    if (!powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is off");
    }
    if (!proc::ue::is_registered(mm_->state())) {
        return make_error(Errc::invalid_argument, 0, "the UE is not registered");
    }
    return sms_->send(m);
}

Result<void> UeDevice::register_update() {
    if (!powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is off");
    }
    return mm_->register_update();
}

Result<void> UeDevice::service_request() {
    if (!powered_) {
        return make_error(Errc::invalid_argument, 0, "the UE is off");
    }
    return mm_->service_request(nas::ie::ServiceType::signalling, 0);
}

std::optional<std::uint8_t> UeDevice::ul_qfi(const proc::ue::SessionInfo& s, ByteView packet) {
    // P2 Q10: the QoS rules' packet filters pick the QFI (TS 24.501 6.2.5.1.1.2, TS 23.501
    // 5.7.1.5); without signalled rules, the default QoS rule's.
    if (s.rules.empty()) {
        return s.default_qfi;
    }
    const auto* r = proc::ue::classify(s.rules, packet, proc::ue::QosDirection::uplink);
    // P2 Q11 (TS 24.501 6.2.5.1.3): the derived rules too, at precedence 80, in their place.
    bool derived = false;
    if (!s.derived.empty() && (r == nullptr || r->precedence.value_or(256) > 80)) {
        if (const auto* d = proc::ue::classify(s.derived, packet, proc::ue::QosDirection::uplink); d != nullptr) {
            r = d;
            derived = true;
        }
    }
    if (r == nullptr || !r->qfi) {
        if (unmatched_.insert(s.psi).second) {
            events_.emit("ue.qos.unmatched", subject(), {{"psi", std::to_string(s.psi)}});
        }
        ++ul_unmatched_[s.psi];
        return std::nullopt;
    }
    if (derived ? derived_classified_.insert({s.psi, *r->qfi}).second : classified_.insert({s.psi, r->id}).second) {
        events_.emit("ue.qos.classified", subject(),
                     {{"psi", std::to_string(s.psi)}, {"rule", derived ? std::string("derived") : std::to_string(r->id)},
                      {"qfi", std::to_string(*r->qfi)}, {"precedence", r->precedence ? std::to_string(*r->precedence) : "-"},
                      {"default", r->default_rule ? "1" : "0"}});
    }
    ++ul_per_qfi_[{s.psi, *r->qfi}];
    return r->qfi;
}

void UeDevice::udp_echo(std::uint8_t psi, const ip::Ipv4& p) {
    // RFC 862 over UDP: a datagram to the UE's port 7 comes back to where it came from, with
    // the ports swapped. Only in inject mode: with a TUN the namespace's stack has the packet.
    const proc::ue::SessionInfo* s = sm_->session(psi);
    if (s == nullptr || !s->ipv4 || p.dst != *s->ipv4 || p.payload.size() < 8 || p.payload[2] != 0 || p.payload[3] != 7) {
        return;
    }
    ip::Ipv4 out;
    out.id = p.id;
    out.protocol = ip::kUdp;
    out.src = p.dst;
    out.dst = p.src;
    out.payload = p.payload;
    std::swap(out.payload[0], out.payload[2]);
    std::swap(out.payload[1], out.payload[3]);
    out.payload[6] = 0;   // no UDP checksum (RFC 768, IPv4)
    out.payload[7] = 0;
    const Bytes reply = ip::encode(out);
    if (const auto qfi = ul_qfi(*s, reply); qfi && rrc_->send_data(psi, *qfi, reply)) {
        ++ul_packets_;
    }
    events_.emit("ue.udp.echoed", subject(),
                 {{"psi", std::to_string(psi)}, {"from", fmt::format("{}.{}.{}.{}", p.src[0], p.src[1], p.src[2], p.src[3])},
                  {"port", std::to_string(p.payload[0] << 8 | p.payload[1])}});
}

bool UeDevice::send_ul(std::uint8_t psi, Bytes packet) {
    const proc::ue::SessionInfo* s = sm_->session(psi);
    if (s == nullptr) {
        return false;
    }
    const auto qfi = ul_qfi(*s, packet);
    if (!qfi) {
        return true;   // taken, not sent: no QoS rule matches it (TS 23.501 5.7.1.5)
    }
    if (rrc_->send_data(psi, *qfi, packet)) {
        ++ul_packets_;
        return true;
    }
    // No DRB: in 5GMM-IDLE (or while a service request runs) the packet waits.
    auto& q = held_[psi];
    if (q.size() < 64) {
        q.push_back(std::move(packet));
    }
    (void)mm_->service_request(nas::ie::ServiceType::data, static_cast<std::uint16_t>(1U << psi));
    return true;
}

void UeDevice::flush_held() {
    auto held = std::move(held_);
    held_.clear();
    for (auto& [psi, q] : held) {
        const proc::ue::SessionInfo* s = sm_->session(psi);
        for (auto& p : q) {
            const auto qfi = s != nullptr ? ul_qfi(*s, p) : std::nullopt;
            if (qfi && rrc_->send_data(psi, *qfi, p)) {
                ++ul_packets_;
                if (auto t = tuns_.find(psi); t != tuns_.end()) {
                    ++t->second.ul;
                }
            }
        }
    }
}

Result<void> UeDevice::ps_establish(const proc::ue::SessionRequest& r) {
    if (!proc::ue::is_registered(mm_->state())) {
        return make_error(Errc::invalid_argument, 0, "the UE is not registered");
    }
    auto psi = sm_->establish(r);
    if (!psi) {
        return psi.error();
    }
    return {};
}

Result<void> UeDevice::ps_release(std::uint8_t psi) { return sm_->release(psi); }

// ---- the inject-mode ping ----------------------------------------------------------------------

Result<void> UeDevice::ping(const PingRequest& p) {
    if (ping_) {
        return make_error(Errc::invalid_argument, 0, "a ping is running on this UE");
    }
    const proc::ue::SessionInfo* s = nullptr;
    if (p.psi != 0) {
        s = sm_->session(p.psi);
    } else {
        for (const auto& info : sm_->sessions()) {
            if (info.state == proc::ue::SmState::active) {
                s = sm_->session(info.psi);
                break;
            }
        }
    }
    if (s == nullptr || s->state != proc::ue::SmState::active || !s->ipv4) {
        return make_error(Errc::invalid_argument, p.psi, "no active IPv4 PDU session");
    }
    Ping g;
    g.id = ++ping_id_;
    g.req = p;
    g.psi = s->psi;
    g.src = *s->ipv4;
    ping_ = std::move(g);
    ping_next();
    return {};
}

void UeDevice::ping_next() {
    if (!ping_) {
        return;
    }
    Ping& g = *ping_;
    g.timer.reset();
    if (g.sent >= g.req.count) {
        ping_done("done");
        return;
    }
    const auto seq = static_cast<std::uint16_t>(g.sent + 1);
    const proc::ue::SessionInfo* s = sm_->session(g.psi);
    if (s == nullptr) {
        ping_done("session released");
        return;
    }
    const bool sent = send_ul(g.psi, ip::ping(g.src, g.req.dst, g.id, seq, g.req.size));
    ++g.sent;
    if (sent) {
        g.outstanding[seq] = ex_.now();   // from idle the time includes the service request
    } else {
        events_.emit("ue.ping.error", subject(), {{"seq", std::to_string(seq)}, {"what", "no such session"}});
    }
    const Millis wait = g.sent >= g.req.count ? g.req.linger : g.req.interval;
    g.timer = ex_.start_timer(wait, [this, alive = alive_] {
        if (*alive && ping_) {
            ping_next();
        }
    });
}

void UeDevice::ping_done(const char* why) {
    if (!ping_) {
        return;
    }
    Ping g = std::move(*ping_);
    ping_.reset();
    if (g.timer) {
        ex_.stop_timer(*g.timer);
    }
    const int loss = g.sent == 0 ? 100 : (g.sent - g.received) * 100 / g.sent;
    events_.emit("ue.ping.done", subject(),
                 {{"psi", std::to_string(g.psi)},
                  {"dst", fmt::format("{}.{}.{}.{}", g.req.dst[0], g.req.dst[1], g.req.dst[2], g.req.dst[3])},
                  {"sent", std::to_string(g.sent)},
                  {"received", std::to_string(g.received)},
                  {"loss_pct", std::to_string(loss)},
                  {"rtt_min_ms", std::to_string(g.rtt_min)},
                  {"rtt_avg_ms", std::to_string(g.received == 0 ? 0 : g.rtt_sum / g.received)},
                  {"rtt_max_ms", std::to_string(g.rtt_max)},
                  {"why", why}});
}

void UeDevice::on_dl(std::uint8_t psi, std::optional<sdap::DlHeader> h, Bytes sdu) {
    const proc::ue::SessionInfo* s = sm_->session(psi);
    if (h && s != nullptr) {
        // P2 Q11: an RQI makes or refreshes a derived QoS rule (TS 24.501 6.2.5.1.4.3; mutant
        // rqi_ignored, row ksim-p2.rqos-derived-rule) before the QFI is checked, since a derived
        // rule is how the UE learns a QFI it was not told of.
        if (h->rqi && !KSIM_MUTANT("rqi_ignored")) {
            (void)sm_->reflect(psi, h->qfi, sdu);
        }
        // KS-SDAP-002: a QFI none of the session's rules, derived rules or flow descriptions
        // names is discarded and counted (mutant unknown_qfi_accepted, row ksim-p2.unknown-qfi).
        if (!known_qfi(*s, h->qfi) && !KSIM_MUTANT("unknown_qfi_accepted")) {
            ++dl_unknown_qfi_[psi];
            if (unknown_told_.insert({psi, h->qfi}).second) {
                events_.emit("ue.sdap.unknown_qfi", subject(), {{"psi", std::to_string(psi)}, {"qfi", std::to_string(h->qfi)}});
            }
            return;
        }
        ++dl_per_qfi_[{psi, h->qfi}];
    }
    on_dl_ip(psi, std::move(sdu));
}

bool UeDevice::known_qfi(const proc::ue::SessionInfo& s, std::uint8_t qfi) {
    if (s.rules.empty() || qfi == s.default_qfi || s.flow_5qi.count(qfi) != 0) {
        return true;
    }
    const auto named = [qfi](const auto& rules) {
        return std::any_of(rules.begin(), rules.end(), [qfi](const auto& r) { return r.qfi == qfi; });
    };
    return named(s.rules) || named(s.derived);
}

void UeDevice::on_dl_ip(std::uint8_t psi, Bytes packet) {
    ++dl_packets_;
    if (auto t = tuns_.find(psi); t != tuns_.end()) {
        // The TUN data plane: the namespace's stack answers and receives;
        // only a reply to ksim's own inject ping is kept back.
        bool ours = false;
        if (ping_ && ping_->psi == psi) {
            auto p = ip::decode(packet);
            if (p && p->protocol == ip::kIcmp) {
                auto e = ip::decode_icmp(p->payload);
                ours = e && *e && (*e)->reply && (*e)->id == ping_->id;
            }
        }
        if (!ours) {
            ++t->second.dl;
            (void)t->second.port->write(packet);
            return;
        }
    }
    auto p = ip::decode(packet);
    if (p && p->protocol == ip::kUdp) {
        udp_echo(psi, *p);   // P2 Q11: inject mode's UDP echo (port 7), for the reflective QoS rows
        return;
    }
    if (!p || p->protocol != ip::kIcmp) {
        return;
    }
    auto e = ip::decode_icmp(p->payload);
    if (!e || !*e) {
        return;
    }
    const ip::Echo& echo = **e;
    if (!echo.reply) {
        // An echo request to the UE (a ping from the DN): answered on the same session.
        const proc::ue::SessionInfo* s = sm_->session(psi);
        if (s != nullptr && s->ipv4 && p->dst == *s->ipv4) {
            ip::Echo r = echo;
            r.reply = true;
            ip::Ipv4 out;
            out.id = p->id;
            out.protocol = ip::kIcmp;
            out.src = p->dst;
            out.dst = p->src;
            out.payload = ip::encode_icmp(r);
            const Bytes reply = ip::encode(out);
            if (const auto qfi = ul_qfi(*s, reply); qfi && rrc_->send_data(psi, *qfi, reply)) {
                ++ul_packets_;
            }
            events_.emit("ue.ping.answered", subject(),
                         {{"psi", std::to_string(psi)},
                          {"from", fmt::format("{}.{}.{}.{}", p->src[0], p->src[1], p->src[2], p->src[3])},
                          {"seq", std::to_string(echo.seq)}});
        }
        return;
    }
    if (!ping_ || echo.id != ping_->id || ping_->psi != psi) {
        return;
    }
    auto it = ping_->outstanding.find(echo.seq);
    if (it == ping_->outstanding.end()) {
        return;
    }
    const Millis rtt = ex_.now() - it->second;
    ping_->outstanding.erase(it);
    ++ping_->received;
    ping_->rtt_sum += rtt;
    ping_->rtt_min = ping_->received == 1 ? rtt : std::min(ping_->rtt_min, rtt);
    ping_->rtt_max = std::max(ping_->rtt_max, rtt);
    events_.emit("ue.ping.reply", subject(),
                 {{"psi", std::to_string(psi)}, {"seq", std::to_string(echo.seq)}, {"rtt_ms", std::to_string(rtt)},
                  {"ttl", std::to_string(p->ttl)}});
}

std::vector<std::pair<std::string, std::string>> UeDevice::status() const {
    using proc::ue::MmState;
    const MmState s = mm_->state();
    std::vector<std::pair<std::string, std::string>> out;
    out.emplace_back("UE", "imsi-" + cfg_.supi);
    out.emplace_back("INDEX", std::to_string(cfg_.index));
    out.emplace_back("POWER", powered_ ? "on" : "off");
    out.emplace_back("RM_STATE", proc::ue::is_registered(s) ? "RM-REGISTERED" : "RM-DEREGISTERED");
    out.emplace_back("CM_STATE", rrc_->state() == proc::ue::RrcState::idle ? "CM-IDLE" : "CM-CONNECTED");
    out.emplace_back("RRC_STATE", proc::ue::rrc_state_name(rrc_->state()));
    out.emplace_back("MM_STATE", proc::ue::mm_state_name(s));
    out.emplace_back("UPDATE_STATUS", proc::ue::update_status_name(mm_->update_status()));
    out.emplace_back("USIM", mm_->usim_valid() ? "valid" : "invalid");
    out.emplace_back("CAMPED", rrc_->camped() ? "1" : "0");
    out.emplace_back("AS_SECURITY", rrc_->as_security() ? "1" : "0");
    if (const auto& g = mm_->guti()) {
        out.emplace_back("GUTI", guti_text(*g));
    }
    if (const auto& tl = mm_->tai_list(); tl && !tl->tais.empty()) {
        const auto& t = tl->tais.front();
        out.emplace_back("TAI", fmt::format("{}{}-{:06x}", t.plmn.mcc, t.plmn.mnc, t.tac));
    }
    if (const auto c = rrc_->c_rnti()) {
        out.emplace_back("C_RNTI", fmt::format("0x{:04x}", *c));
    }
    if (const auto t = mm_->t3512()) {
        out.emplace_back("T3512_S", std::to_string(*t / 1000));
    }
    out.emplace_back("PDU_SESSIONS", std::to_string(sm_->sessions().size()));
    out.emplace_back("DATA_PLANE", net_ != nullptr ? "netns" : "inject");
    if (net_ != nullptr) {
        out.emplace_back("NETNS", netns_up_ ? cfg_.netns : "");
    }
    out.emplace_back("UL_PACKETS", std::to_string(ul_packets_));
    out.emplace_back("DL_PACKETS", std::to_string(dl_packets_));
    return out;
}

} // namespace ksim::node
