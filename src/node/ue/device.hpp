// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One UE as the farm runs it (P1 N8; architecture §6): its soft card behind
// the in-process transport and the terminal, its RRC and 5GMM entities wired
// to each other, and the device commands of cli.md §3 that P1 N8 offers:
// power on (card read, fixed camping, then initial registration), register,
// deregister and power off with switch-off. N10 adds the 5GSM entity, the PDU
// session commands (establish, release, list) and the inject-mode ping: ICMP
// echo requests built by the device and carried on the session's DRB, the
// replies matched and counted, and an echo request to the UE's address
// answered. N11 adds the TUN data plane: given an IUeNet, the device has a
// namespace of its own from power on, a TUN per active session (uplink packets
// from it checked for the session's address, others counted as noise and
// dropped; downlink packets written to it), the session's DNS server as the
// namespace's resolv.conf, and commands run inside it. Everything runs on the
// device's executor; the node posts commands to it.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "codec/air/kair.hpp"
#include "codec/ip/ipv4.hpp"
#include "node/ue/dataplane.hpp"
#include "codec/nas/ie/ie.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/result.hpp"
#include "proc/ue/nas_mm/mm.hpp"
#include "proc/ue/nas_sm/sm.hpp"
#include "proc/ue/sms/sms.hpp"
#include "proc/ue/rrc/rrc.hpp"
#include "uicc/os/card.hpp"
#include "uicc/terminal/terminal.hpp"
#include "uicc/trace/trace.hpp"
#include "uicc/transport/transport.hpp"

namespace ksim::node {

struct UeDeviceConfig {
    unsigned index = 1;                       // the farm index (ksim-ctl ue 17)
    std::string supi;                         // the IMSI's digits
    std::uint32_t radio_id = 1;               // KAIR addressing; 0 is broadcast
    nas::ie::Plmn plmn;
    std::vector<nas::ie::Snssai> nssai;
    std::string imeisv;                       // 16 digits
    bool allow_null_integrity = false;        // D1: the bisect switch only
    std::uint64_t seed = 0;
    std::string netns;                        // with an IUeNet: "ksim-ue-<index>"
    std::optional<proc::ue::MmTimerValues> mm_timers;   // the defaults of TS 24.501 10.2 unless set
};

/// A session's interface as `ifaces` shows it.
struct UeIface {
    std::string ifname;
    std::uint8_t psi = 0;
    ip::Addr addr{};
    std::uint16_t mtu = 0;
    std::optional<ip::Addr> dns;
    std::uint64_t ul = 0;
    std::uint64_t dl = 0;
};

/// An inject-mode ping (cli.md §3 ping): `count` echo requests `interval` apart,
/// then `linger` for the last reply; events ue.ping.reply and ue.ping.done.
struct PingRequest {
    std::uint8_t psi = 0;                     // 0: the lowest active session
    ip::Addr dst{};
    int count = 3;
    Millis interval = 1'000;
    std::size_t size = 56;
    Millis linger = 2'000;
};

/// The run's capture of the UE's RRC and NAS in clear (architecture §9).
struct UeTaps {
    std::function<void(std::string_view channel, ByteView pdu, const std::string& supi)> rrc;
    std::function<void(bool uplink, ByteView plain, const std::string& supi)> nas;
    /// The card's APDU trace, GSMTAP-SIM records (N14), while `sim trace on`.
    std::function<void(std::uint8_t sub_type, ByteView payload, const std::string& supi)> sim;
};

/// What `sim info` shows: read from the card in the reader, never a key.
struct SimInfo {
    bool present = true;
    std::string atr;
    std::string iccid;
    std::string imsi;
    std::string msisdn;
    std::vector<unsigned> ust;
    std::string suci_schemes;        // EF.SUCI_Calc_Info's protection scheme identifiers
    std::string routing_indicator;
};

class UeDevice {
public:
    /// `net`: the system's side of the TUN data plane (none: inject mode).
    UeDevice(Executor& ex, IEventSink& events, UeDeviceConfig cfg, std::unique_ptr<uicc::os::Card> card,
             std::function<void(air::Frame)> to_air, const UeTaps& taps, IUeNet* net = nullptr);
    ~UeDevice();
    UeDevice(const UeDevice&) = delete;
    UeDevice& operator=(const UeDevice&) = delete;

    void on_frame(const air::Frame& f);

    /// The commands; an error means the device is in the wrong state for it
    /// (cli.md exit 6), with the reason in the error's text.
    Result<void> power_on();
    Result<void> register_initial();
    Result<void> deregister(bool switch_off);
    /// Power off without signalling (cli.md power off --abrupt): the radio goes
    /// silent, what is in memory is lost, the card keeps what it holds.
    Result<void> power_off_abrupt();
    /// SERVICE REQUEST for signalling (cli.md service-request).
    Result<void> service_request();
    // ---- SMS over NAS (N13)
    /// An MO message: its parts, or an error while SMS over NAS is not allowed.
    Result<std::size_t> sms_send(const proc::ue::SmsSubmit& m);
    const std::vector<proc::ue::StoredSms>& sms_list() const { return sms_->messages(); }
    void sms_memory(bool full) { sms_->memory(full); }
    bool sms_allowed() const { return mm_->sms_allowed(); }
    /// A mobility registration update (e.g. SMS requested again).
    Result<void> register_update();
    /// The UICC taken out of or put back into the reader (TS 24.501 5.5.2.2.1).
    Result<void> sim(bool present);
    /// The card's APDU trace into the run's sim.pcapng (sim-uicc.md §6).
    Result<void> sim_trace(bool on);
    bool sim_tracing() const noexcept { return tracer_.tracing(); }
    SimInfo sim_info() const;
    /// One EF by name ("EF.IMSI", "IMSI"), FID ("6F07") or FID path
    /// ("7FF0/5FC0/4F01"): its name, path and contents (one entry per record).
    /// Key files and NAS security state are refused, and so is what the card's
    /// access rules would not let a reader read in its present state.
    struct SimEf {
        std::string name;
        std::string path;
        std::vector<Bytes> contents;
        bool records = false;
    };
    Result<SimEf> sim_read(std::string_view ef) const;
    /// Airplane mode: on, a registered UE de-registers as for switch-off and the
    /// radio goes off (the card keeps its state); off, the UE powers on again.
    Result<void> airplane(bool on);
    Result<void> ps_establish(const proc::ue::SessionRequest& r);
    Result<void> ps_release(std::uint8_t psi);
    Result<void> ping(const PingRequest& p);
    std::vector<proc::ue::SessionInfo> sessions() const { return sm_->sessions(); }
    /// The TUN data plane: whether the UE has a namespace, its interfaces, the
    /// uplink packets dropped as noise (not IPv4 from the session's address).
    bool netns_mode() const noexcept { return net_ != nullptr; }
    bool netns_up() const noexcept { return netns_up_; }
    std::vector<UeIface> ifaces() const;
    std::uint64_t noise() const noexcept { return noise_; }
    /// Starts argv inside the UE's namespace (see IUeNet::exec). Errc::unsupported in inject mode.
    Result<std::uint32_t> exec(const std::vector<std::string>& argv, std::vector<int> fds);

    const UeDeviceConfig& config() const noexcept { return cfg_; }
    std::string subject() const { return "ue:imsi-" + cfg_.supi; }
    bool powered() const noexcept { return powered_; }
    /// The status of cli.md §3 as KEY=value pairs.
    std::vector<std::pair<std::string, std::string>> status() const;
    proc::ue::MmState mm_state() const noexcept { return mm_->state(); }

private:
    struct Ping {
        std::uint16_t id = 0;
        PingRequest req;
        std::uint8_t psi = 0;
        ip::Addr src{};
        int sent = 0;
        int received = 0;
        std::map<std::uint16_t, Millis> outstanding;   // seq -> sent at
        Millis rtt_sum = 0;
        Millis rtt_min = 0;
        Millis rtt_max = 0;
        std::optional<TimerId> timer;
    };

    struct Tun {
        UeTun spec;
        std::unique_ptr<IPacketPort> port;
        std::optional<ip::Addr> dns;
        std::uint64_t ul = 0;
        std::uint64_t dl = 0;
    };

    /// Registration once 5GMM leaves `waiting` (5GMM-NULL at power on,
    /// NO-SUPI once a UICC is put back) with a valid USIM.
    void poll_registration(int left, proc::ue::MmState waiting = proc::ue::MmState::null);
    void on_dl_ip(std::uint8_t psi, Bytes packet);
    void on_ul_ip(std::uint8_t psi, ByteView packet);
    /// Sends an uplink packet on its session's DRB; in 5GMM-IDLE it is held and
    /// a service request asks for the bearers (§5.6.1.1 d).
    bool send_ul(std::uint8_t psi, Bytes packet);
    void flush_held();
    void session_up(const proc::ue::SessionInfo& s);
    void session_down(std::uint8_t psi);
    Result<void> ensure_netns();
    void ping_next();
    void ping_done(const char* why);

    Executor& ex_;
    UeDeviceConfig cfg_;
    std::unique_ptr<uicc::os::Card> card_;
    uicc::InProcTransport transport_;
    uicc::trace::TracingTransport tracer_;   // between the reader and the terminal: off until sim trace on
    uicc::Terminal terminal_;
    std::function<void(std::uint8_t, ByteView, const std::string&)> sim_tap_;
    std::unique_ptr<proc::ue::UeRrc> rrc_;
    std::unique_ptr<proc::ue::Mm> mm_;
    std::unique_ptr<proc::ue::Sm> sm_;
    std::unique_ptr<proc::ue::Sms> sms_;
    IEventSink& events_;
    std::optional<Ping> ping_;
    std::uint16_t ping_id_ = 0;
    std::uint64_t dl_packets_ = 0;
    std::uint64_t ul_packets_ = 0;
    IUeNet* net_ = nullptr;
    bool netns_up_ = false;
    std::map<std::uint8_t, Tun> tuns_;   // by PSI
    std::uint64_t noise_ = 0;
    std::map<std::uint8_t, std::vector<Bytes>> held_;   // uplink waiting for a service request
    bool powered_ = false;
    bool sim_present_ = true;
    bool airplane_ = false;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

/// A 5G-GUTI as cli.md prints it: <mcc><mnc>-<region hex>-<set hex>-<pointer hex>-<tmsi hex>.
std::string guti_text(const nas::ie::MobileIdentity& g);

} // namespace ksim::node
