// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One UE as the farm runs it (P1 N8; architecture §6): its soft card behind
// the in-process transport and the terminal, its RRC and 5GMM entities wired
// to each other, and the device commands of cli.md §3 that P1 N8 offers:
// power on (card read, fixed camping, then initial registration), register,
// deregister and power off with switch-off. Everything runs on the device's
// executor; the node posts commands to it.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "codec/air/kair.hpp"
#include "codec/nas/ie/ie.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/result.hpp"
#include "proc/ue/nas_mm/mm.hpp"
#include "proc/ue/rrc/rrc.hpp"
#include "uicc/os/card.hpp"
#include "uicc/terminal/terminal.hpp"
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
};

/// The run's capture of the UE's RRC and NAS in clear (architecture §9).
struct UeTaps {
    std::function<void(std::string_view channel, ByteView pdu, const std::string& supi)> rrc;
    std::function<void(bool uplink, ByteView plain, const std::string& supi)> nas;
};

class UeDevice {
public:
    UeDevice(Executor& ex, IEventSink& events, UeDeviceConfig cfg, std::unique_ptr<uicc::os::Card> card,
             std::function<void(air::Frame)> to_air, const UeTaps& taps);
    ~UeDevice();
    UeDevice(const UeDevice&) = delete;
    UeDevice& operator=(const UeDevice&) = delete;

    void on_frame(const air::Frame& f);

    /// The commands; an error means the device is in the wrong state for it
    /// (cli.md exit 6), with the reason in the error's text.
    Result<void> power_on();
    Result<void> register_initial();
    Result<void> deregister(bool switch_off);

    const UeDeviceConfig& config() const noexcept { return cfg_; }
    std::string subject() const { return "ue:imsi-" + cfg_.supi; }
    bool powered() const noexcept { return powered_; }
    /// The status of cli.md §3 as KEY=value pairs.
    std::vector<std::pair<std::string, std::string>> status() const;

private:
    void poll_registration(int left);

    Executor& ex_;
    UeDeviceConfig cfg_;
    std::unique_ptr<uicc::os::Card> card_;
    uicc::InProcTransport transport_;
    uicc::Terminal terminal_;
    std::unique_ptr<proc::ue::UeRrc> rrc_;
    std::unique_ptr<proc::ue::Mm> mm_;
    bool powered_ = false;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

/// A 5G-GUTI as cli.md prints it: <mcc><mnc>-<region hex>-<set hex>-<pointer hex>-<tmsi hex>.
std::string guti_text(const nas::ie::MobileIdentity& g);

} // namespace ksim::node
