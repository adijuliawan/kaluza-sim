// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The core stub's SMSF with its SC (P1 N13): the network side of SMS over NAS
// for every UE of the stub. An MO SMS-SUBMIT is acknowledged (RP-ACK) and
// relayed as an SMS-DELIVER to the UE whose MSISDN is its TP-DA, with TP-PID,
// TP-DCS, TP-UDHI and TP-UD as submitted (TS 23.040: the SC relays them); an
// idle UE is paged and served once connected; RP-ERROR #22 keeps the message
// until RP-SMMA. The checks are the network side's of TS 24.011: CP-ACK for
// each CP-DATA, the TI flags, and RP-DA naming the service centre (L7).

#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "codec/nas/sms.hpp"
#include "verdict.hpp"

namespace ksim::corestub {

class Smsf {
public:
    struct Link {
        std::function<std::string(const std::string& msisdn)> supi_of;   // empty when unknown
        std::function<std::string(const std::string& supi)> msisdn_of;
        /// A CP message to the UE; false when it is not connected (the stub then pages it).
        std::function<bool(const std::string& supi, Bytes cp)> to_ue;
        std::function<void(const std::string& supi)> page;
        std::function<std::uint64_t()> now_ms;
    };

    /// `sc`: the service centre's digits (RP-OA of MT, the RP-DA the UE must use).
    Smsf(Link link, std::string sc);

    void on_uplink(const std::string& supi, ByteView cp);
    /// The UE is in CM-CONNECTED again: what waits for it goes.
    void on_connected(const std::string& supi);
    /// An SMS-DELIVER the SC has for the UE on its own (GSM 7-bit text from `from`).
    bool deliver(const std::string& to_supi, const std::string& from, const std::string& text);

    std::vector<Verdict> failures() const;
    std::size_t submits() const noexcept { return submits_; }
    std::size_t delivered() const noexcept { return delivered_; }
    std::size_t pending(const std::string& supi) const;

private:
    struct Mt {
        Bytes rpdu;                       // RP-DATA n->ms
        std::uint8_t ti = 0;
        bool sent = false;
        bool ue_acked = false;            // the UE's CP-ACK for our CP-DATA
    };
    struct Ue {
        std::deque<Mt> mt;                // the first one is in flight once sent
        bool memory_full = false;
        std::uint8_t next_ti = 0;
        std::uint8_t mr = 0;
    };

    void check(bool ok, const char* clause, const char* what, std::string detail = {});
    void on_mo(const std::string& supi, std::uint8_t ti, const sms::Rp& rp);
    void on_mt_answer(const std::string& supi, std::uint8_t ti, const sms::Rp& rp);
    void flush(const std::string& supi);
    void send(const std::string& supi, std::uint8_t ti_octet, sms::CpType type, Bytes data = {});
    Bytes sc_address() const;          // TON/NPI and digits, as RP addresses carry them
    Bytes scts() const;                // TP-SCTS from now

    Link link_;
    std::string sc_;
    std::map<std::string, Ue> ues_;
    std::vector<Verdict> verdicts_;
    std::size_t submits_ = 0;
    std::size_t delivered_ = 0;
};

} // namespace ksim::corestub
