// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's SMS over NAS (P1 N13): the SMC (CM sublayer, TS 24.011 5), the SMR
// (RL, TS 24.011 6) and the SM-TL (TS 23.040) of the MS side, over 5GMM's NAS
// transport (TS 24.501 5.4.5, payload container type SMS).
//
// MO: one RP transaction per TPDU: SMS-SUBMIT, or several with a concatenation
// header (TS 23.040 9.2.3.24.1); RP-DA is the service centre of EF.SMSP (L7).
// Each CP-DATA runs TC1* with retransmissions (5.3.2.1), RP-DATA TR1M and
// RP-SMMA TRAM (10.1). A message after the first goes in place of the final
// CP-ACK (5.4). MT: CP-ACK, then the SMS-DELIVER stored in EF.SMS and RP-ACK,
// or RP-ERROR #22 when the memory is full (then RP-SMMA once it is not). A
// CP-DATA repeated on a transaction the UE answered is acknowledged again, not
// delivered twice. Nothing is sent while SMS over NAS is not allowed.

#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "codec/nas/sms.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/result.hpp"

namespace ksim::proc::ue {

struct SmsConfig {
    std::string id;                    // the events' subject
    Millis tc1 = 10'000;               // TC1*: enough for the lower layers (TS 24.011 5.3.2.1)
    int cp_retransmissions = 2;        // 1, 2 or 3 (5.3.2.1)
    Millis tr1m = 40'000;              // 35 to 45 s (TS 24.011 10.1)
    Millis tram = 30'000;              // 25 to 35 s
    std::size_t records = 10;          // EF.SMS's records (cards/usim-5g.yaml)
};

/// What the SMS entity asks of 5GMM and of the card.
struct SmsPorts {
    std::function<Result<void>(Bytes cp)> send;                 // UL NAS TRANSPORT, SMS
    std::function<bool()> allowed;                              // SMS over NAS allowed
    std::function<std::optional<Bytes>()> service_centre;       // EF.SMSP: TON/NPI and digits
    std::function<void(std::uint8_t record, Bytes)> store;      // an EF.SMS record
    std::function<void(Bytes)> store_smss;                      // EF.SMSS
    std::function<Bytes()> smss;                                // EF.SMSS as read
};

struct SmsSubmit {
    std::string to;                       // the destination's digits (international)
    std::string text;                     // UTF-8
    bool ucs2 = false;                    // otherwise the GSM 7-bit default alphabet
    bool status_report = false;           // TP-SRR
    std::optional<std::uint8_t> vp;       // TP-VP, relative format
};

struct StoredSms {
    std::uint8_t record = 0;              // EF.SMS record (1-based)
    std::string from;                     // TP-OA digits
    std::string text;                     // UTF-8, the user data header left out
    std::uint8_t dcs = 0;
    Bytes ud;                             // TP-UD as received
    std::optional<std::array<std::uint8_t, 3>> concat;   // reference, parts, sequence
    Bytes scts;
};

class Sms {
public:
    Sms(Executor& ex, IEventSink& events, SmsConfig cfg, SmsPorts ports);
    ~Sms();
    Sms(const Sms&) = delete;
    Sms& operator=(const Sms&) = delete;

    /// An MO short message: the number of parts queued. Errc::invalid_argument
    /// while SMS over NAS is not allowed (nothing is sent) or for a text the
    /// chosen alphabet cannot carry.
    Result<std::size_t> send(const SmsSubmit& m);
    /// A CP message from the network (DL NAS TRANSPORT).
    void on_downlink(ByteView cp);
    const std::vector<StoredSms>& messages() const noexcept { return stored_; }
    /// sms-memory: full makes MT messages get RP-ERROR #22 (memory capacity
    /// exceeded); available sends RP-SMMA when the network was told (TS 24.011 7.3.6).
    void memory(bool full);
    bool memory_full() const noexcept { return full_; }
    /// Power off or a new card: transactions end, stored messages stay with the card.
    void reset();

private:
    enum class Kind : std::uint8_t { submit, smma, mt };
    enum class CpState : std::uint8_t { wait_cp_ack, connected, done };
    struct Tx {
        std::uint8_t ti = 0;              // 0-6; the TI flag is 0 when the UE allocated it
        bool mo = true;
        Kind kind = Kind::submit;
        CpState cp = CpState::wait_cp_ack;
        Bytes cp_data;                    // the last CP-DATA sent, for TC1*
        int retx = 0;
        std::optional<TimerId> tc1;
        std::optional<TimerId> rl;        // TR1M or TRAM
        std::uint8_t rp_mr = 0;
        Bytes rpdu_in;                    // MT: the network's RPDU, for a repeated CP-DATA
        std::uint8_t tp_mr = 0;           // MO SUBMIT: TP-MR
    };
    struct Pending {
        Kind kind = Kind::submit;
        Bytes rpdu;
        std::uint8_t rp_mr = 0;
        std::uint8_t tp_mr = 0;
        std::string ud_hex;
    };

    std::uint8_t next_tp_mr();
    void start_next_mo();
    void send_cp_data(Tx& t, Bytes rpdu);
    void send_cp(std::uint8_t ti_octet, sms::CpType type, Bytes data = {}, std::uint8_t cause = 0);
    void arm_tc1(std::uint8_t key);
    void on_tc1(std::uint8_t key);
    void on_rl_timer(std::uint8_t key);
    void finish(std::uint8_t key);
    void on_cp_data(const sms::Cp& cp);
    void on_cp_ack(const sms::Cp& cp);
    void on_rp_from_network(Tx& t, const sms::Rp& rp);
    void on_mt_rp_data(Tx& t, const sms::Rp& rp);
    std::optional<std::uint8_t> free_record() const;
    static std::uint8_t key_of(bool mo, std::uint8_t ti) { return static_cast<std::uint8_t>((mo ? 0 : 8) | (ti & 7)); }

    Executor& ex_;
    IEventSink& events_;
    SmsConfig cfg_;
    SmsPorts ports_;
    std::map<std::uint8_t, Tx> txs_;                // by key_of(mo, ti)
    std::deque<Pending> queue_;                      // MO RPDUs not yet sent
    std::optional<std::uint8_t> mo_active_;          // the key of the MO transaction running
    std::optional<std::uint8_t> withheld_ack_;       // 5.4: the final CP-ACK left for the next CP-DATA
    std::uint8_t next_ti_ = 0;
    std::uint8_t rp_mr_ = 0;
    std::uint8_t concat_ref_ = 0;
    std::optional<std::uint8_t> tp_mr_;
    bool full_ = false;
    bool network_told_full_ = false;
    std::vector<StoredSms> stored_;
    std::map<std::uint8_t, Bytes> answered_mt_;      // MT TI -> the RPDU the UE answered (duplicates)
    std::shared_ptr<bool> alive_;
};

} // namespace ksim::proc::ue
