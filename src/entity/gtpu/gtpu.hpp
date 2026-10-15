// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A GTP-U endpoint (P1 N10; TS 29.281 j00, TS 38.415, TS 38.425): one UDP
// port (an IDatagram), tunnels by local TEID. Used for N3 (with the PDU
// Session Container: DL PDU SESSION INFORMATION from the UPF, UL from the
// gNB, each with the QFI) and for F1-U (NR-U DL USER DATA with its sequence
// number from the CU-UP; plain G-PDUs from the DU). It answers Echo Request
// (7.2.2), sends Error Indication for a G-PDU to a TEID it does not know
// (7.3.1) and reports one it receives. Passive (R4): the datagram port and the
// timer service are injected.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/transport.hpp"

namespace ksim::entity::gtpu {

/// An NR-U DL DATA DELIVERY STATUS (TS 38.425 5.5.2.2), the DU's feedback
/// to the node hosting PDCP (P2 Q4). The NR PDCP SNs are those of PDUs that
/// came on F1-U, retransmissions excluded.
struct DeliveryStatus {
    std::uint32_t desired_buffer = 0;                  // bytes for the DRB; 0: stop sending
    std::optional<std::uint32_t> highest_delivered;    // in sequence to the UE (RLC AM)
    std::optional<std::uint32_t> highest_transmitted;  // to the lower layers
    std::optional<std::uint32_t> polling_nru_sn;       // the DL USER DATA whose Report Polling asked
    bool final_frame = false;
    friend bool operator==(const DeliveryStatus&, const DeliveryStatus&) = default;
};

/// The extension a G-PDU carries.
struct UserData {
    std::uint32_t teid = 0;
    std::optional<std::uint8_t> dl_qfi;   // a DL PDU SESSION INFORMATION frame
    std::optional<std::uint8_t> ul_qfi;   // a UL PDU SESSION INFORMATION frame
    std::optional<std::uint32_t> nru_sn;  // an NR-U DL USER DATA frame
    Bytes payload;                        // the T-PDU; none with a DDDS of its own
    bool report_polling = false;          // the DL USER DATA's Report Polling flag (P2 Q4)
    std::optional<DeliveryStatus> ddds;   // an NR-U DL DATA DELIVERY STATUS frame (P2 Q4)

    /// A G-PDU with no frame (an NR-U UL T-PDU), with a PDU SESSION INFORMATION
    /// frame, or with a DL USER DATA frame.
    static UserData plain(std::uint32_t teid, Bytes payload) {
        UserData d;
        d.teid = teid;
        d.payload = std::move(payload);
        return d;
    }
    static UserData dl_psc(std::uint32_t teid, std::uint8_t qfi, Bytes payload) {
        UserData d = plain(teid, std::move(payload));
        d.dl_qfi = qfi;
        return d;
    }
    static UserData ul_psc(std::uint32_t teid, std::uint8_t qfi, Bytes payload) {
        UserData d = plain(teid, std::move(payload));
        d.ul_qfi = qfi;
        return d;
    }
    static UserData nru(std::uint32_t teid, std::uint32_t sn, Bytes payload) {
        UserData d = plain(teid, std::move(payload));
        d.nru_sn = sn;
        return d;
    }
};

Result<Bytes> encode(const UserData& d);
Result<UserData> decode_gpdu(ByteView in);

struct Stats {
    std::uint64_t rx = 0;
    std::uint64_t tx = 0;
    std::uint64_t unknown_teid = 0;        // answered by Error Indication
    std::uint64_t error_indications = 0;   // received
    std::uint64_t echo_requests = 0;
    std::uint64_t echo_responses = 0;
    std::uint64_t malformed = 0;
};

class Endpoint {
public:
    using OnData = std::function<void(const UserData& d, const ksim::Endpoint& from)>;
    /// An Error Indication from a peer: the TEID it names (the peer's receiving TEID we used).
    using OnErrorIndication = std::function<void(std::uint32_t teid, const ksim::Endpoint& from)>;

    /// `tag` goes into the top 8 bits of every TEID this endpoint allocates.
    Endpoint(IDatagram& port, std::uint8_t tag);
    ~Endpoint();
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;

    /// A new local TEID delivering to `rx`.
    std::uint32_t bind(OnData rx);
    void unbind(std::uint32_t teid);
    bool bound(std::uint32_t teid) const { return tunnels_.count(teid) != 0; }

    Result<void> send(const ksim::Endpoint& peer, const UserData& d);
    /// An Echo Request; `on_response` runs when its Echo Response comes.
    Result<void> echo(const ksim::Endpoint& peer, std::function<void()> on_response);

    void on_error_indication(OnErrorIndication f) { on_error_ = std::move(f); }
    const Stats& stats() const noexcept { return stats_; }
    ksim::Endpoint local() const { return port_.local(); }

private:
    void on_datagram(ByteView in, const ksim::Endpoint& from);
    void error_indication(std::uint32_t teid, const ksim::Endpoint& to);

    IDatagram& port_;
    std::uint8_t tag_;
    std::uint32_t next_ = 1;
    std::uint16_t echo_seq_ = 0;
    std::map<std::uint32_t, OnData> tunnels_;
    std::map<std::uint16_t, std::function<void()>> echoes_;
    OnErrorIndication on_error_;
    Stats stats_;
};

} // namespace ksim::entity::gtpu
