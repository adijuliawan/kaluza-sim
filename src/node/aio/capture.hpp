// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A run's packet captures (P1 N8; architecture §9): ngap.pcapng, f1ap.pcapng,
// e1ap.pcapng and uu.pcapng in the run directory, each as Exported-PDU frames
// Wireshark decodes by name ("ngap", "f1ap", "e1ap", "nr-rrc.<channel>",
// "nas-5gs"), and gtpu.pcapng (N10) with N3 and F1-U as raw IPv4/UDP frames on
// port 2152, so Wireshark's GTP-U dissector takes them, and sim.pcapng (N14)
// with the APDUs of the UEs whose trace is on, as GSMTAP-SIM on UDP 4729
// (redacted by uicc/trace before they get here). The Uu
// capture holds RRC in clear, as the UE built or took it, and NAS in clear
// only when the run asks for it (KS-CTL-004). Frame comments carry the
// direction and, on Uu, the SUPI.
//
// Keys never reach a capture (requirements §3.6): every NGAP PDU is re-encoded
// with its Security Keys and NHs zeroed (ngap::redact_keys), and every E1AP PDU
// with its UP keys zeroed (e1ap::redact_keys), before it is written; one that
// does not decode is left out and counted. F1AP, GTP-U and the Uu messages of
// P1 carry no key (the user plane on F1-U is ciphered PDCP).

#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include "platform/pcapng.hpp"
#include "platform/result.hpp"
#include "platform/transport.hpp"

namespace ksim::node {

struct CaptureStats {
    std::uint64_t ngap = 0;
    std::uint64_t f1ap = 0;
    std::uint64_t e1ap = 0;
    std::uint64_t gtpu = 0;
    std::uint64_t uu = 0;
    std::uint64_t sim = 0;
    std::uint64_t keys_zeroed = 0;
    std::uint64_t left_out = 0;   // NGAP and E1AP PDUs that did not decode, so could not be redacted
};

/// P2 Q8 (ADR 0011): how much of the user plane (gtpu.pcapng) a run keeps. full: every
/// frame whole, flushed as written (the gates read it while the run goes on); headers:
/// each frame's first kHeaderOctets (outer IPv4, UDP, GTP-U and its extension headers,
/// the inner IP and transport headers) with its length on the wire, flushed every
/// 1024 frames (performance runs); off: none.
enum class UserPlaneCapture : std::uint8_t { full, headers, off };

class Capture {
public:
    static constexpr std::size_t kHeaderOctets = 128;
    /// Creates the six files in `dir` (mode 0600).
    static Result<std::unique_ptr<Capture>> open(const std::string& dir, UserPlaneCapture up = UserPlaneCapture::full);
    ~Capture();
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;

    void ngap(bool tx, ByteView pdu);
    void f1ap(bool cu_tx, ByteView pdu);
    void e1ap(bool cp_tx, ByteView pdu);
    void gtpu(const Endpoint& from, const Endpoint& to, ByteView pdu);
    void rrc(std::string_view channel, ByteView pdu, const std::string& supi);
    void nas(bool uplink, ByteView plain, const std::string& supi);
    /// A GSMTAP-SIM record (uicc/trace) of the UE's card.
    void sim(std::uint8_t sub_type, ByteView payload, const std::string& supi);

    CaptureStats stats() const;
    void close();

private:
    struct File {
        std::FILE* f = nullptr;
        std::unique_ptr<pcap::PcapngWriter> w;
        std::uint32_t ifc = 0;
    };
    Capture() = default;
    static Result<void> open_file(File& out, const std::string& path, std::string_view ifc_name,
                                  pcap::LinkType type = pcap::LinkType::upper_pdu);
    void write(File& file, std::string_view dissector, ByteView pdu, const std::string& comment);

    mutable std::mutex mu_;
    UserPlaneCapture up_ = UserPlaneCapture::full;
    std::uint64_t unflushed_ = 0;
    File ngap_;
    File f1ap_;
    File e1ap_;
    File gtpu_;
    File uu_;
    File sim_;
    CaptureStats stats_;
};

/// An association that shows each message to `tap` as it is sent (tx) or taken.
class TapAssoc final : public IAssoc {
public:
    using Tap = std::function<void(bool tx, ByteView msg)>;
    TapAssoc(IAssoc& inner, Tap tap) : inner_(inner), tap_(std::move(tap)) {}

    void set_handlers(OnMessage on_message, OnEvent on_event) override;
    Result<void> send(ByteView msg, SctpMeta meta) override;
    bool up() const noexcept override { return inner_.up(); }
    std::uint16_t out_streams() const noexcept override { return inner_.out_streams(); }
    std::uint16_t in_streams() const noexcept override { return inner_.in_streams(); }
    void shutdown() override { inner_.shutdown(); }
    void abort() override { inner_.abort(); }
    Endpoint peer() const override { return inner_.peer(); }

private:
    IAssoc& inner_;
    Tap tap_;
};

/// A datagram port that shows each datagram to `tap` as it is sent or taken.
class TapDatagram final : public IDatagram {
public:
    using Tap = std::function<void(const Endpoint& from, const Endpoint& to, ByteView payload)>;
    TapDatagram(std::unique_ptr<IDatagram> inner, Tap tap) : inner_(std::move(inner)), tap_(std::move(tap)) {}

    void set_handler(OnDatagram on_datagram) override;
    Result<void> send_to(ByteView payload, const Endpoint& to) override;
    Endpoint local() const override { return inner_->local(); }
    std::uint64_t dropped() const noexcept override { return inner_->dropped(); }

private:
    std::unique_ptr<IDatagram> inner_;
    Tap tap_;
};

} // namespace ksim::node
