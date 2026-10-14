// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A run's packet captures (P1 N8; architecture §9): ngap.pcapng, f1ap.pcapng
// and uu.pcapng in the run directory, each as Exported-PDU frames Wireshark
// decodes by name ("ngap", "f1ap", "nr-rrc.<channel>", "nas-5gs"). The Uu
// capture holds RRC in clear, as the UE built or took it, and NAS in clear
// only when the run asks for it (KS-CTL-004). Frame comments carry the
// direction and, on Uu, the SUPI.
//
// Keys never reach a capture (requirements §3.6): every NGAP PDU is re-encoded
// with its Security Keys and NHs zeroed (ngap::redact_keys) before it is
// written, and one that does not decode is left out and counted. F1AP and the
// Uu messages of P1 carry no key.

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
    std::uint64_t uu = 0;
    std::uint64_t keys_zeroed = 0;
    std::uint64_t left_out = 0;   // NGAP PDUs that did not decode, so could not be redacted
};

class Capture {
public:
    /// Creates the three files in `dir` (mode 0600).
    static Result<std::unique_ptr<Capture>> open(const std::string& dir);
    ~Capture();
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;

    void ngap(bool tx, ByteView pdu);
    void f1ap(bool cu_tx, ByteView pdu);
    void rrc(std::string_view channel, ByteView pdu, const std::string& supi);
    void nas(bool uplink, ByteView plain, const std::string& supi);

    CaptureStats stats() const;
    void close();

private:
    struct File {
        std::FILE* f = nullptr;
        std::unique_ptr<pcap::PcapngWriter> w;
        std::uint32_t ifc = 0;
    };
    Capture() = default;
    static Result<void> open_file(File& out, const std::string& path, std::string_view ifc_name);
    void write(File& file, std::string_view dissector, ByteView pdu, const std::string& comment);

    mutable std::mutex mu_;
    File ngap_;
    File f1ap_;
    File uu_;
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

} // namespace ksim::node
