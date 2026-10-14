// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Hostile NG-C into the CU-CP (P1 N7, L15): whatever an AMF sends, the CU-CP
// answers or ignores it and the process goes on. The input is one or more
// NGAP PDUs, each preceded by a two-octet length; the CU-CP has an F1 setup
// behind it, so UE-associated messages meet its real state machine.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "codec/asn1/msg/f1ap.hpp"
#include "codec/asn1/msg/rrc.hpp"
#include "platform/event.hpp"
#include "platform/sim_loop.hpp"
#include "proc/ran/cucp.hpp"

namespace {

using ksim::ByteView;

/// An association that is up and swallows what is sent.
class Sink final : public ksim::IAssoc {
public:
    void set_handlers(OnMessage m, OnEvent) override { on_message = std::move(m); }
    ksim::Result<void> send(ByteView, ksim::SctpMeta) override { return {}; }
    bool up() const noexcept override { return true; }
    std::uint16_t out_streams() const noexcept override { return 3; }
    std::uint16_t in_streams() const noexcept override { return 3; }
    void shutdown() override {}
    void abort() override {}
    ksim::Endpoint peer() const override { return {}; }
    OnMessage on_message;
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    ksim::SimLoop loop;
    ksim::EventRing events(256, loop.clock());
    Sink ng;
    Sink f1;
    ksim::proc::ran::CuCp cucp(loop, events, ksim::proc::ran::CuCpConfig{}, ng, f1);
    // An F1 setup first, so the CU-CP has its cell.
    ksim::f1ap::ServedCell cell;
    cell.cgi = {{0x00, 0xF1, 0x10}, 0x1A0000001};
    cell.pci = 1;
    cell.tac = 1;
    cell.plmns = {cell.cgi.plmn};
    cell.meas_timing = ksim::rrc::measurement_timing_configuration().value_or(ksim::Bytes{0x00});
    if (auto setup = ksim::f1ap::encode(ksim::f1ap::F1SetupRequest{1, 1, "du", {cell}}); setup && f1.on_message) {
        f1.on_message(*setup, {62, 0});
    }
    std::size_t i = 0;
    while (i + 2 <= size) {
        const std::size_t n = static_cast<std::size_t>(data[i]) << 8 | data[i + 1];
        i += 2;
        const std::size_t take = n < size - i ? n : size - i;
        cucp.on_ngap(ByteView(data + i, take));
        i += take;
        loop.run_for(5);
    }
    loop.run_for(100);
    return 0;
}
