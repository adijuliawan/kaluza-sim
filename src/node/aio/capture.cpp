// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/capture.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <utility>

#include "codec/asn1/msg/e1ap.hpp"
#include "codec/asn1/msg/ngap.hpp"

namespace ksim::node {

namespace {

std::int64_t wall_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

Result<void> Capture::open_file(File& out, const std::string& path, std::string_view ifc_name, pcap::LinkType type) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "capture: cannot create a pcapng file");
    }
    out.f = ::fdopen(fd, "wb");
    if (out.f == nullptr) {
        ::close(fd);
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "capture: fdopen failed");
    }
    std::FILE* f = out.f;
    out.w = std::make_unique<pcap::PcapngWriter>([f](ByteView block) {
        (void)std::fwrite(block.data(), 1, block.size(), f);
    });
    out.ifc = out.w->add_interface(type, ifc_name);
    std::fflush(f);
    return {};
}

Result<std::unique_ptr<Capture>> Capture::open(const std::string& dir) {
    std::unique_ptr<Capture> c(new Capture());   // NOLINT(cppcoreguidelines-owning-memory): private constructor
    for (auto [file, name] : {std::pair{&c->ngap_, "ngap"}, std::pair{&c->f1ap_, "f1ap"}, std::pair{&c->e1ap_, "e1ap"},
                              std::pair{&c->uu_, "uu"}}) {
        auto r = open_file(*file, dir + "/" + name + ".pcapng", name);
        if (!r) {
            return r.error();
        }
    }
    if (auto r = open_file(c->gtpu_, dir + "/gtpu.pcapng", "gtpu", pcap::LinkType::ipv4); !r) {
        return r.error();
    }
    if (auto r = open_file(c->sim_, dir + "/sim.pcapng", "sim", pcap::LinkType::ipv4); !r) {
        return r.error();
    }
    return c;
}

Capture::~Capture() { close(); }

void Capture::write(File& file, std::string_view dissector, ByteView pdu, const std::string& comment) {
    if (file.f == nullptr) {
        return;
    }
    (void)file.w->write(file.ifc, wall_ns(), pcap::exported_pdu(dissector, pdu), comment);
    std::fflush(file.f);
}

void Capture::ngap(bool tx, ByteView pdu) {
    auto r = ngap::redact_keys(pdu);
    const std::lock_guard lock(mu_);
    if (!r) {
        ++stats_.left_out;
        return;
    }
    stats_.keys_zeroed += r->keys;
    ++stats_.ngap;
    write(ngap_, "ngap", r->pdu, tx ? "tx" : "rx");
}

void Capture::f1ap(bool cu_tx, ByteView pdu) {
    const std::lock_guard lock(mu_);
    ++stats_.f1ap;
    write(f1ap_, "f1ap", pdu, cu_tx ? "cu->du" : "du->cu");
}

void Capture::e1ap(bool cp_tx, ByteView pdu) {
    auto r = e1ap::redact_keys(pdu);
    const std::lock_guard lock(mu_);
    if (!r) {
        ++stats_.left_out;
        return;
    }
    stats_.keys_zeroed += r->keys;
    ++stats_.e1ap;
    write(e1ap_, "e1ap", r->pdu, cp_tx ? "cp->up" : "up->cp");
}

void Capture::gtpu(const Endpoint& from, const Endpoint& to, ByteView pdu) {
    if (from.family != Endpoint::Family::v4 || to.family != Endpoint::Family::v4) {
        return;
    }
    pcap::Udp4 u;
    std::copy(from.addr.begin(), from.addr.begin() + 4, u.src.begin());
    std::copy(to.addr.begin(), to.addr.begin() + 4, u.dst.begin());
    u.src_port = from.port;
    u.dst_port = to.port;
    auto frame = pcap::ipv4_udp(u, pdu);
    const std::lock_guard lock(mu_);
    if (!frame || gtpu_.f == nullptr) {
        return;
    }
    ++stats_.gtpu;
    (void)gtpu_.w->write(gtpu_.ifc, wall_ns(), *frame);
    std::fflush(gtpu_.f);
}

void Capture::sim(std::uint8_t sub_type, ByteView payload, const std::string& supi) {
    pcap::Udp4 u;
    u.src = {127, 0, 0, 1};
    u.dst = {127, 0, 0, 1};
    u.dst_port = pcap::kGsmtapPort;
    auto frame = pcap::ipv4_udp(u, pcap::gsmtap(pcap::kGsmtapSim, sub_type, payload));
    const std::lock_guard lock(mu_);
    if (!frame || sim_.f == nullptr) {
        return;
    }
    ++stats_.sim;
    (void)sim_.w->write(sim_.ifc, wall_ns(), *frame, "imsi-" + supi);
    std::fflush(sim_.f);
}

void Capture::rrc(std::string_view channel, ByteView pdu, const std::string& supi) {
    const std::lock_guard lock(mu_);
    ++stats_.uu;
    const bool ul = channel.find(".ul.") != std::string_view::npos;
    write(uu_, channel, pdu, "imsi-" + supi + (ul ? " UL" : " DL"));
}

void Capture::nas(bool uplink, ByteView plain, const std::string& supi) {
    const std::lock_guard lock(mu_);
    ++stats_.uu;
    write(uu_, "nas-5gs", plain, "imsi-" + supi + (uplink ? " UL" : " DL"));
}

CaptureStats Capture::stats() const {
    const std::lock_guard lock(mu_);
    return stats_;
}

void Capture::close() {
    const std::lock_guard lock(mu_);
    for (File* f : {&ngap_, &f1ap_, &e1ap_, &gtpu_, &uu_, &sim_}) {
        f->w.reset();
        if (f->f != nullptr) {
            std::fclose(f->f);
            f->f = nullptr;
        }
    }
}

void TapAssoc::set_handlers(OnMessage on_message, OnEvent on_event) {
    inner_.set_handlers(
        [this, on_message = std::move(on_message)](ByteView msg, SctpMeta meta) {
            tap_(false, msg);
            if (on_message) {
                on_message(msg, meta);
            }
        },
        std::move(on_event));
}

Result<void> TapAssoc::send(ByteView msg, SctpMeta meta) {
    auto r = inner_.send(msg, meta);
    if (r) {
        tap_(true, msg);
    }
    return r;
}

void TapDatagram::set_handler(OnDatagram on_datagram) {
    inner_->set_handler([this, on_datagram = std::move(on_datagram)](ByteView payload, const Endpoint& from) {
        tap_(from, inner_->local(), payload);
        if (on_datagram) {
            on_datagram(payload, from);
        }
    });
}

Result<void> TapDatagram::send_to(ByteView payload, const Endpoint& to) {
    auto r = inner_->send_to(payload, to);
    if (r) {
        tap_(inner_->local(), to, payload);
    }
    return r;
}

} // namespace ksim::node
