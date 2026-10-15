// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// What a UE's data plane needs from the system (P1 N11; data-plane.md, ADR
// 0009 point 3): a namespace of its own ("ksim-ue-<index>", IPv6 off before
// any link is up, L13), a TUN device per PDU session carrying the session's
// address and link MTU with its routing table and rule, the session's DNS
// server as the namespace's resolv.conf, and commands run inside it as the
// user. NetdUeNet asks ksim-netd for each (ksim stays unprivileged); tests
// give the device an in-memory one. Without one, a UE runs in inject mode:
// its sessions carry only the packets ksim builds itself (the ping).

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "codec/ip/ipv4.hpp"
#include "platform/reactor.hpp"
#include "platform/result.hpp"
#include "platform/transport.hpp"

namespace ksim::net::netd {
class Client;
}

namespace ksim::node {

/// A session's TUN: "pdu<psi>", the UE's address, the link MTU, the table 100 + PSI,
/// and whether it also takes the namespace's main default route (the first one).
struct UeTun {
    std::string ifname;
    ip::Addr addr{};
    std::uint16_t mtu = 1500;
    std::uint8_t table = 101;
    bool main_default = false;
};

class IUeNet {
public:
    virtual ~IUeNet() = default;
    /// The namespace, made afresh (one a dead run left is replaced).
    virtual Result<void> setup(const std::string& netns) = 0;
    virtual Result<std::unique_ptr<IPacketPort>> open_tun(const std::string& netns, const UeTun& t) = 0;
    /// After the port is closed: the device is gone, its rule goes.
    virtual void close_tun(const std::string& netns, const UeTun& t) = 0;
    virtual Result<void> resolv(const std::string& netns, ip::Addr dns) = 0;
    virtual void teardown(const std::string& netns) = 0;
    /// Starts argv inside the namespace as the user; fds: stdin, stdout, stderr,
    /// the status pipe's write end. The pid (the helper's, a process group leader).
    virtual Result<std::uint32_t> exec(const std::string& netns, const std::vector<std::string>& argv,
                                       std::vector<int> fds) = 0;
};

class NetdUeNet final : public IUeNet {
public:
    NetdUeNet(net::netd::Client& netd, Reactor& reactor) : netd_(netd), reactor_(reactor) {}
    Result<void> setup(const std::string& netns) override;
    Result<std::unique_ptr<IPacketPort>> open_tun(const std::string& netns, const UeTun& t) override;
    void close_tun(const std::string& netns, const UeTun& t) override;
    Result<void> resolv(const std::string& netns, ip::Addr dns) override;
    void teardown(const std::string& netns) override;
    Result<std::uint32_t> exec(const std::string& netns, const std::vector<std::string>& argv,
                               std::vector<int> fds) override;

private:
    net::netd::Client& netd_;
    Reactor& reactor_;
};

} // namespace ksim::node
