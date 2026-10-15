// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/ue/dataplane.hpp"

#include "net/netd.hpp"
#include "net/tun.hpp"

namespace ksim::node {

namespace {

net::netd::TunSpec spec(const UeTun& t) { return {t.ifname, t.addr, t.mtu, t.table, t.main_default}; }

Error netd_error(const net::netd::Client& c, const Error& e) {
    return make_error(e.code, e.offset, c.last_error().empty() ? e.what : "ksim-netd refused or failed (see its message)");
}

} // namespace

Result<void> NetdUeNet::setup(const std::string& netns) {
    auto r = netd_.setup_ue(netns);
    if (!r && netd_.last_error() == "netd: the namespace exists") {
        (void)netd_.teardown(netns);
        r = netd_.setup_ue(netns);
    }
    if (!r) {
        return netd_error(netd_, r.error());
    }
    return {};
}

Result<std::unique_ptr<IPacketPort>> NetdUeNet::open_tun(const std::string& netns, const UeTun& t) {
    auto fd = netd_.tun(netns, spec(t));
    if (!fd) {
        return netd_error(netd_, fd.error());
    }
    auto port = net::TunPort::adopt(reactor_, std::move(*fd));
    if (!port) {
        return port.error();
    }
    return std::unique_ptr<IPacketPort>(std::move(*port));
}

void NetdUeNet::close_tun(const std::string& netns, const UeTun& t) { (void)netd_.tun_down(netns, spec(t)); }

Result<void> NetdUeNet::resolv(const std::string& netns, ip::Addr dns) {
    auto r = netd_.resolv(netns, dns);
    if (!r) {
        return netd_error(netd_, r.error());
    }
    return {};
}

void NetdUeNet::teardown(const std::string& netns) { (void)netd_.teardown(netns); }

Result<std::uint32_t> NetdUeNet::exec(const std::string& netns, const std::vector<std::string>& argv,
                                      std::vector<int> fds) {
    auto pid = netd_.exec(netns, argv, fds);
    if (!pid) {
        return netd_error(netd_, pid.error());
    }
    return *pid;
}

} // namespace ksim::node
