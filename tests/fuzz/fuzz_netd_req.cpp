// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// fuzz_netd_req (P1 N9; ADR 0009 consequences): any octets as a request to
// ksim-netd's handler, with a fake set of operations. Properties: nothing a
// peer sends ends the root helper; a request that decodes re-encodes to the
// same octets; an operation runs only on a request the policy accepted (a
// valid ksim- name, the allowed parent and address range; from P1 N11 the UE
// operations only on a listed ksim-ue- namespace with a sane device, exec
// only with its four descriptors and never as root); replies decode.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <set>

#include <unistd.h>

#include "net/netd.hpp"

namespace {

using namespace ksim::net::netd;

class FakeOps final : public INetOps {
public:
    ksim::Result<void> setup_node(const std::string& n, const std::string& parent, std::array<std::uint8_t, 4> addr,
                                  std::uint8_t) override {
        if (!valid_name(n) || (!parent.empty() && parent != "ens19") ||
            (!parent.empty() && (addr[0] != 172 || addr[1] != 30 || addr[2] != 30 || addr[3] < 30 || addr[3] > 39))) {
            std::abort();   // the policy let something through
        }
        names.insert(n);
        return {};
    }
    ksim::Result<void> teardown(const std::string& n) override {
        if (!valid_name(n) || names.count(n) == 0) {
            std::abort();
        }
        names.erase(n);
        return {};
    }
    ksim::Result<ksim::Fd> socket(const std::string& n, SockKind, int) override {
        if (!valid_name(n) || names.count(n) == 0) {
            std::abort();
        }
        return ksim::make_error(ksim::Errc::io, 0, "fake: no socket");
    }
    std::vector<std::string> list() override { return {names.begin(), names.end()}; }
    ksim::Result<void> setup_ue(const std::string& n) override {
        if (!ue_name(n)) {
            std::abort();
        }
        names.insert(n);
        return {};
    }
    ksim::Result<ksim::Fd> tun(const std::string& n, const TunSpec& t) override {
        check_tun(n, t);
        if (t.mtu < 576 || t.mtu > 9000 || t.addr[0] == 0 || t.addr[0] == 127 || t.addr[0] >= 224) {
            std::abort();
        }
        return ksim::make_error(ksim::Errc::io, 0, "fake");
    }
    ksim::Result<void> tun_down(const std::string& n, const TunSpec& t) override {
        check_tun(n, t);
        return {};
    }
    ksim::Result<void> resolv(const std::string& n, std::array<std::uint8_t, 4>) override {
        if (!ue_name(n) || names.count(n) == 0) {
            std::abort();
        }
        return {};
    }
    ksim::Result<std::uint32_t> exec(const std::string& n, const std::vector<std::string>& argv, const Peer& peer,
                                     std::vector<ksim::Fd> fds) override {
        if (!ue_name(n) || names.count(n) == 0 || argv.empty() || fds.size() != 4 || peer.uid == 0 || peer.gid == 0) {
            std::abort();
        }
        return 1;
    }
    void check_tun(const std::string& n, const TunSpec& t) const {
        const bool name = t.ifname.size() >= 4 && t.ifname.rfind("pdu", 0) == 0;
        if (!ue_name(n) || names.count(n) == 0 || !name || t.table < 101 || t.table > 115) {
            std::abort();
        }
    }
    std::set<std::string> names{"ksim-cucp", "not-ours"};
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const ksim::ByteView in(data, size);
    auto q = decode_request(in);
    if (q && encode(*q) != ksim::Bytes(in.begin(), in.end())) {
        std::abort();
    }
    FakeOps ops;
    Policy p;
    p.uid = 1000;
    p.parent = "ens19";
    p.first = {172, 30, 30, 30};
    p.last = {172, 30, 30, 39};
    p.prefix = 24;
    Server s(p, ops);
    std::optional<ksim::Fd> fd;
    const Reply r = s.handle(in, 1000, fd);
    if (!decode_reply(encode(r))) {
        std::abort();
    }
    (void)s.handle(in, 1001, fd);   // another uid: refused before anything
    // With four descriptors, as exec takes them, and a UE namespace in place.
    ops.names.insert("ksim-ue-1");
    std::vector<ksim::Fd> four;
    four.reserve(4);
    for (int i = 0; i < 4; ++i) {
        four.emplace_back(::dup(2));
    }
    (void)s.handle(in, Peer{1000, 1000}, std::move(four), fd);
    return 0;
}
