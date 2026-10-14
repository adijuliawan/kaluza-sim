// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/guard.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>

namespace ksim::node {

namespace {

constexpr std::string_view kLabHost = "kaluza-uesim";
constexpr std::array<std::string_view, 2> kCellProcesses{"gnb", "odu"};

} // namespace

std::string check_guard(const GuardInput& in) {
    for (const auto& p : in.processes) {
        if (std::find(kCellProcesses.begin(), kCellProcesses.end(), p) != kCellProcesses.end()) {
            return "a cell process (" + p + ") runs on this host; ksim does not start beside it";
        }
    }
    if (in.lab && in.host != kLabHost) {
        return "--lab is for the host kaluza-uesim only, not " + in.host;
    }
    const Endpoint lab_net = Endpoint::v4(172, 30, 0, 0, 0);
    for (const auto& a : in.addresses) {
        if (a.family == Endpoint::Family::v4 && a.in(lab_net, 16) && !in.lab) {
            return a.host() + " is in the lab network 172.30.0.0/16: only --lab on kaluza-uesim reaches it";
        }
    }
    return {};
}

std::string host_name() {
    std::array<char, 256> buf{};
    if (::gethostname(buf.data(), buf.size() - 1) != 0) {
        return {};
    }
    return std::string(buf.data());
}

std::vector<std::string> process_names() {
    std::vector<std::string> out;
    std::error_code ec;
    for (const auto& d : std::filesystem::directory_iterator("/proc", ec)) {
        const std::string pid = d.path().filename().string();
        if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos) {
            continue;
        }
        std::ifstream comm(d.path() / "comm");
        std::string name;
        if (std::getline(comm, name)) {
            out.push_back(name);
        }
    }
    return out;
}

} // namespace ksim::node
