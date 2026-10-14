// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/netns.hpp"

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <thread>

namespace ksim::net::netns {

namespace {

Error os(const char* what) { return make_error(Errc::io, static_cast<std::uint32_t>(errno), what); }

std::string path_of(const std::string& name) { return std::string(kDir) + "/" + name; }

/// /run/netns as a shared mount, so a namespace mounted under it shows in
/// every mount namespace that shares it (what iproute2 arranges).
Result<void> prepare_dir() {
    if (::mkdir(kDir, 0755) != 0 && errno != EEXIST) {
        return os("netns: mkdir /run/netns");
    }
    if (::mount("", kDir, "none", MS_SHARED | MS_REC, nullptr) == 0) {
        return {};
    }
    if (errno != EINVAL) {
        return os("netns: make /run/netns shared");
    }
    // Not a mount point yet: bind it on itself, then make it shared.
    if (::mount(kDir, kDir, "none", MS_BIND | MS_REC, nullptr) != 0) {
        return os("netns: bind /run/netns");
    }
    if (::mount("", kDir, "none", MS_SHARED | MS_REC, nullptr) != 0) {
        return os("netns: make /run/netns shared");
    }
    return {};
}

} // namespace

Result<void> add(const std::string& name) {
    if (auto r = prepare_dir(); !r) {
        return r;
    }
    const std::string path = path_of(name);
    const int f = ::open(path.c_str(), O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0);
    if (f < 0) {
        return os("netns: create the mount point (does the namespace exist?)");
    }
    ::close(f);
    // A thread of its own unshares, so the caller keeps its namespace.
    Result<void> out;
    std::thread t([&] {
        if (::unshare(CLONE_NEWNET) != 0) {
            out = os("netns: unshare");
            return;
        }
        if (::mount("/proc/thread-self/ns/net", path.c_str(), "none", MS_BIND, nullptr) != 0) {
            out = os("netns: bind the namespace");
        }
    });
    t.join();
    if (!out) {
        ::unlink(path.c_str());
    }
    return out;
}

Result<void> del(const std::string& name) {
    const std::string path = path_of(name);
    if (::umount2(path.c_str(), MNT_DETACH) != 0 && errno != EINVAL) {
        return os("netns: unmount");
    }
    if (::unlink(path.c_str()) != 0) {
        return os("netns: remove the mount point");
    }
    return {};
}

Result<Fd> open(const std::string& name) {
    Fd fd(::open(path_of(name).c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) {
        return os("netns: open");
    }
    return fd;
}

std::vector<std::string> list() {
    std::vector<std::string> out;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(kDir, ec)) {
        out.push_back(e.path().filename().string());
    }
    return out;
}

Result<void> run_in(int ns_fd, const std::function<Result<void>()>& fn) {
    Result<void> out;
    std::thread t([&] {
        if (::setns(ns_fd, CLONE_NEWNET) != 0) {
            out = os("netns: setns");
            return;
        }
        out = fn();
    });
    t.join();
    return out;
}

} // namespace ksim::net::netns
