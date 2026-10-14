// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/run_dir.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iterator>

#include "crypto/kdf.hpp"

namespace ksim::node {

namespace fs = std::filesystem;

Result<void> make_run_dir(const std::string& path) {
    std::error_code ec;
    const fs::path p(path);
    if (fs::exists(p, ec)) {
        if (!fs::is_directory(p, ec) || !fs::is_empty(p, ec)) {
            return make_error(Errc::invalid_argument, 0, "the run directory exists and is not empty");
        }
    } else {
        if (p.has_parent_path()) {
            fs::create_directories(p.parent_path(), ec);
        }
        if (::mkdir(path.c_str(), 0700) != 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "cannot create the run directory");
        }
    }
    if (::chmod(path.c_str(), 0700) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "cannot set the run directory's mode");
    }
    return {};
}

Result<void> write_file(const std::string& path, std::string_view content) {
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "cannot create a run file");
    }
    std::size_t done = 0;
    while (done < content.size()) {
        const ssize_t n = ::write(fd, content.data() + done, content.size() - done);
        if (n <= 0) {
            ::close(fd);
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "cannot write a run file");
        }
        done += static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "cannot rename a run file");
    }
    return {};
}

Result<std::unique_ptr<EventFile>> EventFile::open(const std::string& path) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "cannot create events.ndjson");
    }
    std::FILE* f = ::fdopen(fd, "ab");
    if (f == nullptr) {
        ::close(fd);
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "fdopen failed");
    }
    return std::unique_ptr<EventFile>(new EventFile(f));   // NOLINT(cppcoreguidelines-owning-memory): private constructor
}

EventFile::~EventFile() {
    const std::lock_guard lock(mu_);
    std::fclose(f_);
}

void EventFile::write(const Event& e) {
    std::string line = to_ndjson(e);
    line += '\n';
    const std::lock_guard lock(mu_);
    (void)std::fwrite(line.data(), 1, line.size(), f_);
    std::fflush(f_);
    ++lines_;
}

std::uint64_t EventFile::lines() const {
    const std::lock_guard lock(mu_);
    return lines_;
}

std::string file_sha256(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    const Bytes data{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    return to_hex(crypto::sha256(data));
}

} // namespace ksim::node
