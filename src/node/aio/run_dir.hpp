// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A run directory (P1 N8; architecture §9, verification.md §6): mode 0700, and
// in it manifest.json (build, topology hash, seed, spec and asn1c pins, the
// peer's pins), events.ndjson (every event, one JSON object per line, written
// as it is emitted), ksim.log, the captures and ctl.sock. Files are 0600.

#pragma once

#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include "platform/event.hpp"
#include "platform/result.hpp"

namespace ksim::node {

/// Creates `path` (0700; its parents as needed). An existing directory must be empty.
Result<void> make_run_dir(const std::string& path);

/// Writes `content` to `path` with mode 0600, through a temporary file and a rename.
Result<void> write_file(const std::string& path, std::string_view content);

/// Appends each event to a file as one NDJSON line, flushed at once (gates may
/// read the file while the run goes on).
class EventFile {
public:
    static Result<std::unique_ptr<EventFile>> open(const std::string& path);
    ~EventFile();
    EventFile(const EventFile&) = delete;
    EventFile& operator=(const EventFile&) = delete;

    void write(const Event& e);
    std::uint64_t lines() const;

private:
    explicit EventFile(std::FILE* f) : f_(f) {}
    mutable std::mutex mu_;
    std::FILE* f_;
    std::uint64_t lines_ = 0;
};

/// The hex SHA-256 of a file's contents, or "" if it cannot be read.
std::string file_sha256(const std::string& path);

} // namespace ksim::node
