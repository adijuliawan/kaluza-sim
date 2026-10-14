// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The log façade (plan M13): levels, an area tag, the shard of the calling
// thread, fmt formatting, and one sink (stderr by default). quill replaces the
// sink later without touching call sites. SecretBytes has no formatter, so a
// key cannot be passed to a log call at all (requirements §3.6).

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include <fmt/format.h>

namespace ksim::log {

enum class Level : std::uint8_t { trace, debug, info, warn, error, off };

const char* level_name(Level l) noexcept;

void set_level(Level l) noexcept;
Level level() noexcept;
inline bool enabled(Level l) noexcept { return l >= level(); }

/// Where finished lines go; nullptr restores stderr. Not for use while other
/// threads log.
void set_sink(std::function<void(std::string_view line)> sink);

/// "2026-10-14T12:00:00.123Z I area [s3] message": UTC, level letter, area,
/// the calling thread's shard (or '-'), the message.
void write(Level l, std::string_view area, std::string_view message);

template <class... Args>
void log(Level l, std::string_view area, fmt::format_string<Args...> f, Args&&... args) {
    if (enabled(l)) {
        write(l, area, fmt::format(f, std::forward<Args>(args)...));
    }
}

template <class... Args>
void info(std::string_view area, fmt::format_string<Args...> f, Args&&... args) {
    log(Level::info, area, f, std::forward<Args>(args)...);
}
template <class... Args>
void warn(std::string_view area, fmt::format_string<Args...> f, Args&&... args) {
    log(Level::warn, area, f, std::forward<Args>(args)...);
}
template <class... Args>
void error(std::string_view area, fmt::format_string<Args...> f, Args&&... args) {
    log(Level::error, area, f, std::forward<Args>(args)...);
}
template <class... Args>
void debug(std::string_view area, fmt::format_string<Args...> f, Args&&... args) {
    log(Level::debug, area, f, std::forward<Args>(args)...);
}

} // namespace ksim::log
