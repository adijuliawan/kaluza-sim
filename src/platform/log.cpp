// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/log.hpp"

#include <atomic>
#include <cstdio>
#include <ctime>
#include <mutex>

#include "platform/clock.hpp"
#include "platform/shard.hpp"

namespace ksim::log {

namespace {
std::atomic<Level> g_level{Level::info};
std::mutex g_mu;
std::function<void(std::string_view)> g_sink;

void to_stderr(std::string_view line) {
    std::fwrite(line.data(), 1, line.size(), stderr);
}
} // namespace

const char* level_name(Level l) noexcept {
    switch (l) {
    case Level::trace: return "T";
    case Level::debug: return "D";
    case Level::info: return "I";
    case Level::warn: return "W";
    case Level::error: return "E";
    case Level::off: return "-";
    }
    return "?";
}

void set_level(Level l) noexcept {
    g_level.store(l, std::memory_order_relaxed);
}

Level level() noexcept {
    return g_level.load(std::memory_order_relaxed);
}

void set_sink(std::function<void(std::string_view)> sink) {
    const std::lock_guard lock(g_mu);
    g_sink = std::move(sink);
}

void write(Level l, std::string_view area, std::string_view message) {
    const std::int64_t ns = realtime_ns();
    const std::time_t secs = static_cast<std::time_t>(ns / 1'000'000'000);
    std::tm tm{};
    ::gmtime_r(&secs, &tm);
    const Shard* s = Shard::current();
    std::string line = fmt::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z {} {} [{}] {}\n", tm.tm_year + 1900,
                                   tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                                   (ns / 1'000'000) % 1000, level_name(l), area,
                                   s != nullptr ? fmt::format("s{}", s->id()) : std::string("-"), message);
    const std::lock_guard lock(g_mu);
    if (g_sink) {
        g_sink(line);
    } else {
        to_stderr(line);
    }
}

} // namespace ksim::log
