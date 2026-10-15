// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/trace/trace.hpp"

#include <algorithm>
#include <optional>
#include <utility>

#include "uicc/os/file.hpp"

namespace ksim::uicc::trace {

namespace {

constexpr std::uint8_t kSelect = 0xA4;
constexpr std::uint8_t kReadBinary = 0xB0;
constexpr std::uint8_t kUpdateBinary = 0xD6;
constexpr std::uint8_t kReadRecord = 0xB2;
constexpr std::uint8_t kUpdateRecord = 0xDC;
constexpr std::uint8_t kGetResponse = 0xC0;
constexpr std::uint8_t kAuthenticate = 0x88;

bool is_df(std::uint16_t fid) { return fid == 0x3F00 || fid == 0x7FF0 || fid == 0x7FFF || (fid >> 8) == 0x5F; }
bool is_pin_command(std::uint8_t ins) { return ins == 0x20 || ins == 0x24 || ins == 0x26 || ins == 0x28 || ins == 0x2C; }

std::uint8_t channel_of(std::uint8_t cla) {
    // TS 102 221 §10.1.1: the first interindustry values carry channels 0-3 in b1-b2.
    return (cla & 0x40) == 0 ? (cla & 0x03) : 0;
}

/// The command data and its offset (after Lc), for cases 3 and 4.
std::pair<std::size_t, std::size_t> data_span(ByteView c) {
    if (c.size() <= 5) {
        return {0, 0};
    }
    const std::size_t lc = c[4];
    if (c.size() < 5 + lc) {
        return {0, 0};
    }
    return {5, lc};
}

/// Zeroes CK, IK and Kc in an AUTHENTICATE answer (TS 31.102 7.1.2.1: DB L RES L CK L IK [L Kc]).
void mask_auth(Bytes& r) {
    if (r.size() < 3 || r[0] != 0xDB) {
        return;
    }
    const std::size_t body = r.size() - 2;   // SW1 SW2 stay
    std::size_t at = 1;
    if (at >= body) {
        return;
    }
    at += 1 + r[at];   // RES stays: it goes over the air anyway
    for (int field = 0; field < 3 && at < body; ++field) {
        const std::size_t n = r[at];
        const std::size_t end = std::min(body, at + 1 + n);
        std::fill(r.begin() + static_cast<std::ptrdiff_t>(at + 1), r.begin() + static_cast<std::ptrdiff_t>(end), 0x00);
        at = end;
    }
}

} // namespace

Bytes tpdu(ByteView command, ByteView response) {
    Bytes out(command.begin(), command.end());
    if (out.size() == 4) {
        out.push_back(0x00);   // case 1: P3 = 0
    } else if (out.size() > 5 && out.size() == 5 + static_cast<std::size_t>(out[4]) + 1) {
        out.pop_back();        // case 4: the response data follows instead of Le
    }
    out.insert(out.end(), response.begin(), response.end());
    return out;
}

void Redactor::reset() noexcept {
    for (auto& ch : ch_) {
        secure_zero(ch.held_cmd);
        secure_zero(ch.held_rsp);
    }
    ch_ = {};
}

std::vector<Bytes> Redactor::flush() {
    std::vector<Bytes> out;
    for (auto& ch : ch_) {
        if (!ch.held_cmd.empty()) {
            const Bytes c = std::move(ch.held_cmd);
            const Bytes r = std::move(ch.held_rsp);
            ch.held_cmd.clear();
            ch.held_rsp.clear();
            out.push_back(one(ch, c, r));
        }
    }
    return out;
}

std::vector<Bytes> Redactor::apply(ByteView command, ByteView response) {
    std::vector<Bytes> out;
    if (command.size() < 4) {
        // Not an APDU: traced as it came, and nothing at all for nothing.
        if (!command.empty() || !response.empty()) {
            out.push_back(tpdu(command, response));
        }
        return out;
    }
    Lchan& ch = ch_[channel_of(command[0])];
    const bool more = response.size() == 2 && (response[0] == 0x61 || response[0] == 0x6C);
    if (!ch.held_cmd.empty() && command[1] == kGetResponse && more) {
        ch.held_rsp.assign(response.begin(), response.end());   // the GET RESPONSE needs another go: still waiting
        return out;
    }
    if (!ch.held_cmd.empty()) {
        Bytes held_c = std::move(ch.held_cmd);
        Bytes held_r = std::move(ch.held_rsp);
        ch.held_cmd.clear();
        ch.held_rsp.clear();
        if (command[1] == kGetResponse) {
            // The command with the answer GET RESPONSE fetched (Le, if it had one, dropped).
            if (held_c.size() > 5 && held_c.size() == 5 + static_cast<std::size_t>(held_c[4]) + 1) {
                held_c.pop_back();
            }
            out.push_back(one(ch, held_c, response));
            secure_zero(held_c);
            return out;
        }
        if (held_r[0] == 0x6C && command[1] == held_c[1]) {
            secure_zero(held_c);   // sent again with the right Le: that exchange is the record
        } else {
            out.push_back(one(ch, held_c, held_r));
            secure_zero(held_c);
        }
    }
    if (more && command[1] != kGetResponse) {
        ch.held_cmd.assign(command.begin(), command.end());
        ch.held_rsp.assign(response.begin(), response.end());
        return out;
    }
    out.push_back(one(ch, command, response));
    return out;
}

bool Redactor::secret_target(const Lchan& ch, ByteView c) const {
    auto secret_fid = [](std::uint16_t f) { return os::key_fid(f); };
    const std::uint8_t ins = c[1];
    std::optional<std::uint8_t> sfi;
    if ((ins == kReadBinary || ins == kUpdateBinary) && (c[2] & 0x80) != 0) {
        sfi = static_cast<std::uint8_t>(c[2] & 0x1F);
    } else if ((ins == kReadRecord || ins == kUpdateRecord) && (c[3] >> 3) != 0) {
        sfi = static_cast<std::uint8_t>(c[3] >> 3);
    }
    if (sfi) {
        // The NAS security contexts and EF.5GAUTHKEYS have SFIs 03, 04 and 05 in
        // DF.5GS, EF.KEYS and EF.KEYSPS 08 and 09 in the ADF; in another DF.5x
        // unsure means masked.
        if (ch.df == 0x5FC0) {
            return *sfi == 0x03 || *sfi == 0x04 || *sfi == 0x05;
        }
        if (ch.df == 0x7FF0) {
            return *sfi == 0x08 || *sfi == 0x09;
        }
        return (ch.df >> 8) == 0x5F;
    }
    return secret_fid(ch.ef);
}

Bytes Redactor::one(Lchan& ch, ByteView command, ByteView response) {
    Bytes c(command.begin(), command.end());
    Bytes r(response.begin(), response.end());
    const std::uint8_t ins = c[1];
    const bool ok = r.size() >= 2 && (r[r.size() - 2] == 0x90 || r[r.size() - 2] == 0x91 || r[r.size() - 2] == 0x61);
    if (ins == kSelect && ok) {
        auto [at, n] = data_span(c);
        if (c[2] == 0x04) {
            ch.df = 0x7FF0;   // an application by its AID: the ADF
            ch.ef = 0;
        } else if (n >= 2) {
            const auto fid = static_cast<std::uint16_t>(c[at + n - 2] << 8 | c[at + n - 1]);
            if (is_df(fid)) {
                ch.df = fid;
                ch.ef = 0;
            } else {
                ch.ef = fid;
                if (n >= 4 && (c[2] == 0x08 || c[2] == 0x09)) {
                    const auto parent = static_cast<std::uint16_t>(c[at + n - 4] << 8 | c[at + n - 3]);
                    ch.df = is_df(parent) ? parent : ch.df;
                }
            }
        }
    }
    if (on_) {
        if (is_pin_command(ins)) {
            auto [at, n] = data_span(c);
            std::fill(c.begin() + static_cast<std::ptrdiff_t>(at), c.begin() + static_cast<std::ptrdiff_t>(at + n), 0xFF);
        } else if (ins == kAuthenticate) {
            mask_auth(r);
            ch.auth_pending = r.size() == 2 && r[0] == 0x61;
        } else if (ins == kGetResponse && ch.auth_pending) {
            mask_auth(r);
            ch.auth_pending = false;
        } else if ((ins == kReadBinary || ins == kReadRecord) && secret_target(ch, c)) {
            std::fill(r.begin(), r.end() - std::min<std::ptrdiff_t>(2, static_cast<std::ptrdiff_t>(r.size())), 0x00);
        } else if ((ins == kUpdateBinary || ins == kUpdateRecord) && secret_target(ch, c)) {
            auto [at, n] = data_span(c);
            std::fill(c.begin() + static_cast<std::ptrdiff_t>(at), c.begin() + static_cast<std::ptrdiff_t>(at + n), 0x00);
        }
        if (ins != kAuthenticate && ins != kGetResponse) {
            ch.auth_pending = false;
        }
    }
    Bytes out = tpdu(c, r);
    secure_zero(c);
    secure_zero(r);
    return out;
}

TracingTransport::TracingTransport(IApduTransport& inner, Sink sink, bool redact)
    : inner_(inner), sink_(std::make_shared<Sink>(std::move(sink))), redactor_(std::make_shared<Redactor>(redact)),
      count_(std::make_shared<std::size_t>(0)) {}

void TracingTransport::reset(Done done) {
    inner_.reset([sink = sink_, red = redactor_, count = count_, done = std::move(done)](Result<Bytes> atr) mutable {
        for (auto& rec : red->flush()) {
            if (*sink) {
                ++*count;
                (*sink)(kSubApdu, std::move(rec));
            }
        }
        red->reset();
        if (atr && *sink) {
            ++*count;
            (*sink)(kSubAtr, *atr);
        }
        done(std::move(atr));
    });
}

void TracingTransport::transmit(Bytes capdu, Done done) {
    Bytes copy = capdu;
    inner_.transmit(std::move(capdu), [sink = sink_, red = redactor_, count = count_, copy = std::move(copy),
                                       done = std::move(done)](Result<Bytes> r) mutable {
        if (r) {
            for (auto& rec : red->apply(copy, *r)) {   // followed even with no sink
                if (*sink) {
                    ++*count;
                    (*sink)(kSubApdu, std::move(rec));
                }
            }
        }
        secure_zero(copy);
        done(std::move(r));
    });
}

} // namespace ksim::uicc::trace
