// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/transport/vpcd.hpp"

#include <algorithm>
#include <utility>

namespace ksim::uicc::vpcd {

Bytes frame(ByteView payload) {
    Bytes out(payload.size() + 2);
    out[0] = static_cast<std::uint8_t>(payload.size() >> 8);
    out[1] = static_cast<std::uint8_t>(payload.size());
    std::copy(payload.begin(), payload.end(), out.begin() + 2);
    return out;
}

void Deframer::feed(ByteView data) {
    buf_.insert(buf_.end(), data.begin(), data.end());
    std::size_t at = 0;
    while (buf_.size() - at >= 2) {
        const std::size_t n = static_cast<std::size_t>(buf_[at]) << 8 | buf_[at + 1];
        if (buf_.size() - at - 2 < n) {
            break;
        }
        // Copied out first: the handler may feed again or close the stream.
        const Bytes m(buf_.begin() + static_cast<std::ptrdiff_t>(at + 2),
                      buf_.begin() + static_cast<std::ptrdiff_t>(at + 2 + n));
        at += 2 + n;
        on_message_(m);
    }
    buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(at));
}

// ---- the card side ----

VpcdCard::VpcdCard(IStream& stream, os::Card& card, Tap tap)
    : stream_(stream), card_(card), tap_(std::move(tap)), in_([this](ByteView m) { on_message(m); }) {
    stream_.set_handlers([this](ByteView d) { in_.feed(d); }, [] {});
}

VpcdCard::~VpcdCard() { stream_.set_handlers([](ByteView) {}, [] {}); }

void VpcdCard::on_message(ByteView m) {
    if (m.size() == 1) {
        switch (m[0]) {
        case kPowerOff:
            powered_ = false;
            return;
        case kPowerOn:
            if (!powered_) {
                card_.reset();
                atr_due_ = true;
            }
            powered_ = true;
            return;
        case kReset:
            powered_ = true;
            ++resets_;
            card_.reset();
            atr_due_ = true;
            return;
        case kAtr: {
            const Bytes& atr = card_.atr();
            (void)stream_.send(frame(atr));
            if (tap_ && atr_due_) {
                tap_({}, atr);
            }
            atr_due_ = false;
            return;
        }
        default:
            return;   // an unknown control code: the protocol has no answer for it
        }
    }
    if (m.empty()) {
        return;
    }
    ++apdus_;
    Bytes r = card_.process(m);
    (void)stream_.send(frame(r));
    if (tap_) {
        tap_(m, r);
    }
}

// ---- the terminal side ----

VpcdTransport::VpcdTransport(Executor& exec, std::unique_ptr<IStream> stream)
    : exec_(exec), stream_(std::move(stream)), in_([this](ByteView m) { on_message(m); }),
      alive_(std::make_shared<bool>(true)) {
    stream_->set_handlers([this](ByteView d) { in_.feed(d); },
                          [this, alive = alive_] {
                              if (*alive) {
                                  fail_all();
                              }
                          });
}

VpcdTransport::~VpcdTransport() {
    *alive_ = false;
    stream_->set_handlers([](ByteView) {}, [] {});
    stream_->close();
}

void VpcdTransport::reset(Done done) {
    queue_.push_back(Pending{{}, std::move(done), false});
    pump();
}

void VpcdTransport::transmit(Bytes capdu, Done done) {
    if (capdu.size() < 4) {
        exec_.post([done = std::move(done)] { done(make_error(Errc::invalid_argument, 0, "vpcd: a command APDU has 4 octets at least")); });
        return;
    }
    queue_.push_back(Pending{std::move(capdu), std::move(done), false});
    pump();
}

void VpcdTransport::pump() {
    if (queue_.empty() || queue_.front().sent) {
        return;
    }
    if (!stream_->open()) {
        fail_all();
        return;
    }
    Pending& p = queue_.front();
    p.sent = true;
    if (p.message.empty()) {
        (void)stream_->send(frame(Bytes{kReset}));
        (void)stream_->send(frame(Bytes{kAtr}));
    } else {
        (void)stream_->send(frame(p.message));
        secure_zero(p.message);
    }
}

void VpcdTransport::on_message(ByteView m) {
    if (queue_.empty() || !queue_.front().sent) {
        return;   // nothing asked: the card speaks only when spoken to
    }
    Done done = std::move(queue_.front().done);
    queue_.pop_front();
    exec_.post([done = std::move(done), answer = Bytes(m.begin(), m.end()), alive = alive_]() mutable {
        done(std::move(answer));
    });
    pump();
}

void VpcdTransport::fail_all() {
    while (!queue_.empty()) {
        Done done = std::move(queue_.front().done);
        queue_.pop_front();
        exec_.post([done = std::move(done)] { done(make_error(Errc::closed, 0, "vpcd: the card went away")); });
    }
}

} // namespace ksim::uicc::vpcd
