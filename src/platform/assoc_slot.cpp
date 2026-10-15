// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/assoc_slot.hpp"

#include <utility>

namespace ksim {

AssocSlot::~AssocSlot() = default;

bool AssocSlot::take(std::unique_ptr<IAssoc> a) {
    retired_.clear();
    if (!a) {
        return false;
    }
    if (cur_ && cur_->up()) {
        ++refused_;
        a->abort();
        return false;
    }
    if (cur_) {
        retired_.push_back(std::move(cur_));
    }
    cur_ = std::move(a);
    ++taken_;
    cur_->set_handlers(
        [this](ByteView msg, SctpMeta meta) {
            if (on_message_) {
                on_message_(msg, meta);
            }
        },
        [this](LinkEvent e) {
            if (on_event_) {
                on_event_(e);
            }
        });
    if (on_event_) {
        on_event_(LinkEvent::up);
    }
    return true;
}

void AssocSlot::set_handlers(OnMessage on_message, OnEvent on_event) {
    on_message_ = std::move(on_message);
    on_event_ = std::move(on_event);
}

Result<void> AssocSlot::send(ByteView msg, SctpMeta meta) {
    if (!cur_) {
        return make_error(Errc::closed, 0, "assoc: no peer has associated");
    }
    return cur_->send(msg, meta);
}

bool AssocSlot::up() const noexcept { return cur_ && cur_->up(); }
std::uint16_t AssocSlot::out_streams() const noexcept { return cur_ ? cur_->out_streams() : 0; }
std::uint16_t AssocSlot::in_streams() const noexcept { return cur_ ? cur_->in_streams() : 0; }

void AssocSlot::shutdown() {
    if (cur_) {
        cur_->shutdown();
    }
}

void AssocSlot::abort() {
    if (cur_) {
        cur_->abort();
    }
}

Endpoint AssocSlot::peer() const { return cur_ ? cur_->peer() : Endpoint{}; }

} // namespace ksim
