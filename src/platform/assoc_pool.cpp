// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/assoc_pool.hpp"

#include <algorithm>
#include <utility>

namespace ksim {

AssocPool::~AssocPool() = default;

void AssocPool::wire(LinkId id, IAssoc& a) {
    a.set_handlers(
        [this, id](ByteView msg, SctpMeta meta) {
            if (on_message_) {
                on_message_(id, msg, meta);
            }
        },
        [this, id](LinkEvent e) {
            if (e != LinkEvent::up && e != LinkEvent::restart && e != LinkEvent::refused) {
                // A taken association that went is freed at the next take, not inside its callback.
                if (auto it = links_.find(id); it != links_.end() && it->second.owned) {
                    retired_.push_back(std::move(it->second.owned));
                    links_.erase(it);
                }
            }
            if (on_event_) {
                on_event_(id, e);
            }
        });
}

LinkId AssocPool::add(IAssoc& a) {
    const LinkId id = next_++;
    links_[id] = Link{&a, nullptr};
    wire(id, a);
    return id;
}

std::size_t AssocPool::up_count() const {
    return static_cast<std::size_t>(std::count_if(links_.begin(), links_.end(), [](const auto& l) { return l.second.a->up(); }));
}

bool AssocPool::take(std::unique_ptr<IAssoc> a) {
    retired_.clear();
    if (!a) {
        return false;
    }
    if (limit_ != 0 && up_count() >= limit_) {
        ++refused_;
        a->abort();
        return false;
    }
    const LinkId id = next_++;
    IAssoc& ref = *a;
    links_[id] = Link{&ref, std::move(a)};
    ++taken_;
    wire(id, ref);
    if (on_event_) {
        on_event_(id, LinkEvent::up);
    }
    return true;
}

void AssocPool::set_handlers(OnMessage on_message, OnEvent on_event) {
    on_message_ = std::move(on_message);
    on_event_ = std::move(on_event);
}

Result<void> AssocPool::send(LinkId link, ByteView msg, SctpMeta meta) {
    auto it = links_.find(link);
    if (it == links_.end()) {
        return make_error(Errc::closed, link, "assoc pool: no such link");
    }
    return it->second.a->send(msg, meta);
}

bool AssocPool::up(LinkId link) const noexcept {
    auto it = links_.find(link);
    return it != links_.end() && it->second.a->up();
}

std::uint16_t AssocPool::out_streams(LinkId link) const noexcept {
    auto it = links_.find(link);
    return it != links_.end() ? it->second.a->out_streams() : 0;
}

std::vector<LinkId> AssocPool::links() const {
    std::vector<LinkId> out;
    for (const auto& [id, l] : links_) {
        if (l.a->up()) {
            out.push_back(id);
        }
    }
    return out;
}

void AssocPool::shutdown_all() {
    for (auto& [id, l] : links_) {
        l.a->shutdown();
    }
}

void AssocPool::abort_all() {
    // An owned link's abort comes back as its loss, which retires it: walk a copy of the ids.
    std::vector<LinkId> ids;
    ids.reserve(links_.size());
    for (const auto& [id, l] : links_) {
        ids.push_back(id);
    }
    for (LinkId id : ids) {
        if (auto it = links_.find(id); it != links_.end()) {
            it->second.a->abort();
        }
    }
}

void AssocPool::clear() {
    links_.clear();
    retired_.clear();
}

void SingleAssocPool::set_handlers(OnMessage on_message, OnEvent on_event) {
    a_.set_handlers(
        [m = std::move(on_message)](ByteView msg, SctpMeta meta) {
            if (m) {
                m(1, msg, meta);
            }
        },
        [e = std::move(on_event)](LinkEvent ev) {
            if (e) {
                e(1, ev);
            }
        });
}

Result<void> SingleAssocPool::send(LinkId link, ByteView msg, SctpMeta meta) {
    if (link != 1) {
        return make_error(Errc::closed, link, "assoc pool: no such link");
    }
    return a_.send(msg, meta);
}

std::vector<LinkId> SingleAssocPool::links() const { return a_.up() ? std::vector<LinkId>{1} : std::vector<LinkId>{}; }

} // namespace ksim
