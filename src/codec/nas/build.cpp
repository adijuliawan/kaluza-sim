// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/nas/build.hpp"

#include <algorithm>
#include <string>

namespace ksim::nas {

namespace {

bool ends_with(std::string_view s, std::string_view tail) {
    return s.size() >= tail.size() && s.substr(s.size() - tail.size()) == tail;
}

std::ptrdiff_t index_of(const Message& m, const IeDesc* d) { return d - m.desc->ies; }

} // namespace

Result<Message> make(Epd epd, std::uint8_t type) {
    const MsgDesc* desc = find_message(epd, type);
    if (desc == nullptr) {
        return make_error(Errc::invalid_argument, type, "nas: no such message type");
    }
    Message m;
    m.desc = desc;
    for (std::size_t i = 0; i < desc->ie_count; ++i) {
        const IeDesc& d = desc->ies[i];
        const std::string_view name = d.name;
        Bytes value;
        if (name == "Extended protocol discriminator") {
            value = {static_cast<std::uint8_t>(epd)};
        } else if (name == "Security header type" || name == "Spare half octet" || name == "PDU session ID" ||
                   name == "PTI") {
            value = {0x00};
        } else if (ends_with(name, "message identity")) {
            value = {type};
        } else {
            continue;
        }
        Ie ie;
        ie.desc = &d;
        ie.value = std::move(value);
        m.ies.push_back(std::move(ie));
    }
    return m;
}

Result<void> set(Message& m, std::string_view name, Bytes value) {
    if (m.desc == nullptr) {
        return make_error(Errc::invalid_argument, 0, "nas: no message descriptor");
    }
    const IeDesc* d = nullptr;
    for (std::size_t i = 0; i < m.desc->ie_count; ++i) {
        if (name == m.desc->ies[i].name) {
            d = &m.desc->ies[i];
            break;
        }
    }
    if (d == nullptr) {
        return make_error(Errc::invalid_argument, 0, "nas: the message has no IE of that name");
    }
    for (auto& ie : m.ies) {
        if (ie.desc == d) {
            ie.value = std::move(value);
            return {};
        }
    }
    Ie ie;
    ie.desc = d;
    ie.iei = d->iei;
    ie.value = std::move(value);
    const auto at = std::find_if(m.ies.begin(), m.ies.end(), [&](const Ie& e) {
        return e.desc != nullptr && index_of(m, e.desc) > index_of(m, d);
    });
    m.ies.insert(at, std::move(ie));
    return {};
}

void unset(Message& m, std::string_view name) {
    m.ies.erase(std::remove_if(m.ies.begin(), m.ies.end(),
                               [&](const Ie& e) { return e.desc != nullptr && name == e.desc->name; }),
                m.ies.end());
}

const Bytes* get(const Message& m, std::string_view name) noexcept {
    const Ie* ie = m.find(name);
    return ie != nullptr ? &ie->value : nullptr;
}

std::vector<std::string_view> missing_mandatory(const Message& m) {
    std::vector<std::string_view> out;
    if (m.desc == nullptr) {
        return out;
    }
    for (std::size_t i = 0; i < m.desc->ie_count; ++i) {
        const IeDesc& d = m.desc->ies[i];
        if (d.presence != Presence::m) {
            continue;
        }
        const bool present = std::any_of(m.ies.begin(), m.ies.end(), [&](const Ie& e) { return e.desc == &d; });
        if (!present) {
            out.emplace_back(d.name);
        }
    }
    return out;
}

} // namespace ksim::nas
