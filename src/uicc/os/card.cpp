// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Clause references are to ETSI TS 102 221 V18.4.0 unless stated otherwise.

#include "uicc/os/card.hpp"

#include <algorithm>
#include <utility>

#include "codec/uicc/fcp.hpp"
#include "uicc/os/keyfile.hpp"

namespace ksim::uicc::os {

namespace {

// Status words (§10.2.1).
constexpr std::uint16_t kOk = 0x9000;
constexpr std::uint16_t kWarnInvalidated = 0x6283;    // selected file invalidated
constexpr std::uint16_t kWarnEof = 0x6282;            // end of file reached before Le
constexpr std::uint16_t kWrongLength = 0x6700;
constexpr std::uint16_t kChannelNotSupported = 0x6881;
constexpr std::uint16_t kIncompatibleStructure = 0x6981;
constexpr std::uint16_t kSecurityNotSatisfied = 0x6982;
constexpr std::uint16_t kPinBlocked = 0x6983;
constexpr std::uint16_t kConditionsNotSatisfied = 0x6985;
constexpr std::uint16_t kNoEfSelected = 0x6986;
constexpr std::uint16_t kWrongData = 0x6A80;
constexpr std::uint16_t kNotFound = 0x6A82;
constexpr std::uint16_t kRecordNotFound = 0x6A83;
constexpr std::uint16_t kWrongP1P2 = 0x6A86;
constexpr std::uint16_t kRefNotFound = 0x6A88;
constexpr std::uint16_t kWrongOffset = 0x6B00;
constexpr std::uint16_t kInsNotSupported = 0x6D00;
constexpr std::uint16_t kClaNotSupported = 0x6E00;

Response sw(std::uint16_t s) {
    Response r;
    r.sw1 = static_cast<std::uint8_t>(s >> 8);
    r.sw2 = static_cast<std::uint8_t>(s & 0xFF);
    return r;
}

Response data_sw(Bytes data, std::uint16_t s = kOk) {
    Response r = sw(s);
    r.data = std::move(data);
    return r;
}

Response wrong_le(std::size_t exact) { return sw(static_cast<std::uint16_t>(0x6C00 | (exact & 0xFF))); }

std::size_t le_value(const Command& c) { return c.le ? *c.le : 256; }

uicc::Tlv prim(std::uint32_t tag, Bytes value) {
    uicc::Tlv t;
    t.tag = tag;
    t.tag_octets = tag > 0xFF ? 2 : 1;
    t.value = std::move(value);
    return t;
}

Bytes u16(std::size_t v) { return {static_cast<std::uint8_t>((v >> 8) & 0xFF), static_cast<std::uint8_t>(v & 0xFF)}; }

bool is_pin_ins(std::uint8_t ins) { return ins == 0x20 || ins == 0x24 || ins == 0x26 || ins == 0x28 || ins == 0x2C; }

} // namespace

Bytes make_atr(ByteView historical) {
    const std::size_t k = historical.size() > 15 ? 15 : historical.size();
    Bytes a{0x3B, static_cast<std::uint8_t>(0x90 | k), 0x96, 0x80, 0x1F, 0xC7};
    a.insert(a.end(), historical.begin(), historical.begin() + static_cast<std::ptrdiff_t>(k));
    std::uint8_t tck = 0;
    for (std::size_t i = 1; i < a.size(); ++i) {
        tck ^= a[i];
    }
    a.push_back(tck);
    return a;
}

Card::Card(std::unique_ptr<File> mf, CardConfig config) : mf_(std::move(mf)), config_(std::move(config)) {
    if (config_.channels == 0) {
        config_.channels = 1;
    }
    if (config_.atr.empty()) {
        config_.atr = make_atr(Bytes{0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x1B, 0x66, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    }
    reset();
}

Card::~Card() = default;

const Bytes& Card::reset() {
    channels_.assign(config_.channels, Channel{});
    channels_[0].open = true;
    channels_[0].df = mf_.get();
    for (auto& p : pins_) {
        p.verified = false;
    }
    return config_.atr;
}

void Card::add_application(Bytes aid, std::unique_ptr<Application> app) { apps_.emplace_back(std::move(aid), std::move(app)); }

void Card::add_pin(Pin pin) {
    for (auto& p : pins_) {
        if (p.ref == pin.ref) {
            p = std::move(pin);
            return;
        }
    }
    pins_.push_back(std::move(pin));
}

Pin* Card::pin(std::uint8_t ref) noexcept {
    for (auto& p : pins_) {
        if (p.ref == ref) {
            return &p;
        }
    }
    return nullptr;
}

bool Card::pin_condition(std::uint8_t ref) const noexcept {
    for (const auto& p : pins_) {
        if (p.ref == ref) {
            return p.verified || !p.enabled;
        }
    }
    return false;
}

Application* Card::application_of(const File* adf) const noexcept {
    if (adf == nullptr) {
        return nullptr;
    }
    for (const auto& [aid, app] : apps_) {
        const std::size_t n = std::min<std::size_t>(aid.size(), 7);   // RID and application code (TS 101 220)
        if (adf->aid.size() >= n && std::equal(aid.begin(), aid.begin() + static_cast<std::ptrdiff_t>(n), adf->aid.begin())) {
            return app.get();
        }
    }
    return nullptr;
}

File* Card::find_ef(const File& df, std::uint16_t fid) const noexcept {
    for (const File* d = &df; d != nullptr; d = d->parent) {
        if (File* f = d->child(fid); f != nullptr && !is_df(f->kind)) {
            return f;
        }
    }
    return nullptr;
}

// ---- access rules (§9.2.4; ISO/IEC 7816-4 §7.4.3, expanded format) ----------

namespace {

bool sc_satisfied(const uicc::Tlv& sc, const std::function<bool(std::uint8_t)>& pin_ok) {
    switch (sc.tag) {
    case 0x90:
        return true;   // always
    case 0x97:
        return false;  // never
    case 0xA4: {       // CRT: the key reference '83' must be verified
        const uicc::Tlv* k = sc.find(0x83);
        return k != nullptr && k->value.size() == 1 && pin_ok(k->value[0]);
    }
    case 0xA0:         // OR template
        return std::any_of(sc.children.begin(), sc.children.end(),
                           [&](const uicc::Tlv& c) { return sc_satisfied(c, pin_ok); });
    case 0xAF:         // AND template
        return !sc.children.empty() && std::all_of(sc.children.begin(), sc.children.end(),
                                                   [&](const uicc::Tlv& c) { return sc_satisfied(c, pin_ok); });
    default:
        return false;
    }
}

} // namespace

bool Card::allowed(const File& f, std::uint8_t mode) const {
    if (f.arr.fid == 0) {
        return true;
    }
    const File* home = is_df(f.kind) ? &f : f.parent;
    const File* arr = home != nullptr ? find_ef(*home, f.arr.fid) : nullptr;
    if (arr == nullptr || f.arr.record == 0 || f.arr.record > arr->records.size()) {
        return false;
    }
    Bytes rec = arr->records[f.arr.record - 1];
    while (!rec.empty() && (rec.back() == 0xFF || rec.back() == 0x00)) {
        rec.pop_back();   // the unused tail of the record
    }
    auto objs = uicc::decode_ber(rec);
    if (!objs) {
        return false;
    }
    const auto pin_ok = [this](std::uint8_t ref) { return pin_condition(ref); };
    // Each rule is an AM_DO ('80': the access mode byte) followed by one or
    // more SC_DOs, any of which grants it.
    for (std::size_t i = 0; i < objs->size(); ++i) {
        const auto& am = (*objs)[i];
        if (am.tag != 0x80 || am.value.size() != 1 || (am.value[0] & mode) == 0) {
            continue;
        }
        for (std::size_t j = i + 1; j < objs->size() && (*objs)[j].tag != 0x80; ++j) {
            if (sc_satisfied((*objs)[j], pin_ok)) {
                return true;
            }
        }
    }
    return false;
}

// ---- the FCP (§11.1.1.3) ------------------------------------------------------

Bytes Card::fcp(const File& f) const {
    uicc::Tlv root;
    root.tag = 0x62;
    switch (f.kind) {
    case Kind::mf:
    case Kind::df:
    case Kind::adf:
        root.children.push_back(prim(0x82, {0x78, 0x21}));
        break;
    case Kind::transparent:
        root.children.push_back(prim(0x82, {0x41, 0x21}));
        break;
    case Kind::linear_fixed:
    case Kind::cyclic: {
        Bytes d{static_cast<std::uint8_t>(f.kind == Kind::cyclic ? 0x46 : 0x42), 0x21};
        const Bytes rl = u16(f.record_len);
        d.insert(d.end(), rl.begin(), rl.end());
        d.push_back(static_cast<std::uint8_t>(f.records.size()));
        root.children.push_back(prim(0x82, std::move(d)));
        break;
    }
    }
    root.children.push_back(prim(0x83, u16(f.fid)));
    if (f.kind == Kind::adf) {
        root.children.push_back(prim(0x84, f.aid));
    }
    if (f.kind == Kind::mf) {
        uicc::Tlv a5;
        a5.tag = 0xA5;
        a5.children.push_back(prim(0x80, {0x71}));   // UICC characteristics (§11.1.1.4.6.1)
        root.children.push_back(std::move(a5));
    }
    root.children.push_back(prim(0x8A, {f.lcs}));
    if (f.arr.fid != 0) {
        Bytes a = u16(f.arr.fid);
        a.push_back(f.arr.record);
        root.children.push_back(prim(0x8B, std::move(a)));
    }
    if (is_df(f.kind)) {
        // The PIN status template DO (§9.5.2): PS_DO's bit b8 is the first key
        // reference listed, b7 the next; a set bit is an enabled PIN.
        // 'C6' has the primitive bit in its tag, so its DOs are its value's octets.
        std::uint8_t ps = 0;
        Bytes refs;
        std::uint8_t bit = 0x80;
        for (const auto& p : pins_) {
            if (p.enabled) {
                ps |= bit;
            }
            bit = static_cast<std::uint8_t>(bit >> 1);
            refs.insert(refs.end(), {0x83, 0x01, p.ref});
        }
        Bytes c6{0x90, 0x01, ps};
        c6.insert(c6.end(), refs.begin(), refs.end());
        root.children.push_back(prim(0xC6, std::move(c6)));
    } else {
        root.children.push_back(prim(0x80, u16(f.size())));
        root.children.push_back(prim(0x88, f.sfi ? Bytes{static_cast<std::uint8_t>(*f.sfi << 3)} : Bytes{}));
    }
    auto enc = uicc::encode_ber({root});
    return enc ? *enc : Bytes{};
}

// ---- dispatch ------------------------------------------------------------------

Bytes Card::process(ByteView capdu) {
    auto c = uicc::decode_command(capdu);
    if (!c) {
        return uicc::encode_response(sw(kWrongLength));
    }
    Response r = process(*c);
    if (is_pin_ins(c->ins) || c->ins == 0xD6) {
        secure_zero(c->data);   // PINs, PUKs, and what an update may carry to a key file
    }
    Bytes out = uicc::encode_response(r);
    secure_zero(r.data);        // AUTHENTICATE's CK and IK pass through here
    return out;
}

Response Card::process(const Command& c) {
    const auto cla = uicc::decode_cla(c.cla);
    if (!cla || cla->coding == uicc::ClaInfo::Coding::gsm) {
        return sw(kClaNotSupported);   // 'A0' is TS 51.011's class, not a UICC's
    }
    if (cla->channel >= channels_.size() || !channels_[cla->channel].open) {
        return sw(kChannelNotSupported);
    }
    Channel& ch = channels_[cla->channel];
    if (c.ins == 0xC0) {   // GET RESPONSE (§11.1.18)
        if (ch.pending.empty()) {
            return sw(kConditionsNotSatisfied);
        }
        const std::size_t want = le_value(c);
        if (want > ch.pending.size()) {
            return wrong_le(ch.pending.size());
        }
        Bytes out(ch.pending.begin(), ch.pending.begin() + static_cast<std::ptrdiff_t>(want));
        secure_zero(std::span<std::uint8_t>(ch.pending.data(), want));
        ch.pending.erase(ch.pending.begin(), ch.pending.begin() + static_cast<std::ptrdiff_t>(want));
        if (!ch.pending.empty()) {
            return data_sw(std::move(out), static_cast<std::uint16_t>(0x6100 | (ch.pending.size() >= 256 ? 0 : ch.pending.size())));
        }
        return data_sw(std::move(out));
    }
    secure_zero(ch.pending);
    ch.pending.clear();
    Response r = dispatch(ch, c);
    if (config_.t0 && !r.data.empty() && !c.le && (r.sw1 == 0x90 || r.sw1 == 0x62 || r.sw1 == 0x63)) {
        // Case 4 under T=0 (§7.3.1.1.4): the data waits for GET RESPONSE.
        ch.pending = std::move(r.data);
        r.data.clear();
        r.sw1 = 0x61;
        r.sw2 = static_cast<std::uint8_t>(ch.pending.size() >= 256 ? 0 : ch.pending.size());
    } else if (c.le && r.data.size() > le_value(c)) {
        r.data.resize(le_value(c));
    }
    return r;
}

Response Card::dispatch(Channel& ch, const Command& c) {
    if (Application* app = application_of(ch.app)) {
        if (auto r = app->handle(*this, ch, c)) {
            return *r;
        }
    }
    const bool proprietary = (c.cla & 0x80) != 0;
    if (proprietary) {
        switch (c.ins) {
        case 0x10:   // TERMINAL PROFILE (§11.2.1)
            return sw(kOk);
        case 0xF2:   // STATUS
            return status(ch, c);
        default:
            return sw(kInsNotSupported);   // GET IDENTITY without a USIM, FETCH and ENVELOPE (no USAT in P1)
        }
    }
    switch (c.ins) {
    case 0xA4:
        return select(ch, c);
    case 0xB0:
        return read_binary(ch, c);
    case 0xD6:
        return update_binary(ch, c);
    case 0xB2:
        return read_record(ch, c);
    case 0xDC:
        return update_record(ch, c);
    case 0xA2:
        return search_record(ch, c);
    case 0x70:
        return manage_channel(ch, c);
    case 0x20:
    case 0x24:
    case 0x26:
    case 0x28:
    case 0x2C:
        return pin_command(ch, c);
    case 0x44:
        return activation(ch, c, true);
    case 0x04:
        return activation(ch, c, false);
    case 0x88:
        return sw(kConditionsNotSatisfied);   // AUTHENTICATE with no application selected
    default:
        return sw(kInsNotSupported);
    }
}

// ---- SELECT (§11.1.1) and STATUS (§11.1.2) ----------------------------------------

Response Card::select(Channel& ch, const Command& c) {
    File* target = nullptr;
    switch (c.p1) {
    case 0x00: {   // by file identifier (§8.4.1)
        if (c.data.empty()) {
            target = mf_.get();
            break;
        }
        if (c.data.size() != 2) {
            return sw(kWrongLength);
        }
        const auto fid = static_cast<std::uint16_t>((c.data[0] << 8) | c.data[1]);
        File* cur = ch.df != nullptr ? ch.df : mf_.get();
        if (fid == 0x3F00) {
            target = mf_.get();
        } else if (fid == 0x7FFF) {
            target = ch.app;
        } else if (fid == cur->fid) {
            target = cur;
        } else if (File* k = cur->child(fid)) {
            target = k;
        } else if (cur->parent != nullptr && cur->parent->fid == fid) {
            target = cur->parent;
        } else if (cur->parent != nullptr) {
            File* s = cur->parent->child(fid);
            target = s != nullptr && is_df(s->kind) ? s : nullptr;
        }
        break;
    }
    case 0x04: {   // by DF name: an application's AID, matched on its first octets
        if (c.data.empty() || c.data.size() > 16) {
            return sw(kWrongLength);
        }
        for (const auto& k : mf_->children) {
            if (k->kind == Kind::adf && k->aid.size() >= c.data.size() &&
                std::equal(c.data.begin(), c.data.end(), k->aid.begin())) {
                target = k.get();
                break;
            }
        }
        break;
    }
    case 0x08:     // by path from the MF
    case 0x09: {   // by path from the current DF
        if (c.data.empty() || c.data.size() % 2 != 0) {
            return sw(kWrongLength);
        }
        File* at = c.p1 == 0x08 ? mf_.get() : (ch.df != nullptr ? ch.df : mf_.get());
        for (std::size_t i = 0; i < c.data.size() && at != nullptr; i += 2) {
            const auto fid = static_cast<std::uint16_t>((c.data[i] << 8) | c.data[i + 1]);
            if (i == 0 && c.p1 == 0x08 && fid == 0x3F00) {
                continue;   // a path may start with the MF itself
            }
            if (fid == 0x7FFF && ch.app != nullptr) {
                at = ch.app;
                continue;
            }
            at = is_df(at->kind) ? at->child(fid) : nullptr;
        }
        target = at;
        break;
    }
    default:
        return sw(kWrongP1P2);
    }
    if (target == nullptr) {
        return sw(kNotFound);
    }
    if (is_df(target->kind)) {
        ch.df = target;
        ch.ef = nullptr;
        if (target->kind == Kind::adf) {
            ch.app = target;
        }
    } else {
        ch.ef = target;
        ch.df = target->parent;
    }
    ch.record = 0;
    const std::uint16_t status_word = target->lcs == kLcsDeactivated ? kWarnInvalidated : kOk;
    if ((c.p2 & 0x0C) == 0x0C) {
        return sw(status_word);
    }
    return data_sw(fcp(*target), status_word);
}

Response Card::status(Channel& ch, const Command& c) {
    File* cur = ch.df != nullptr ? ch.df : mf_.get();
    switch (c.p2) {
    case 0x00:
        return data_sw(fcp(*cur));
    case 0x01:   // the current application's DF name as a TLV
        if (ch.app == nullptr) {
            return sw(kOk);
        }
        {
            Bytes out{0x84, static_cast<std::uint8_t>(ch.app->aid.size())};
            out.insert(out.end(), ch.app->aid.begin(), ch.app->aid.end());
            return data_sw(std::move(out));
        }
    case 0x0C:
        return sw(kOk);
    default:
        return sw(kWrongP1P2);
    }
}

// ---- transparent EFs (§11.1.3, §11.1.4) ---------------------------------------

File* Card::addressed_ef(Channel& ch, std::optional<std::uint8_t> sfi, std::uint16_t& status_word) const {
    if (sfi) {
        File* df = ch.df != nullptr ? ch.df : mf_.get();
        File* f = df->child_by_sfi(*sfi);
        if (f == nullptr) {
            status_word = kNotFound;
            return nullptr;
        }
        ch.ef = f;
        ch.record = 0;
        return f;
    }
    if (ch.ef == nullptr) {
        status_word = kNoEfSelected;
    }
    return ch.ef;
}

Response Card::read_binary(Channel& ch, const Command& c) {
    std::uint16_t status_word = kOk;
    const bool by_sfi = (c.p1 & 0x80) != 0;
    File* f = addressed_ef(ch, by_sfi ? std::optional<std::uint8_t>(c.p1 & 0x1F) : std::nullopt, status_word);
    if (f == nullptr) {
        return sw(status_word);
    }
    if (f->kind != Kind::transparent) {
        return sw(kIncompatibleStructure);
    }
    if (f->secret || !allowed(*f, 0x01)) {
        return sw(kSecurityNotSatisfied);
    }
    if (f->lcs == kLcsDeactivated) {
        return sw(kConditionsNotSatisfied);
    }
    const std::size_t offset = by_sfi ? c.p2 : static_cast<std::size_t>(((c.p1 & 0x7F) << 8) | c.p2);
    if (offset > f->data.size()) {
        return sw(kWrongOffset);
    }
    const std::size_t avail = f->data.size() - offset;
    const std::size_t want = le_value(c);
    if (want > avail) {
        if (config_.t0 && avail > 0) {
            return wrong_le(avail);
        }
        return data_sw(Bytes(f->data.begin() + static_cast<std::ptrdiff_t>(offset), f->data.end()), kWarnEof);
    }
    return data_sw(Bytes(f->data.begin() + static_cast<std::ptrdiff_t>(offset),
                         f->data.begin() + static_cast<std::ptrdiff_t>(offset + want)));
}

Response Card::update_binary(Channel& ch, const Command& c) {
    std::uint16_t status_word = kOk;
    const bool by_sfi = (c.p1 & 0x80) != 0;
    File* f = addressed_ef(ch, by_sfi ? std::optional<std::uint8_t>(c.p1 & 0x1F) : std::nullopt, status_word);
    if (f == nullptr) {
        return sw(status_word);
    }
    if (f->kind != Kind::transparent) {
        return sw(kIncompatibleStructure);
    }
    if (!allowed(*f, 0x02)) {
        return sw(kSecurityNotSatisfied);
    }
    if (f->lcs == kLcsDeactivated) {
        return sw(kConditionsNotSatisfied);
    }
    const std::size_t offset = by_sfi ? c.p2 : static_cast<std::size_t>(((c.p1 & 0x7F) << 8) | c.p2);
    if (offset + c.data.size() > f->size()) {
        return sw(offset > f->size() ? kWrongOffset : kWrongLength);
    }
    if (f->secret) {
        write_key_file(*f, offset, c.data);
    } else {
        std::copy(c.data.begin(), c.data.end(), f->data.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    changed();
    return sw(kOk);
}

// ---- record EFs (§11.1.5 – §11.1.7) ----------------------------------------------

Response Card::read_record(Channel& ch, const Command& c) {
    std::uint16_t status_word = kOk;
    const std::uint8_t sfi = c.p2 >> 3;
    File* f = addressed_ef(ch, sfi != 0 ? std::optional<std::uint8_t>(sfi) : std::nullopt, status_word);
    if (f == nullptr) {
        return sw(status_word);
    }
    if (!is_record(f->kind)) {
        return sw(kIncompatibleStructure);
    }
    if (!allowed(*f, 0x01)) {
        return sw(kSecurityNotSatisfied);
    }
    const std::size_t n = f->records.size();
    std::size_t rec = 0;
    switch (c.p2 & 0x07) {
    case 0x04:   // absolute, or the current record when P1 is 0
        rec = c.p1 != 0 ? c.p1 : ch.record;
        break;
    case 0x02:   // next
        rec = ch.record < n ? ch.record + 1 : (f->kind == Kind::cyclic ? 1 : 0);
        break;
    case 0x03:   // previous
        rec = ch.record > 1 ? ch.record - 1 : (ch.record == 0 || f->kind == Kind::cyclic ? n : 0);
        break;
    default:
        return sw(kWrongP1P2);
    }
    if (rec == 0 || rec > n) {
        return sw(kRecordNotFound);
    }
    if (c.le && le_value(c) != f->record_len) {
        return wrong_le(f->record_len);
    }
    ch.record = rec;
    return data_sw(f->records[rec - 1]);
}

Response Card::update_record(Channel& ch, const Command& c) {
    std::uint16_t status_word = kOk;
    const std::uint8_t sfi = c.p2 >> 3;
    File* f = addressed_ef(ch, sfi != 0 ? std::optional<std::uint8_t>(sfi) : std::nullopt, status_word);
    if (f == nullptr) {
        return sw(status_word);
    }
    if (!is_record(f->kind)) {
        return sw(kIncompatibleStructure);
    }
    if (!allowed(*f, 0x02)) {
        return sw(kSecurityNotSatisfied);
    }
    if (c.data.size() != f->record_len) {
        return sw(kWrongLength);
    }
    const std::size_t n = f->records.size();
    const std::uint8_t mode = c.p2 & 0x07;
    if (f->kind == Kind::cyclic) {
        // Only PREVIOUS: the oldest record is overwritten and becomes record 1.
        if (mode != 0x03 || n == 0) {
            return sw(kWrongP1P2);
        }
        f->records.pop_back();
        f->records.insert(f->records.begin(), c.data);
        ch.record = 1;
    } else {
        std::size_t rec = 0;
        switch (mode) {
        case 0x04:
            rec = c.p1 != 0 ? c.p1 : ch.record;
            break;
        case 0x02:
            rec = ch.record < n ? ch.record + 1 : 0;
            break;
        case 0x03:
            rec = ch.record > 1 ? ch.record - 1 : (ch.record == 0 ? n : 0);
            break;
        default:
            return sw(kWrongP1P2);
        }
        if (rec == 0 || rec > n) {
            return sw(kRecordNotFound);
        }
        f->records[rec - 1] = c.data;
        ch.record = rec;
    }
    changed();
    return sw(kOk);
}

Response Card::search_record(Channel& ch, const Command& c) {
    std::uint16_t status_word = kOk;
    const std::uint8_t sfi = c.p2 >> 3;
    File* f = addressed_ef(ch, sfi != 0 ? std::optional<std::uint8_t>(sfi) : std::nullopt, status_word);
    if (f == nullptr) {
        return sw(status_word);
    }
    if (!is_record(f->kind)) {
        return sw(kIncompatibleStructure);
    }
    if (!allowed(*f, 0x01)) {
        return sw(kSecurityNotSatisfied);
    }
    if (c.data.empty()) {
        return sw(kWrongLength);
    }
    const std::uint8_t mode = c.p2 & 0x07;
    if (mode != 0x04 && mode != 0x05) {
        return sw(kWrongP1P2);   // simple search forward (100) and backward (101) from P1
    }
    const std::size_t n = f->records.size();
    const std::size_t start = c.p1 != 0 ? c.p1 : 1;
    if (start > n) {
        return sw(kRecordNotFound);
    }
    Bytes hits;
    auto matches = [&](std::size_t rec) {
        const Bytes& r = f->records[rec - 1];
        return std::search(r.begin(), r.end(), c.data.begin(), c.data.end()) != r.end();
    };
    if (mode == 0x04) {
        for (std::size_t r = start; r <= n; ++r) {
            if (matches(r)) {
                hits.push_back(static_cast<std::uint8_t>(r));
            }
        }
    } else {
        for (std::size_t r = start; r >= 1; --r) {
            if (matches(r)) {
                hits.push_back(static_cast<std::uint8_t>(r));
            }
        }
    }
    if (hits.empty()) {
        return sw(kRecordNotFound);
    }
    ch.record = hits.front();
    return data_sw(std::move(hits));
}

// ---- MANAGE CHANNEL (§11.1.17) ------------------------------------------------------

Response Card::manage_channel(Channel& ch, const Command& c) {
    (void)ch;
    if (c.p1 == 0x00) {   // open
        std::size_t n = c.p2;
        if (n == 0) {
            for (n = 1; n < channels_.size() && channels_[n].open; ++n) {
            }
            if (n == channels_.size()) {
                return sw(kChannelNotSupported);
            }
        } else if (n >= channels_.size() || channels_[n].open) {
            return sw(kWrongP1P2);
        }
        channels_[n] = Channel{};
        channels_[n].open = true;
        channels_[n].df = mf_.get();
        return c.p2 == 0 ? data_sw(Bytes{static_cast<std::uint8_t>(n)}) : sw(kOk);
    }
    if (c.p1 == 0x80) {   // close
        if (c.p2 == 0 || c.p2 >= channels_.size() || !channels_[c.p2].open) {
            return sw(kWrongP1P2);
        }
        channels_[c.p2] = Channel{};
        return sw(kOk);
    }
    return sw(kWrongP1P2);
}

// ---- the PIN commands (§11.1.9 – §11.1.13) --------------------------------------------

Response Card::pin_command(Channel& ch, const Command& c) {
    (void)ch;
    Pin* p = pin(c.p2);
    if (p == nullptr) {
        return sw(kRefNotFound);
    }
    const auto remaining = [](std::uint8_t tries) { return sw(static_cast<std::uint16_t>(0x63C0 | (tries & 0x0F))); };
    const auto check = [&](ByteView given) -> std::optional<Response> {
        if (p->tries == 0) {
            return sw(kPinBlocked);
        }
        if (!ct_equal(p->value, given)) {
            --p->tries;
            p->verified = false;
            changed();
            return remaining(p->tries);
        }
        p->tries = p->max_tries;
        return std::nullopt;
    };
    switch (c.ins) {
    case 0x20:   // VERIFY
        if (c.data.empty()) {
            return p->tries == 0 ? sw(kPinBlocked) : (p->verified || !p->enabled ? sw(kOk) : remaining(p->tries));
        }
        if (c.data.size() != 8) {
            return sw(kWrongLength);
        }
        if (auto r = check(c.data)) {
            return *r;
        }
        p->verified = true;
        changed();
        return sw(kOk);
    case 0x24:   // CHANGE PIN: old, then new
        if (c.data.size() != 16) {
            return sw(kWrongLength);
        }
        if (!p->enabled) {
            return sw(kConditionsNotSatisfied);
        }
        if (auto r = check(ByteView(c.data.data(), 8))) {
            return *r;
        }
        p->value = SecretBytes::copy_of(ByteView(c.data.data() + 8, 8));
        p->verified = true;
        changed();
        return sw(kOk);
    case 0x26:   // DISABLE PIN
    case 0x28: { // ENABLE PIN
        if (c.data.size() != 8) {
            return sw(kWrongLength);
        }
        if (p->ref == kAdm1) {
            return sw(kConditionsNotSatisfied);   // ADM1 cannot be disabled
        }
        const bool enable = c.ins == 0x28;
        if (p->enabled == enable) {
            return sw(kConditionsNotSatisfied);
        }
        if (auto r = check(c.data)) {
            return *r;
        }
        p->enabled = enable;
        p->verified = true;
        changed();
        return sw(kOk);
    }
    case 0x2C:   // UNBLOCK PIN: the PUK, then the new PIN
        if (p->unblock.empty()) {
            return sw(kConditionsNotSatisfied);
        }
        if (c.data.empty()) {
            return remaining(p->unblock_tries);
        }
        if (c.data.size() != 16) {
            return sw(kWrongLength);
        }
        if (p->unblock_tries == 0) {
            return sw(kPinBlocked);
        }
        if (!ct_equal(p->unblock, ByteView(c.data.data(), 8))) {
            --p->unblock_tries;
            changed();
            return remaining(p->unblock_tries);
        }
        p->unblock_tries = p->max_unblock_tries;
        p->value = SecretBytes::copy_of(ByteView(c.data.data() + 8, 8));
        p->tries = p->max_tries;
        p->verified = true;
        changed();
        return sw(kOk);
    default:
        return sw(kInsNotSupported);
    }
}

// ---- ACTIVATE / DEACTIVATE FILE (§11.1.14, §11.1.15) ----------------------------------

Response Card::activation(Channel& ch, const Command& c, bool activate) {
    File* f = ch.ef;
    if (!c.data.empty()) {
        if (c.p1 != 0x00 || c.data.size() != 2) {
            return sw(kWrongData);
        }
        const auto fid = static_cast<std::uint16_t>((c.data[0] << 8) | c.data[1]);
        File* df = ch.df != nullptr ? ch.df : mf_.get();
        f = df->child(fid);
        if (f == nullptr) {
            return sw(kNotFound);
        }
        ch.ef = is_df(f->kind) ? nullptr : f;
    }
    if (f == nullptr) {
        return sw(kNoEfSelected);
    }
    if (!allowed(*f, activate ? 0x10 : 0x08)) {
        return sw(kSecurityNotSatisfied);
    }
    f->lcs = activate ? kLcsActivated : kLcsDeactivated;
    changed();
    return sw(kOk);
}

} // namespace ksim::uicc::os
