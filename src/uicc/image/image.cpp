// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/image/image.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

#include "uicc/usim/usim.hpp"

namespace ksim::uicc::image {

namespace {

std::string fid_hex(std::uint16_t fid) {
    char b[8];
    std::snprintf(b, sizeof b, "%04X", fid);
    return b;
}

std::string hex_byte(unsigned v) {
    char b[8];
    std::snprintf(b, sizeof b, "0x%02X", v & 0xFF);
    return b;
}

std::string hex_word(unsigned v) {
    char b[8];
    std::snprintf(b, sizeof b, "0x%04X", v & 0xFFFF);
    return b;
}

std::string upper_hex(ByteView b) {
    std::string s = to_hex(b);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

Bytes hex_of(const Yaml& y) {
    auto b = from_hex(y.as<std::string>());
    if (!b) {
        y.fail("is not hex");
    }
    return *b;
}

os::Kind kind_of(const Yaml& y) {
    const std::string t = y.as<std::string>();
    if (t == "mf") return os::Kind::mf;
    if (t == "df") return os::Kind::df;
    if (t == "adf") return os::Kind::adf;
    if (t == "transparent") return os::Kind::transparent;
    if (t == "linear_fixed") return os::Kind::linear_fixed;
    if (t == "cyclic") return os::Kind::cyclic;
    y.fail("is not one of mf, df, adf, transparent, linear_fixed, cyclic");
}

const char* kind_name(os::Kind k) {
    switch (k) {
    case os::Kind::mf: return "mf";
    case os::Kind::df: return "df";
    case os::Kind::adf: return "adf";
    case os::Kind::transparent: return "transparent";
    case os::Kind::linear_fixed: return "linear_fixed";
    case os::Kind::cyclic: return "cyclic";
    }
    return "?";
}

std::unique_ptr<os::File> load_file(const Yaml& y, const secrets::SecretMap& s) {
    y.only({"fid", "name", "type", "aid", "sfi", "lcs", "arr", "data", "size", "fill", "records", "record_len",
            "record_count", "secret", "sealed", "files"});
    auto f = std::make_unique<os::File>();
    f->kind = kind_of(y.at("type"));
    f->fid = y.at("fid").as<std::uint16_t>();
    f->name = y.get<std::string>("name", "");
    f->lcs = y.get<std::uint8_t>("lcs", os::kLcsActivated);
    if (y.has("sfi")) {
        const auto sfi = y.at("sfi").as<std::uint8_t>();
        if (sfi == 0 || sfi > 30) {
            y.at("sfi").fail("an SFI is 1..30");
        }
        f->sfi = sfi;
    }
    if (y.has("arr")) {
        const Yaml a = y.at("arr");
        if (!a.is_seq() || a.size() != 2) {
            a.fail("is [EF.ARR fid, record]");
        }
        f->arr = os::ArrRef{a.at(0).as<std::uint16_t>(), a.at(1).as<std::uint8_t>()};
    }
    if (os::is_df(f->kind)) {
        if (f->kind == os::Kind::adf) {
            f->aid = hex_of(y.at("aid"));
        }
        if (y.has("files")) {
            const Yaml kids = y.at("files");
            for (std::size_t i = 0; i < kids.size(); ++i) {
                f->add(load_file(kids.at(i), s));
            }
        }
        return f;
    }
    const auto fill = y.get<std::uint8_t>("fill", 0xFF);
    const std::string sealed_name = "ef." + fid_hex(f->fid);
    if (f->kind == os::Kind::transparent) {
        f->secret = y.get<bool>("secret", false);
        Bytes data = y.has("data") ? hex_of(y.at("data")) : Bytes(y.at("size").as<std::uint32_t>(), fill);
        if (f->secret) {
            const auto size = y.has("size") ? y.at("size").as<std::uint32_t>() : static_cast<std::uint32_t>(data.size());
            if (const SecretBytes* v = s.get(sealed_name)) {
                f->secret_data = v->clone();
            } else if (f->fid == usim::kEfAuthKey && s.get("k") != nullptr && s.get("opc") != nullptr) {
                f->secret_data = secrets::milenage_auth_key(*s.get("k"), *s.get("opc"));
            } else {
                f->secret_data = SecretBytes(size);
            }
            secure_zero(data);
        } else {
            if (y.get<bool>("sealed", false)) {
                if (const SecretBytes* v = s.get(sealed_name); v != nullptr && v->size() == data.size()) {
                    data = Bytes(v->expose().begin(), v->expose().end());
                }
            }
            f->data = std::move(data);
        }
        return f;
    }
    if (y.has("records")) {
        const Yaml r = y.at("records");
        for (std::size_t i = 0; i < r.size(); ++i) {
            f->records.push_back(hex_of(r.at(i)));
        }
        f->record_len = y.has("record_len") ? y.at("record_len").as<std::uint16_t>()
                                            : static_cast<std::uint16_t>(f->records.empty() ? 0 : f->records[0].size());
        for (auto& rec : f->records) {
            if (rec.size() > f->record_len) {
                y.at("records").fail("a record is longer than record_len");
            }
            rec.resize(f->record_len, fill);
        }
    } else {
        f->record_len = y.at("record_len").as<std::uint16_t>();
        f->records.assign(y.at("record_count").as<std::uint8_t>(), Bytes(f->record_len, fill));
    }
    if (y.get<bool>("sealed", false)) {
        if (const SecretBytes* v = s.get(sealed_name); v != nullptr && v->size() == f->size()) {
            const ByteView b = v->expose();
            for (std::size_t i = 0; i < f->records.size(); ++i) {
                f->records[i].assign(b.begin() + static_cast<std::ptrdiff_t>(i * f->record_len),
                                     b.begin() + static_cast<std::ptrdiff_t>((i + 1) * f->record_len));
            }
        }
    }
    return f;
}

/// Which files hold session keys: their contents go to the sealed secrets.
bool sealed_fid(std::uint16_t fid) { return fid == 0x4F03 || fid == 0x4F04 || fid == 0x4F05; }

void save_file(std::ostringstream& o, const os::File& f, const std::string& in, secrets::SecretMap& sealed) {
    o << in << "fid: " << hex_word(f.fid) << "\n";
    if (!f.name.empty()) {
        o << in << "name: " << f.name << "\n";
    }
    o << in << "type: " << kind_name(f.kind) << "\n";
    if (f.kind == os::Kind::adf) {
        o << in << "aid: " << upper_hex(f.aid) << "\n";
    }
    if (f.sfi) {
        o << in << "sfi: " << hex_byte(*f.sfi) << "\n";
    }
    if (f.lcs != os::kLcsActivated) {
        o << in << "lcs: " << hex_byte(f.lcs) << "\n";
    }
    if (f.arr.fid != 0) {
        o << in << "arr: [" << hex_word(f.arr.fid) << ", " << unsigned{f.arr.record} << "]\n";
    }
    if (os::is_df(f.kind)) {
        if (!f.children.empty()) {
            o << in << "files:\n";
            for (const auto& k : f.children) {
                o << in << "  - ";
                std::ostringstream child;
                save_file(child, *k, in + "    ", sealed);
                std::string text = child.str();
                o << text.substr(in.size() + 4);   // the first key goes on the "- " line
            }
        }
        return;
    }
    const std::string sealed_name = "ef." + fid_hex(f.fid);
    if (f.kind == os::Kind::transparent) {
        if (f.secret) {
            o << in << "secret: true\n" << in << "size: " << f.secret_data.size() << "\n";
            sealed.set(sealed_name, f.secret_data.clone());
            return;
        }
        if (sealed_fid(f.fid)) {
            o << in << "sealed: true\n" << in << "size: " << f.data.size() << "\n";
            sealed.set(sealed_name, SecretBytes::copy_of(f.data));
            return;
        }
        o << in << "data: " << upper_hex(f.data) << "\n";
        return;
    }
    o << in << "record_len: " << f.record_len << "\n";
    if (sealed_fid(f.fid)) {
        Bytes all;
        for (const auto& r : f.records) {
            all.insert(all.end(), r.begin(), r.end());
        }
        o << in << "sealed: true\n" << in << "record_count: " << f.records.size() << "\n";
        sealed.set(sealed_name, SecretBytes::copy_of(all));
        secure_zero(all);
        return;
    }
    o << in << "records:\n";
    for (const auto& r : f.records) {
        o << in << "  - " << upper_hex(r) << "\n";
    }
}

os::File* find_child(os::File* df, std::uint16_t fid) { return df != nullptr ? df->child(fid) : nullptr; }

} // namespace

std::optional<Bytes> personality_atr(std::string_view name) {
    // sim-uicc.md §3: a real card's ATR, so pySim applies that card's model
    // (it then also looks for the card's own files, AF20 and AF30 among them).
    if (name == "sysmoISIM-SJA5") {
        return from_hex("3B9F96801F878031E073FE211B674A357530350251CC").value_or(Bytes{});
    }
    return std::nullopt;
}

std::unique_ptr<os::Card> load(const Yaml& image, const secrets::SecretMap& s) {
    image.only({"atr", "personality", "t0", "channels", "pins", "mf"});
    os::CardConfig cfg;
    if (image.has("atr")) {
        cfg.atr = hex_of(image.at("atr"));
    }
    if (image.has("personality")) {
        auto atr = personality_atr(image.at("personality").as<std::string>());
        if (!atr) {
            image.at("personality").fail("not a personality this card has (sysmoISIM-SJA5)");
        }
        cfg.atr = std::move(*atr);
    }
    cfg.t0 = image.get<bool>("t0", true);
    cfg.channels = image.get<std::uint8_t>("channels", 4);
    auto mf = load_file(image.at("mf"), s);
    if (mf->kind != os::Kind::mf || mf->fid != 0x3F00) {
        image.at("mf").fail("the root is the MF, 0x3F00");
    }
    auto card = std::make_unique<os::Card>(std::move(mf), std::move(cfg));
    if (image.has("pins")) {
        const Yaml pins = image.at("pins");
        for (std::size_t i = 0; i < pins.size(); ++i) {
            const Yaml p = pins.at(i);
            p.only({"ref", "enabled", "tries", "max_tries", "unblock_tries", "max_unblock_tries"});
            os::Pin pin;
            pin.ref = p.at("ref").as<std::uint8_t>();
            pin.enabled = p.get<bool>("enabled", true);
            pin.max_tries = p.get<std::uint8_t>("max_tries", 3);
            pin.tries = p.get<std::uint8_t>("tries", pin.max_tries);
            pin.max_unblock_tries = p.get<std::uint8_t>("max_unblock_tries", 10);
            pin.unblock_tries = p.get<std::uint8_t>("unblock_tries", pin.max_unblock_tries);
            const std::string base = pin.ref == os::kPin1 ? "pin1" : pin.ref == os::kPin2 ? "pin2" : pin.ref == os::kAdm1 ? "adm1" : "";
            if (const SecretBytes* v = base.empty() ? nullptr : s.get(base)) {
                auto block = secrets::pin_block(*v);
                if (!block) {
                    p.fail("its secret is not 4 to 8 digits");
                }
                pin.value = std::move(*block);
            } else {
                pin.value = SecretBytes(8);   // no PIN given: it can never verify
            }
            if (pin.ref != os::kAdm1) {
                if (const SecretBytes* u = s.get(pin.ref == os::kPin1 ? "puk1" : "puk2")) {
                    auto block = secrets::pin_block(*u);
                    if (block) {
                        pin.unblock = std::move(*block);
                    }
                }
            }
            card->add_pin(std::move(pin));
        }
    }
    for (const auto& k : card->mf().children) {
        if (k->kind == os::Kind::adf && k->aid.size() >= sizeof usim::kUsimAid &&
            std::equal(std::begin(usim::kUsimAid), std::end(usim::kUsimAid), k->aid.begin())) {
            card->add_application(Bytes(std::begin(usim::kUsimAid), std::end(usim::kUsimAid)), std::make_unique<usim::Usim>());
            break;
        }
    }
    return card;
}

std::string save(os::Card& card, secrets::SecretMap& sealed) {
    std::ostringstream o;
    o << "# kaluza-sim card image (sim-uicc.md section 7). No secrets: those are in the sealed file.\n";
    o << "atr: " << upper_hex(card.atr()) << "\n";
    o << "t0: true\nchannels: 4\n";
    o << "pins:\n";
    for (std::uint8_t ref : {os::kPin1, os::kPin2, os::kAdm1}) {
        if (const os::Pin* p = card.pin(ref)) {
            o << "  - {ref: " << hex_byte(p->ref) << ", enabled: " << (p->enabled ? "true" : "false")
              << ", tries: " << unsigned{p->tries} << ", unblock_tries: " << unsigned{p->unblock_tries} << "}\n";
        }
    }
    o << "mf:\n";
    save_file(o, card.mf(), "  ", sealed);
    return o.str();
}

os::File* usim_adf(os::Card& card) noexcept {
    for (const auto& k : card.mf().children) {
        if (k->kind == os::Kind::adf && k->aid.size() >= sizeof usim::kUsimAid &&
            std::equal(std::begin(usim::kUsimAid), std::end(usim::kUsimAid), k->aid.begin())) {
            return k.get();
        }
    }
    return nullptr;
}

Result<Bytes> encode_imsi(std::string_view d) {
    if (d.size() < 6 || d.size() > 15 || !std::all_of(d.begin(), d.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return make_error(Errc::invalid_argument, 0, "image: an IMSI is 6 to 15 digits");
    }
    const bool odd = d.size() % 2 == 1;
    Bytes out(9, 0xFF);
    // Octet 2: the first digit over the type and parity nibble ('1001' odd, '0001' even).
    std::vector<std::uint8_t> nibbles{static_cast<std::uint8_t>(odd ? 0x9 : 0x1)};
    for (char c : d) {
        nibbles.push_back(static_cast<std::uint8_t>(c - '0'));
    }
    if (nibbles.size() % 2 == 1) {
        nibbles.push_back(0xF);
    }
    out[0] = static_cast<std::uint8_t>(nibbles.size() / 2);
    for (std::size_t i = 0; i < nibbles.size(); i += 2) {
        out[1 + i / 2] = static_cast<std::uint8_t>(nibbles[i] | (nibbles[i + 1] << 4));
    }
    return out;
}

Result<Bytes> encode_iccid(std::string_view d) {
    if (d.size() < 18 || d.size() > 20 || !std::all_of(d.begin(), d.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return make_error(Errc::invalid_argument, 0, "image: an ICCID is 18 to 20 digits");
    }
    Bytes out(10, 0xFF);
    for (std::size_t i = 0; i < 20; i += 2) {
        const std::uint8_t lo = i < d.size() ? static_cast<std::uint8_t>(d[i] - '0') : 0xF;
        const std::uint8_t hi = i + 1 < d.size() ? static_cast<std::uint8_t>(d[i + 1] - '0') : 0xF;
        out[i / 2] = static_cast<std::uint8_t>(lo | (hi << 4));
    }
    return out;
}

Bytes encode_acc(std::string_view imsi) {
    Bytes out{0x00, 0x00};
    if (!imsi.empty() && imsi.back() >= '0' && imsi.back() <= '9') {
        const int cls = imsi.back() - '0';
        if (cls < 8) {
            out[1] = static_cast<std::uint8_t>(1U << cls);
        } else {
            out[0] = static_cast<std::uint8_t>(1U << (cls - 8));
        }
    }
    return out;
}

Result<Bytes> encode_msisdn_record(std::string_view d, std::size_t record_len) {
    if (record_len < 14) {
        return make_error(Errc::invalid_argument, 0, "image: an EF.MSISDN record is at least 14 octets");
    }
    if (d.size() > 20 || !std::all_of(d.begin(), d.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return make_error(Errc::invalid_argument, 0, "image: an MSISDN is up to 20 digits");
    }
    Bytes rec(record_len, 0xFF);
    const std::size_t x = record_len - 14;   // the alpha identifier, left empty
    if (d.empty()) {
        return rec;
    }
    rec[x] = static_cast<std::uint8_t>(1 + (d.size() + 1) / 2);   // TON/NPI plus the BCD octets
    rec[x + 1] = 0x91;                                           // international number, ISDN/telephony
    for (std::size_t i = 0; i < d.size(); i += 2) {
        const std::uint8_t lo = static_cast<std::uint8_t>(d[i] - '0');
        const std::uint8_t hi = i + 1 < d.size() ? static_cast<std::uint8_t>(d[i + 1] - '0') : 0xF;
        rec[x + 2 + i / 2] = static_cast<std::uint8_t>(lo | (hi << 4));
    }
    return rec;
}

namespace {

/// BCD digits, low nibble first, up to the first filler.
std::string bcd_digits(ByteView b) {
    std::string out;
    for (std::uint8_t o : b) {
        for (std::uint8_t n : {static_cast<std::uint8_t>(o & 0x0F), static_cast<std::uint8_t>(o >> 4)}) {
            if (n > 9) {
                return out;
            }
            out.push_back(static_cast<char>('0' + n));
        }
    }
    return out;
}

} // namespace

std::string decode_imsi(ByteView ef) {
    if (ef.size() < 2 || ef[0] == 0 || ef[0] == 0xFF || ef[0] > 8 || ef.size() < 1u + ef[0]) {
        return {};
    }
    // The first nibble is the type and parity; the digits follow.
    std::string out;
    const std::uint8_t first = ef[1] >> 4;
    if (first > 9) {
        return {};
    }
    out.push_back(static_cast<char>('0' + first));
    for (std::size_t i = 1; i < ef[0]; ++i) {
        for (std::uint8_t n : {static_cast<std::uint8_t>(ef[1 + i] & 0x0F), static_cast<std::uint8_t>(ef[1 + i] >> 4)}) {
            if (n > 9) {
                return out;
            }
            out.push_back(static_cast<char>('0' + n));
        }
    }
    return out;
}

std::string decode_iccid(ByteView ef) { return bcd_digits(ef.subspan(0, std::min<std::size_t>(ef.size(), 10))); }

std::string decode_msisdn_record(ByteView rec) {
    if (rec.size() < 14) {
        return {};
    }
    const std::size_t x = rec.size() - 14;
    const std::size_t n = rec[x];
    if (n < 2 || n > 11) {
        return {};
    }
    return bcd_digits(rec.subspan(x + 2, n - 1));
}

std::vector<unsigned> services(ByteView ust) {
    std::vector<unsigned> out;
    for (std::size_t i = 0; i < ust.size(); ++i) {
        for (unsigned b = 0; b < 8; ++b) {
            if ((ust[i] >> b & 1) != 0) {
                out.push_back(static_cast<unsigned>(i * 8 + b + 1));
            }
        }
    }
    return out;
}

Result<Subscriber> range_subscriber(std::string_view imsi) {
    const bool digits = imsi.size() == 15 && std::all_of(imsi.begin(), imsi.end(), [](char c) { return c >= '0' && c <= '9'; });
    if (!digits || (imsi.substr(0, 12) != "001010000300" && imsi.substr(0, 12) != "999700000300")) {
        return make_error(Errc::invalid_argument, 0, "not an IMSI of the sim ranges (sim-uicc.md section 8)");
    }
    const std::string msin(imsi.substr(5));
    return Subscriber{std::string(imsi), "898821100" + msin, "999" + msin.substr(2), 2};
}

Result<void> personalise(os::Card& card, const Subscriber& sub) {
    os::File* adf = usim_adf(card);
    if (adf == nullptr) {
        return make_error(Errc::invalid_argument, 0, "image: the card has no USIM ADF");
    }
    auto imsi = encode_imsi(sub.imsi);
    if (!imsi) {
        return imsi.error();
    }
    auto iccid = encode_iccid(sub.iccid);
    if (!iccid) {
        return iccid.error();
    }
    os::File* f_imsi = find_child(adf, 0x6F07);
    os::File* f_iccid = find_child(&card.mf(), 0x2FE2);
    os::File* f_acc = find_child(adf, 0x6F78);
    os::File* f_ad = find_child(adf, 0x6FAD);
    if (f_imsi == nullptr || f_iccid == nullptr || f_acc == nullptr || f_ad == nullptr) {
        return make_error(Errc::invalid_argument, 0, "image: the template lacks EF.IMSI, EF.ICCID, EF.ACC or EF.AD");
    }
    f_imsi->data = *imsi;
    f_iccid->data = *iccid;
    f_acc->data = encode_acc(sub.imsi);
    if (f_ad->data.size() >= 4) {
        f_ad->data[3] = static_cast<std::uint8_t>((f_ad->data[3] & 0xF0) | (sub.mnc_digits & 0x0F));
    }
    if (os::File* f_msisdn = find_child(adf, 0x6F40); f_msisdn != nullptr && !f_msisdn->records.empty()) {
        auto rec = encode_msisdn_record(sub.msisdn, f_msisdn->record_len);
        if (!rec) {
            return rec.error();
        }
        f_msisdn->records[0] = *rec;
    }
    card.changed();
    return {};
}

} // namespace ksim::uicc::image
