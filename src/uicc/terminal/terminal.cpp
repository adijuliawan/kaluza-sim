// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/terminal/terminal.hpp"

#include <algorithm>
#include <coroutine>
#include <optional>

#include "uicc/usim/usim.hpp"

namespace ksim::uicc {

namespace {

/// Awaits one exchange on the transport.
class Exchange {
public:
    Exchange(IApduTransport& t, Bytes capdu, bool reset) : t_(t), capdu_(std::move(capdu)), reset_(reset) {}
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> h) {
        auto done = [this, h](Result<Bytes> r) {
            out_.emplace(std::move(r));
            h.resume();
        };
        if (reset_) {
            t_.reset(std::move(done));
        } else {
            t_.transmit(std::move(capdu_), std::move(done));
        }
    }
    Result<Bytes> await_resume() {
        if (!out_.has_value()) {
            std::terminate();   // resumed without an answer: a transport bug
        }
        return std::move(out_).value();
    }

private:
    IApduTransport& t_;
    Bytes capdu_;
    bool reset_;
    std::optional<Result<Bytes>> out_;
};

Error status_error(std::uint16_t) { return make_error(Errc::unsupported, 0, "uicc: the card refused the command"); }

std::uint16_t sw_of(const Response& r) { return r.sw(); }

} // namespace

coro::Task<Result<Bytes>> Terminal::call(Bytes capdu, bool reset) {
    ++apdus_;
    co_return co_await Exchange(t_, std::move(capdu), reset);
}

coro::Task<Result<Bytes>> Terminal::power_on() {
    aid_.clear();
    co_return co_await call({}, true);
}

coro::Task<Result<Response>> Terminal::transmit(Command c) {
    // A PIN command's data is wiped when the exchange ends, however it ends.
    struct Wipe {
        Bytes& data;
        bool on;
        ~Wipe() {
            if (on) {
                secure_zero(data);
            }
        }
    } wipe{c.data, c.ins == 0x20 || c.ins == 0x24 || c.ins == 0x26 || c.ins == 0x28 || c.ins == 0x2C};
    for (int round = 0; round < 4; ++round) {
        auto enc = encode_command(c);
        if (!enc) {
            co_return enc.error();
        }
        auto raw = co_await call(std::move(*enc), false);
        if (!raw) {
            co_return raw.error();
        }
        auto r = decode_response(*raw);
        secure_zero(*raw);
        if (!r) {
            co_return r.error();
        }
        if (r->sw1 == 0x6C) {   // wrong Le: send it again with the length the card gave
            c.le = r->sw2 == 0 ? 256 : r->sw2;
            continue;
        }
        if (r->sw1 != 0x61) {
            co_return std::move(*r);
        }
        // '61xx': the data waits; fetch it with GET RESPONSE, as often as the card says more.
        Response all;
        std::uint8_t more = r->sw2;
        for (int k = 0; k < 64; ++k) {
            Command gr{static_cast<std::uint8_t>(c.cla & 0x03), 0xC0, 0x00, 0x00, {},
                       static_cast<std::uint16_t>(more == 0 ? 256 : more)};
            auto genc = encode_command(gr);
            auto graw = co_await call(std::move(*genc), false);
            if (!graw) {
                secure_zero(all.data);
                co_return graw.error();
            }
            auto g = decode_response(*graw);
            secure_zero(*graw);
            if (!g) {
                secure_zero(all.data);
                co_return g.error();
            }
            all.data.insert(all.data.end(), g->data.begin(), g->data.end());
            secure_zero(g->data);
            all.sw1 = g->sw1;
            all.sw2 = g->sw2;
            if (g->sw1 != 0x61) {
                break;
            }
            more = g->sw2;
        }
        co_return all;
    }
    co_return make_error(Errc::malformed, 0, "uicc: the card kept asking for another Le");
}

coro::Task<Result<void>> Terminal::select_usim() {
    // EF.DIR (TS 102 221 §13.1): one application template ('61') per record,
    // with the AID in '4F'.
    auto sel = co_await transmit(Command{0x00, 0xA4, 0x00, 0x04, {0x2F, 0x00}, std::nullopt});
    if (!sel) {
        co_return sel.error();
    }
    if (sel->sw() != 0x9000) {
        last_sw_ = sw_of(*sel);
        co_return status_error(sel->sw());
    }
    auto fcp = decode_fcp(sel->data);
    if (!fcp) {
        co_return make_error(Errc::malformed, 0, "uicc: EF.DIR's FCP does not decode");
    }
    const std::optional<FileDescriptor> fd = fcp->file_descriptor();
    if (!fd.has_value() || !fd->records.has_value() || !fd->record_length.has_value()) {
        co_return make_error(Errc::malformed, 0, "uicc: EF.DIR's FCP has no record structure");
    }
    const std::uint8_t records = fd->records.value();
    const std::uint16_t record_length = fd->record_length.value();
    for (std::uint8_t rec = 1; rec <= records; ++rec) {
        auto r = co_await transmit(Command{0x00, 0xB2, rec, 0x04, {}, record_length});
        if (!r || r->sw() != 0x9000) {
            continue;
        }
        // The record's unused tail is 'FF' padding; an AID may hold 'FF' octets itself.
        Bytes body = r->data;
        while (!body.empty() && body.back() == 0xFF) {
            body.pop_back();
        }
        auto tlvs = decode_ber(body);
        if (!tlvs || tlvs->empty() || tlvs->front().tag != 0x61) {
            continue;
        }
        const Tlv* aid = tlvs->front().find(0x4F);
        if (aid == nullptr || aid->value.size() < sizeof usim::kUsimAid ||
            !std::equal(std::begin(usim::kUsimAid), std::end(usim::kUsimAid), aid->value.begin())) {
            continue;
        }
        auto s = co_await transmit(Command{0x00, 0xA4, 0x04, 0x04, aid->value, std::nullopt});
        if (!s) {
            co_return s.error();
        }
        if (s->sw() != 0x9000) {
            last_sw_ = sw_of(*s);
            co_return status_error(s->sw());
        }
        aid_ = aid->value;
        co_return Result<void>{};
    }
    co_return make_error(Errc::unsupported, 0, "uicc: no USIM in EF.DIR");
}

coro::Task<Result<void>> Terminal::verify_pin(std::uint8_t ref, const SecretBytes& pin_block) {
    Command c{0x00, 0x20, 0x00, ref, Bytes(pin_block.expose().begin(), pin_block.expose().end()), std::nullopt};
    auto r = co_await transmit(std::move(c));
    if (!r) {
        co_return r.error();
    }
    if (r->sw() != 0x9000) {
        last_sw_ = sw_of(*r);
        co_return status_error(r->sw());
    }
    co_return Result<void>{};
}

coro::Task<Result<Fcp>> Terminal::select_in_usim(std::vector<std::uint16_t> path) {
    if (aid_.empty()) {
        co_return make_error(Errc::invalid_argument, 0, "uicc: no USIM selected");
    }
    // '7FFF' is the current application's ADF (TS 102 221 §8.4.1).
    auto adf = co_await transmit(Command{0x00, 0xA4, 0x00, 0x0C, {0x7F, 0xFF}, std::nullopt});
    if (!adf) {
        co_return adf.error();
    }
    if (adf->sw() != 0x9000) {
        last_sw_ = sw_of(*adf);
        co_return status_error(adf->sw());
    }
    Result<Response> r = make_error(Errc::invalid_argument, 0, "uicc: an empty path");
    for (std::size_t i = 0; i < path.size(); ++i) {
        const bool last = i + 1 == path.size();
        r = co_await transmit(Command{0x00, 0xA4, 0x00, static_cast<std::uint8_t>(last ? 0x04 : 0x0C),
                                      {static_cast<std::uint8_t>(path[i] >> 8), static_cast<std::uint8_t>(path[i] & 0xFF)},
                                      std::nullopt});
        if (!r) {
            co_return r.error();
        }
        if (r->sw() != 0x9000 && r->sw() != 0x6283) {
            last_sw_ = sw_of(*r);
            co_return status_error(r->sw());
        }
    }
    if (!r) {
        co_return r.error();
    }
    auto fcp = decode_fcp(r->data);
    if (!fcp) {
        co_return fcp.error();
    }
    co_return std::move(*fcp);
}

coro::Task<Result<Bytes>> Terminal::read_ef(std::vector<std::uint16_t> path) {
    auto fcp = co_await select_in_usim(std::move(path));
    if (!fcp) {
        co_return fcp.error();
    }
    const auto size = fcp->file_size();
    if (!size) {
        co_return make_error(Errc::malformed, 0, "uicc: the EF's FCP has no size");
    }
    Bytes out;
    while (out.size() < *size) {
        const std::size_t want = std::min<std::size_t>(*size - out.size(), 256);
        auto r = co_await transmit(Command{0x00, 0xB0, static_cast<std::uint8_t>((out.size() >> 8) & 0x7F),
                                           static_cast<std::uint8_t>(out.size() & 0xFF), {}, static_cast<std::uint16_t>(want)});
        if (!r) {
            co_return r.error();
        }
        if (r->sw() != 0x9000 || r->data.empty()) {
            last_sw_ = sw_of(*r);
            co_return status_error(r->sw());
        }
        out.insert(out.end(), r->data.begin(), r->data.end());
    }
    co_return out;
}

coro::Task<Result<Bytes>> Terminal::read_record(std::vector<std::uint16_t> path, std::uint8_t record) {
    auto fcp = co_await select_in_usim(std::move(path));
    if (!fcp) {
        co_return fcp.error();
    }
    const std::optional<FileDescriptor> fd = fcp->file_descriptor();
    if (!fd.has_value() || !fd->record_length.has_value()) {
        co_return make_error(Errc::malformed, 0, "uicc: not a record file");
    }
    auto r = co_await transmit(Command{0x00, 0xB2, record, 0x04, {}, fd->record_length});
    if (!r) {
        co_return r.error();
    }
    if (r->sw() != 0x9000) {
        last_sw_ = sw_of(*r);
        co_return status_error(r->sw());
    }
    co_return std::move(r->data);
}

coro::Task<Result<void>> Terminal::update_ef(std::vector<std::uint16_t> path, Bytes data) {
    auto fcp = co_await select_in_usim(std::move(path));
    if (!fcp) {
        co_return fcp.error();
    }
    for (std::size_t at = 0; at < data.size(); at += 255) {
        const std::size_t n = std::min<std::size_t>(data.size() - at, 255);
        auto r = co_await transmit(Command{0x00, 0xD6, static_cast<std::uint8_t>((at >> 8) & 0x7F), static_cast<std::uint8_t>(at & 0xFF),
                                           Bytes(data.begin() + static_cast<std::ptrdiff_t>(at),
                                                 data.begin() + static_cast<std::ptrdiff_t>(at + n)),
                                           std::nullopt});
        if (!r) {
            co_return r.error();
        }
        if (r->sw() != 0x9000) {
            last_sw_ = sw_of(*r);
            co_return status_error(r->sw());
        }
    }
    co_return Result<void>{};
}

coro::Task<Result<void>> Terminal::update_record(std::vector<std::uint16_t> path, std::uint8_t record, Bytes data) {
    auto fcp = co_await select_in_usim(std::move(path));
    if (!fcp) {
        co_return fcp.error();
    }
    auto r = co_await transmit(Command{0x00, 0xDC, record, 0x04, std::move(data), std::nullopt});
    if (!r) {
        co_return r.error();
    }
    if (r->sw() != 0x9000) {
        last_sw_ = sw_of(*r);
        co_return status_error(r->sw());
    }
    co_return Result<void>{};
}

coro::Task<Result<AuthOutcome>> Terminal::authenticate(Bytes rand, Bytes autn) {
    if (aid_.empty()) {
        co_return make_error(Errc::invalid_argument, 0, "uicc: no USIM selected");
    }
    const Bytes data = encode_auth_challenge(AuthChallenge{std::move(rand), std::move(autn)}, AuthContext::umts);
    auto r = co_await transmit(Command{0x00, 0x88, 0x00, 0x81, data, std::nullopt});
    if (!r) {
        co_return r.error();
    }
    AuthOutcome out;
    if (r->sw() == 0x9862) {
        out.kind = AuthOutcome::Kind::mac_failure;
        co_return out;
    }
    if (r->sw() != 0x9000) {
        last_sw_ = sw_of(*r);
        co_return status_error(r->sw());
    }
    auto res = decode_auth_result(r->data, AuthContext::umts);
    if (!res) {
        secure_zero(r->data);
        co_return res.error();
    }
    if (res->kind == AuthResult::Kind::sync_failure) {
        out.kind = AuthOutcome::Kind::sync_failure;
        out.auts = res->auts;
    } else if (res->kind == AuthResult::Kind::success) {
        out.kind = AuthOutcome::Kind::success;
        out.res = SecretBytes::copy_of(res->res);
        out.ck = SecretBytes::copy_of(res->ck.in(r->data));
        out.ik = SecretBytes::copy_of(res->ik.in(r->data));
        secure_zero(res->res);
    } else {
        secure_zero(r->data);
        co_return make_error(Errc::unsupported, 0, "uicc: a GSM-context answer to a 3G AUTHENTICATE");
    }
    secure_zero(r->data);
    co_return out;
}

} // namespace ksim::uicc
