// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/transport/pcsc.hpp"

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

#include <array>
#include <utility>

#include "platform/mutation.hpp"
#include "platform/secret.hpp"

namespace ksim::uicc::pcsc {

namespace {

Error pcsc_error(LONG rc, const char* what) {
    if (rc == static_cast<LONG>(SCARD_E_NO_SMARTCARD) || rc == static_cast<LONG>(SCARD_W_REMOVED_CARD) ||
        rc == static_cast<LONG>(SCARD_E_NO_READERS_AVAILABLE) || rc == static_cast<LONG>(SCARD_E_UNKNOWN_READER)) {
        return make_error(Errc::closed, static_cast<std::uint32_t>(rc), what);
    }
    return make_error(Errc::io, static_cast<std::uint32_t>(rc), what);
}

struct Context {
    SCARDCONTEXT ctx = 0;
    bool ok = false;
    Context() { ok = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx) == SCARD_S_SUCCESS; }
    ~Context() {
        if (ok) {
            SCardReleaseContext(ctx);
        }
    }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
};

} // namespace

Result<std::vector<std::string>> readers() {
    Context c;
    if (!c.ok) {
        return make_error(Errc::io, 0, "pcsc: no context (is pcscd running?)");
    }
    DWORD len = 0;
    LONG rc = SCardListReaders(c.ctx, nullptr, nullptr, &len);
    if (rc == static_cast<LONG>(SCARD_E_NO_READERS_AVAILABLE)) {
        return std::vector<std::string>{};
    }
    if (rc != SCARD_S_SUCCESS) {
        return pcsc_error(rc, "pcsc: SCardListReaders");
    }
    std::string buf(len, '\0');
    rc = SCardListReaders(c.ctx, nullptr, buf.data(), &len);
    if (rc != SCARD_S_SUCCESS) {
        return pcsc_error(rc, "pcsc: SCardListReaders");
    }
    std::vector<std::string> out;
    for (std::size_t i = 0; i < buf.size() && buf[i] != '\0';) {
        const std::size_t end = buf.find('\0', i);
        out.emplace_back(buf.substr(i, end - i));
        i = end + 1;
    }
    return out;
}

Result<std::string> pick(const std::vector<std::string>& names, std::string_view pattern) {
    if (pattern.size() > 1 && pattern.front() == '#') {
        std::size_t n = 0;
        for (char ch : pattern.substr(1)) {
            if (ch < '0' || ch > '9') {
                return make_error(Errc::invalid_argument, 0, "pcsc: a reader index is #<digits>");
            }
            n = n * 10 + static_cast<std::size_t>(ch - '0');
        }
        if (n >= names.size()) {
            return make_error(Errc::closed, 0, "pcsc: no reader at that index");
        }
        return names[n];
    }
    const std::string* found = nullptr;
    for (const auto& name : names) {
        if (name == pattern) {
            return name;
        }
        if (name.find(pattern) != std::string::npos) {
            if (found != nullptr) {
                return make_error(Errc::invalid_argument, 0, "pcsc: more than one reader matches");
            }
            found = &name;
        }
    }
    if (found == nullptr) {
        return make_error(Errc::closed, 0, "pcsc: no reader matches");
    }
    return *found;
}

struct PcscCard::Handle {
    Context c;
    SCARDHANDLE card = 0;
    DWORD protocol = 0;
};

PcscCard::PcscCard(std::string reader, std::unique_ptr<Handle> h) : reader_(std::move(reader)), h_(std::move(h)) {}

PcscCard::~PcscCard() {
    if (h_ && h_->card != 0) {
        SCardDisconnect(h_->card, SCARD_LEAVE_CARD);
    }
}

Result<std::unique_ptr<PcscCard>> PcscCard::open(const std::string& reader) {
    auto h = std::make_unique<Handle>();
    if (!h->c.ok) {
        return make_error(Errc::io, 0, "pcsc: no context (is pcscd running?)");
    }
    const LONG rc = SCardConnect(h->c.ctx, reader.c_str(), SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                 &h->card, &h->protocol);
    if (rc != SCARD_S_SUCCESS) {
        return pcsc_error(rc, "pcsc: SCardConnect");
    }
    return std::unique_ptr<PcscCard>(new PcscCard(reader, std::move(h)));
}

Result<Bytes> PcscCard::atr() {
    std::array<BYTE, MAX_ATR_SIZE> atr{};
    DWORD atr_len = atr.size();
    DWORD state = 0;
    DWORD proto = 0;
    DWORD name_len = 0;
    const LONG rc = SCardStatus(h_->card, nullptr, &name_len, &state, &proto, atr.data(), &atr_len);
    if (rc != SCARD_S_SUCCESS) {
        return pcsc_error(rc, "pcsc: SCardStatus");
    }
    return Bytes(atr.begin(), atr.begin() + atr_len);
}

Result<Bytes> PcscCard::reset() {
    const LONG rc = SCardReconnect(h_->card, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                   SCARD_RESET_CARD, &h_->protocol);
    if (rc != SCARD_S_SUCCESS) {
        return pcsc_error(rc, "pcsc: SCardReconnect");
    }
    return atr();
}

Result<Bytes> PcscCard::transmit(ByteView capdu) {
    if (capdu.size() < 4 || capdu.size() > MAX_BUFFER_SIZE_EXTENDED) {
        return make_error(Errc::invalid_argument, 0, "pcsc: a command APDU is 4 octets or more");
    }
    const SCARD_IO_REQUEST* pci = h_->protocol == SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0;
    std::array<BYTE, MAX_BUFFER_SIZE_EXTENDED> rsp{};
    DWORD len = rsp.size();
    const LONG rc = SCardTransmit(h_->card, pci, capdu.data(), static_cast<DWORD>(capdu.size()), nullptr, rsp.data(), &len);
    if (rc != SCARD_S_SUCCESS) {
        secure_zero(std::span<std::uint8_t>(rsp.data(), rsp.size()));
        return pcsc_error(rc, "pcsc: SCardTransmit");
    }
    if (len < 2) {
        return make_error(Errc::malformed, 0, "pcsc: a response without SW1 SW2");
    }
    Bytes out(rsp.begin(), rsp.begin() + len);
    secure_zero(std::span<std::uint8_t>(rsp.data(), len));
    if (KSIM_MUTANT("pcsc_response_truncated") && out.size() > 2) {
        out.erase(out.begin(), out.end() - 2);   // the data dropped, SW1 SW2 kept
    }
    return out;
}

// ---- the asynchronous transport --------------------------------------------------------------

struct PcscTransport::Shared {
    std::string reader;
    std::unique_ptr<PcscCard> card;   // used only on the pool, one job at a time
    bool alive = true;                // set false by the transport's owner thread, read after the job
};

PcscTransport::PcscTransport(Executor& exec, BlockingPool& pool, std::string reader)
    : exec_(exec), pool_(pool), shared_(std::make_shared<Shared>()) {
    shared_->reader = std::move(reader);
}

PcscTransport::~PcscTransport() {
    shared_->alive = false;
    // A job still on the pool holds `shared_`; it closes the card when it ends.
}

void PcscTransport::reset(Done done) {
    queue_.push_back(Job{true, {}, std::move(done)});
    pump();
}

void PcscTransport::transmit(Bytes capdu, Done done) {
    queue_.push_back(Job{false, std::move(capdu), std::move(done)});
    pump();
}

void PcscTransport::pump() {
    if (busy_ || queue_.empty()) {
        return;
    }
    busy_ = true;
    auto job = std::make_shared<Job>(std::move(queue_.front()));
    queue_.pop_front();
    auto shared = shared_;
    Executor* exec = &exec_;
    auto finish = [this, shared, exec, job](Result<Bytes> answer) {
        exec->post([this, shared, job, answer = std::move(answer)]() mutable {
            if (!shared->alive) {
                return;   // the transport is gone
            }
            busy_ = false;
            job->done(std::move(answer));
            pump();
        });
    };
    const bool queued = pool_.run([shared, job, finish]() {
        Result<Bytes> answer = make_error(Errc::closed, 0, "uicc: no card in the reader");
        if (!shared->card) {
            auto c = PcscCard::open(shared->reader);
            if (c) {
                shared->card = std::move(*c);
            } else {
                answer = c.error();
            }
        }
        if (shared->card) {
            answer = job->reset ? shared->card->reset() : shared->card->transmit(job->capdu);
            if (!answer && answer.error().code == Errc::closed) {
                shared->card.reset();   // removed: the next reset reconnects
            }
        }
        secure_zero(job->capdu);
        finish(std::move(answer));
    });
    if (!queued) {
        secure_zero(job->capdu);
        exec_.post([this, shared, job]() {
            if (!shared->alive) {
                return;
            }
            busy_ = false;
            job->done(make_error(Errc::closed, 0, "uicc: the blocking pool is stopping"));
            pump();
        });
    }
}

} // namespace ksim::uicc::pcsc
