// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The soft card's operating system (P1 N3; ETSI TS 102 221 §10 and §11;
// sim-uicc.md §2). It takes command APDUs and returns response APDUs, as a
// card does: SELECT, STATUS, READ/UPDATE BINARY, READ/UPDATE/SEARCH RECORD,
// GET RESPONSE, MANAGE CHANNEL, VERIFY/CHANGE/DISABLE/ENABLE/UNBLOCK PIN,
// ACTIVATE/DEACTIVATE FILE and TERMINAL PROFILE. An application selected on a
// channel (the USIM) handles its own commands, AUTHENTICATE and GET IDENTITY.
//
// T=0 semantics (the default): a command sent without Le whose answer has data
// gets SW 61xx and the data waits for GET RESPONSE; a wrong Le gets 6Cxx. A
// card knows nothing of UEs (rule R5).

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "codec/uicc/apdu.hpp"
#include "platform/buf.hpp"
#include "platform/secret.hpp"
#include "uicc/os/file.hpp"

namespace ksim::uicc::os {

/// Key references (TS 102 221 Table 9.3).
inline constexpr std::uint8_t kPin1 = 0x01;
inline constexpr std::uint8_t kPin2 = 0x81;
inline constexpr std::uint8_t kAdm1 = 0x0A;

struct Pin {
    std::uint8_t ref = 0;
    SecretBytes value;            // 8 octets, 'FF'-padded (§9.5.1)
    SecretBytes unblock;          // the PUK, 8 octets; empty: none (ADM1)
    std::uint8_t max_tries = 3;
    std::uint8_t tries = 3;
    std::uint8_t max_unblock_tries = 10;
    std::uint8_t unblock_tries = 10;
    bool enabled = true;          // a disabled PIN counts as verified (§9.5.1)
    bool verified = false;        // security status, cleared by a reset
};

/// Per logical channel (§8.6): the current DF, EF and application, the
/// record pointer, and data waiting for GET RESPONSE.
struct Channel {
    bool open = false;
    File* df = nullptr;
    File* ef = nullptr;
    File* app = nullptr;          // the selected ADF, if any
    std::size_t record = 0;       // the current record, 1-based; 0: none
    Bytes pending;
};

class Card;

class Application {
public:
    virtual ~Application() = default;
    /// Handles a command the application owns; nullopt leaves it to the OS.
    virtual std::optional<Response> handle(Card& card, Channel& ch, const Command& c) = 0;
};

struct CardConfig {
    Bytes atr;
    bool t0 = true;
    std::uint8_t channels = 4;
};

class Card {
public:
    Card(std::unique_ptr<File> mf, CardConfig config);
    ~Card();
    Card(const Card&) = delete;
    Card& operator=(const Card&) = delete;

    /// A cold or warm reset: channels closed but the basic one, the MF
    /// current, security status cleared. Returns the ATR.
    const Bytes& reset();
    const Bytes& atr() const noexcept { return config_.atr; }
    /// Another ATR from the next reset on (an image's personality).
    void set_atr(Bytes atr) { config_.atr = std::move(atr); }

    /// One command APDU in, one response APDU out. An undecodable command gets
    /// SW 6700 (wrong length) or 6E00/6D00 as the class or instruction is.
    Bytes process(ByteView capdu);
    Response process(const Command& c);

    /// The application an ADF's AID belongs to (matched by the AID's first
    /// octets, the RID and the application code).
    void add_application(Bytes aid, std::unique_ptr<Application> app);
    void add_pin(Pin pin);

    File& mf() noexcept { return *mf_; }
    Pin* pin(std::uint8_t ref) noexcept;
    /// Whether the access rule of `f` grants `mode` (an AM byte bit, ISO/IEC
    /// 7816-4 Table 17: 0x01 read, 0x02 update, 0x08 deactivate, 0x10 activate).
    bool allowed(const File& f, std::uint8_t mode) const;
    /// The EF `fid` in `df` or, failing that, in the MF.
    File* find_ef(const File& df, std::uint16_t fid) const noexcept;

    /// Called after every change worth keeping (an update, a PIN state, the
    /// SQN array): the owner saves the card (write-through NVM).
    std::function<void()> on_change;
    void changed() const {
        if (on_change) {
            on_change();
        }
    }

private:
    Response dispatch(Channel& ch, const Command& c);
    Response select(Channel& ch, const Command& c);
    Response status(Channel& ch, const Command& c);
    Response read_binary(Channel& ch, const Command& c);
    Response update_binary(Channel& ch, const Command& c);
    Response read_record(Channel& ch, const Command& c);
    Response update_record(Channel& ch, const Command& c);
    Response search_record(Channel& ch, const Command& c);
    Response manage_channel(Channel& ch, const Command& c);
    Response pin_command(Channel& ch, const Command& c);
    Response activation(Channel& ch, const Command& c, bool activate);
    Application* application_of(const File* adf) const noexcept;
    /// The EF a READ/UPDATE addresses: by SFI (b8 of P1 or P2's high bits) or the current EF.
    File* addressed_ef(Channel& ch, std::optional<std::uint8_t> sfi, std::uint16_t& sw) const;
    Bytes fcp(const File& f) const;
    bool pin_condition(std::uint8_t ref) const noexcept;

    std::unique_ptr<File> mf_;
    CardConfig config_;
    std::vector<Channel> channels_;
    std::vector<Pin> pins_;
    std::vector<std::pair<Bytes, std::unique_ptr<Application>>> apps_;
};

/// A UICC ATR (ISO/IEC 7816-3): T=0 and T=15 (class A, B and C), the given
/// historical bytes, and the check byte TCK.
Bytes make_atr(ByteView historical);

} // namespace ksim::uicc::os
