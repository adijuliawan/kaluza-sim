// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/sms/sms.hpp"

#include <algorithm>
#include <string>
#include <utility>

#include "platform/mutation.hpp"

namespace ksim::proc::ue {

namespace {

constexpr std::uint8_t kRpCauseMemoryExceeded = 22;    // TS 24.011 8.2.5.4, Table 8.4 (part 2)
constexpr std::uint8_t kCpCauseInvalidTi = 81;         // TS 24.011 8.1.4.2
constexpr std::uint8_t kTfVpfRelative = 0x10;          // TS 23.040 9.2.3.3: TP-VPF "10"
constexpr std::uint8_t kTpSrr = 0x20;
constexpr std::uint8_t kTpUdhi = 0x40;

std::string str(long long v) { return std::to_string(v); }

/// Digits as TS 23.040 9.1.2.5 semi-octets: low nibble first, an odd count padded with F.
Bytes bcd(std::string_view digits) {
    Bytes out;
    for (std::size_t i = 0; i < digits.size(); i += 2) {
        const auto lo = static_cast<std::uint8_t>(digits[i] - '0');
        const auto hi = static_cast<std::uint8_t>(i + 1 < digits.size() ? digits[i + 1] - '0' : 0x0F);
        out.push_back(static_cast<std::uint8_t>(hi << 4 | lo));
    }
    return out;
}

std::string digits_of(ByteView semi, std::size_t count) {
    std::string out;
    for (std::size_t i = 0; i < count && i / 2 < semi.size(); ++i) {
        const std::uint8_t nib = i % 2 == 0 ? semi[i / 2] & 0x0F : semi[i / 2] >> 4;
        if (nib > 9) {
            break;
        }
        out.push_back(static_cast<char>('0' + nib));
    }
    return out;
}

const char* kind_name(int k) {
    switch (k) {
    case 0: return "submit";
    case 1: return "smma";
    default: return "mt";
    }
}

} // namespace

Sms::Sms(Executor& ex, IEventSink& events, SmsConfig cfg, SmsPorts ports)
    : ex_(ex), events_(events), cfg_(std::move(cfg)), ports_(std::move(ports)), alive_(std::make_shared<bool>(true)) {}

Sms::~Sms() {
    *alive_ = false;
    reset();
}

void Sms::reset() {
    for (auto& [k, t] : txs_) {
        if (t.tc1) {
            ex_.stop_timer(*t.tc1);
        }
        if (t.rl) {
            ex_.stop_timer(*t.rl);
        }
    }
    txs_.clear();
    queue_.clear();
    mo_active_.reset();
    withheld_ack_.reset();
    answered_mt_.clear();
    tp_mr_.reset();
}

std::uint8_t Sms::next_tp_mr() {
    // TS 23.040 9.2.3.6: TP-MR one up from the last used, kept in EF.SMSS (TS 31.102 4.2.28).
    if (!tp_mr_) {
        const Bytes s = ports_.smss ? ports_.smss() : Bytes{};
        tp_mr_ = s.empty() ? std::uint8_t{0} : s[0];
    }
    tp_mr_ = static_cast<std::uint8_t>(*tp_mr_ + 1);
    if (ports_.store_smss) {
        const Bytes s = ports_.smss ? ports_.smss() : Bytes{};
        const std::uint8_t flag = s.size() > 1 ? s[1] : 0xFF;
        ports_.store_smss(Bytes{*tp_mr_, flag});
    }
    return *tp_mr_;
}

// ---- MO (TS 23.040 9.2.2.2, TS 24.011 6.3.1) ----------------------------------------------

Result<std::size_t> Sms::send(const SmsSubmit& m) {
    if (!ports_.allowed || !ports_.allowed()) {
        events_.emit("sms.mo.refused", cfg_.id, {{"why", "SMS over NAS is not allowed"}});
        return make_error(Errc::invalid_argument, 0, "SMS over NAS is not allowed");
    }
    if (m.to.empty() || m.to.size() > 20 || m.to.find_first_not_of("0123456789") != std::string::npos) {
        return make_error(Errc::invalid_argument, 0, "SMS: the destination is 1 to 20 digits");
    }
    // One TPDU holds 160 septets or 70 UCS2 characters; a concatenated part
    // gives 6 octets to its header: 153 septets or 67 characters.
    auto single = sms::split_text(m.text, m.ucs2, m.ucs2 ? 70 : 160);
    if (!single) {
        return single.error();
    }
    std::vector<std::string> parts = *single;
    const bool concat = parts.size() > 1;
    if (concat) {
        auto multi = sms::split_text(m.text, m.ucs2, m.ucs2 ? 67 : 153);
        if (!multi) {
            return multi.error();
        }
        parts = *multi;
        if (parts.size() > 255) {
            return make_error(Errc::invalid_argument, 0, "SMS: more than 255 parts");
        }
    }
    const std::optional<Bytes> sc = ports_.service_centre ? ports_.service_centre() : std::nullopt;
    if (!sc) {
        events_.emit("sms.mo.no_service_centre", cfg_.id, {});   // RP-DA goes empty: L7's case
    }
    const auto ref = ++concat_ref_;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        Bytes ud;
        std::size_t udl = 0;
        if (concat) {
            // TS 23.040 9.2.3.24.1: the 8-bit reference concatenation element.
            ud = {0x05, 0x00, 0x03, ref, static_cast<std::uint8_t>(parts.size()), static_cast<std::uint8_t>(i + 1)};
        }
        if (m.ucs2) {
            auto u = sms::utf8_to_ucs2(parts[i]);
            if (!u) {
                return u.error();
            }
            ud.insert(ud.end(), u->begin(), u->end());
            udl = ud.size();
        } else {
            // After a 6-octet header the septets start on a septet boundary: 1 fill bit.
            auto g = sms::utf8_to_gsm7(parts[i], concat ? 1U : 0U);
            if (!g) {
                return g.error();
            }
            ud.insert(ud.end(), g->first.begin(), g->first.end());
            udl = (concat ? 7 : 0) + g->second;
        }
        sms::Tpdu t;
        t.type = sms::TpduType::submit;
        t.first = static_cast<std::uint8_t>(0x01 | (m.vp ? kTfVpfRelative : 0) | (m.status_report ? kTpSrr : 0) |
                                            (concat ? kTpUdhi : 0));
        t.mr = next_tp_mr();
        t.address = sms::Address{static_cast<std::uint8_t>(m.to.size()), 0x91, bcd(m.to)};
        t.pid = 0;
        t.dcs = m.ucs2 ? 0x08 : 0x00;
        t.has_pid = t.has_dcs = t.has_ud = true;
        if (m.vp) {
            t.vp = Bytes{*m.vp};
        }
        t.udl = static_cast<std::uint8_t>(udl);
        t.ud = ud;
        sms::Rp rp;
        rp.mti = sms::RpMti::data_ms_n;
        rp.mr = ++rp_mr_;
        // TS 24.011 7.3.1.2: RP-Destination Address, the service centre from EF.SMSP (L7).
        if (!KSIM_MUTANT("sms_rp_da_empty")) {
            rp.destination = sc.value_or(Bytes{});
        }
        rp.user_data = sms::encode_tpdu(t);
        queue_.push_back(Pending{Kind::submit, sms::encode_rp(rp), rp.mr, t.mr, to_hex(ud)});
        events_.emit("sms.mo.submit", cfg_.id,
                     {{"to", m.to},
                      {"part", str(static_cast<long long>(i) + 1)},
                      {"parts", str(static_cast<long long>(parts.size()))},
                      {"tp_mr", str(t.mr)},
                      {"dcs", str(t.dcs)},
                      {"ud", to_hex(ud)}});
    }
    start_next_mo();
    return parts.size();
}

void Sms::start_next_mo() {
    if (mo_active_ || queue_.empty()) {
        return;
    }
    // A TI the UE has no transaction on (TS 24.007 11.2.3.1.3: values 0 to 6).
    std::uint8_t v = next_ti_;
    for (int tries = 0; tries < 7 && txs_.count(key_of(true, v)) != 0; ++tries) {
        v = static_cast<std::uint8_t>((v + 1) % 7);
    }
    if (txs_.count(key_of(true, v)) != 0) {
        return;   // every TI in use: the next free one starts it
    }
    next_ti_ = static_cast<std::uint8_t>((v + 1) % 7);
    Pending p = std::move(queue_.front());
    queue_.pop_front();
    const std::uint8_t key = key_of(true, v);
    Tx t;
    t.ti = v;
    t.mo = true;
    t.kind = p.kind;
    t.rp_mr = p.rp_mr;
    t.tp_mr = p.tp_mr;
    txs_[key] = t;
    mo_active_ = key;
    withheld_ack_.reset();   // 5.4: this CP-DATA stands for the final CP-ACK of the last one
    if (p.kind == Kind::smma) {
        events_.emit("sms.rp.smma", cfg_.id, {{"dir", "ul"}, {"mr", str(p.rp_mr)}, {"ti", str(v)}});
    } else {
        events_.emit("sms.rp.data", cfg_.id, {{"dir", "ul"}, {"mr", str(p.rp_mr)}, {"ti", str(v)}});
    }
    send_cp_data(txs_[key], std::move(p.rpdu));
    // TS 24.011 6.3.1, 6.3.2: TR1M for RP-DATA, TRAM for RP-SMMA.
    const Millis rl = p.kind == Kind::smma ? cfg_.tram : cfg_.tr1m;
    txs_[key].rl = ex_.start_timer(rl, [this, alive = alive_, key] {
        if (*alive) {
            on_rl_timer(key);
        }
    });
}

void Sms::send_cp_data(Tx& t, Bytes rpdu) {
    sms::Cp cp;
    cp.ti = t.mo ? t.ti : static_cast<std::uint8_t>(8 | t.ti);
    cp.type = sms::CpType::data;
    cp.user_data = std::move(rpdu);
    t.cp_data = sms::encode_cp(cp);
    t.cp = CpState::wait_cp_ack;
    t.retx = 0;
    events_.emit("sms.cp.data", cfg_.id, {{"dir", "ul"}, {"ti", str(t.ti)}, {"transmission", "1"}});
    if (ports_.send) {
        (void)ports_.send(t.cp_data);
    }
    arm_tc1(key_of(t.mo, t.ti));
}

void Sms::send_cp(std::uint8_t ti_octet, sms::CpType type, Bytes data, std::uint8_t cause) {
    sms::Cp cp;
    cp.ti = ti_octet;
    cp.type = type;
    cp.user_data = std::move(data);
    cp.cause = cause;
    if (type == sms::CpType::ack) {
        events_.emit("sms.cp.ack", cfg_.id, {{"dir", "ul"}, {"ti", str(ti_octet & 7)}});
    } else {
        events_.emit("sms.cp.error", cfg_.id, {{"dir", "ul"}, {"ti", str(ti_octet & 7)}, {"cause", str(cause)}});
    }
    if (ports_.send) {
        (void)ports_.send(sms::encode_cp(cp));
    }
}

void Sms::arm_tc1(std::uint8_t key) {
    auto it = txs_.find(key);
    if (it == txs_.end()) {
        return;
    }
    if (it->second.tc1) {
        ex_.stop_timer(*it->second.tc1);
    }
    it->second.tc1 = ex_.start_timer(cfg_.tc1, [this, alive = alive_, key] {
        if (*alive) {
            on_tc1(key);
        }
    });
}

void Sms::on_tc1(std::uint8_t key) {
    auto it = txs_.find(key);
    if (it == txs_.end()) {
        return;
    }
    Tx& t = it->second;
    t.tc1.reset();
    if (t.cp != CpState::wait_cp_ack) {
        return;
    }
    if (t.retx < cfg_.cp_retransmissions) {
        // TS 24.011 5.3.2.1: the CP-DATA again, TC1* restarted.
        ++t.retx;
        events_.emit("sms.cp.data", cfg_.id, {{"dir", "ul"}, {"ti", str(t.ti)}, {"transmission", str(t.retx + 1)}});
        if (ports_.send) {
            (void)ports_.send(t.cp_data);
        }
        arm_tc1(key);
        return;
    }
    events_.emit("sms.cp.timeout", cfg_.id, {{"ti", str(t.ti)}, {"kind", kind_name(static_cast<int>(t.kind))}});
    if (t.mo) {
        events_.emit("sms.mo.done", cfg_.id, {{"result", "failed"}, {"why", "TC1*"}, {"tp_mr", str(t.tp_mr)}});
    }
    finish(key);
    start_next_mo();
}

void Sms::on_rl_timer(std::uint8_t key) {
    auto it = txs_.find(key);
    if (it == txs_.end()) {
        return;
    }
    it->second.rl.reset();
    const bool smma = it->second.kind == Kind::smma;
    // TS 24.011 6.3.1, 6.3.2: no RP answer in time: the procedure fails.
    events_.emit("sms.mo.done", cfg_.id,
                 {{"result", "failed"}, {"why", smma ? "TRAM" : "TR1M"}, {"tp_mr", str(it->second.tp_mr)}});
    finish(key);
    start_next_mo();
}

void Sms::finish(std::uint8_t key) {
    auto it = txs_.find(key);
    if (it == txs_.end()) {
        return;
    }
    if (it->second.tc1) {
        ex_.stop_timer(*it->second.tc1);
    }
    if (it->second.rl) {
        ex_.stop_timer(*it->second.rl);
    }
    txs_.erase(it);
    if (mo_active_ == key) {
        mo_active_.reset();
    }
}

// ---- from the network ----------------------------------------------------------------------

void Sms::on_downlink(ByteView in) {
    auto cp = sms::decode_cp(in);
    if (!cp) {
        events_.emit("sms.discard", cfg_.id, {{"what", cp.error().what}});
        return;
    }
    switch (cp->type) {
    case sms::CpType::data:
        on_cp_data(*cp);
        return;
    case sms::CpType::ack:
        on_cp_ack(*cp);
        return;
    case sms::CpType::error: {
        const std::uint8_t key = key_of((cp->ti & 8) != 0, cp->ti & 7);
        events_.emit("sms.cp.error", cfg_.id, {{"dir", "dl"}, {"ti", str(cp->ti & 7)}, {"cause", str(cp->cause)}});
        auto it = txs_.find(key);
        if (it != txs_.end() && it->second.mo) {
            events_.emit("sms.mo.done", cfg_.id, {{"result", "failed"}, {"why", "CP-ERROR"}, {"tp_mr", str(it->second.tp_mr)}});
        }
        finish(key);
        start_next_mo();
        return;
    }
    }
}

void Sms::on_cp_ack(const sms::Cp& cp) {
    // TS 24.007 11.2.3.1.3: the network's CP-ACK has the TI flag at 1 on a UE
    // transaction (MO), at 0 on its own (MT).
    const bool mo = (cp.ti & 8) != 0;
    const std::uint8_t key = key_of(mo, cp.ti & 7);
    events_.emit("sms.cp.ack", cfg_.id, {{"dir", "dl"}, {"ti", str(cp.ti & 7)}});
    auto it = txs_.find(key);
    if (it == txs_.end() || it->second.cp != CpState::wait_cp_ack) {
        return;
    }
    Tx& t = it->second;
    if (t.tc1) {
        ex_.stop_timer(*t.tc1);
        t.tc1.reset();
    }
    if (t.mo) {
        t.cp = CpState::connected;   // 5.3.2.1: MM-connection established, the RP answer awaited
        return;
    }
    finish(key);   // MT: the network has the RP-ACK
}

void Sms::on_cp_data(const sms::Cp& cp) {
    const bool mo = (cp.ti & 8) != 0;
    const std::uint8_t v = cp.ti & 7;
    events_.emit("sms.cp.data", cfg_.id, {{"dir", "dl"}, {"ti", str(v)}});
    auto rp = sms::decode_rp(cp.user_data);
    if (mo) {
        auto it = txs_.find(key_of(true, v));
        if (it == txs_.end()) {
            send_cp(static_cast<std::uint8_t>(v), sms::CpType::error, {}, kCpCauseInvalidTi);
            return;
        }
        Tx& t = it->second;
        if (t.tc1) {   // a CP-DATA in Wait for CP-ACK acknowledges the CP-DATA too
            ex_.stop_timer(*t.tc1);
            t.tc1.reset();
        }
        t.cp = CpState::connected;
        if (!rp) {
            events_.emit("sms.discard", cfg_.id, {{"what", rp.error().what}});
            return;
        }
        on_rp_from_network(t, *rp);
        return;
    }
    // MT: a CP-DATA on a transaction the UE already answered is a retransmission:
    // acknowledged again, not delivered again (TS 24.011 5.3.2.1).
    if (auto a = answered_mt_.find(v); a != answered_mt_.end() && a->second == cp.user_data) {
        events_.emit("sms.mt.duplicate", cfg_.id, {{"ti", str(v)}});
        send_cp(static_cast<std::uint8_t>(8 | v), sms::CpType::ack);
        return;
    }
    const std::uint8_t key = key_of(false, v);
    if (txs_.count(key) != 0) {
        finish(key);   // a new transaction on the TI replaces the old one
    }
    Tx t;
    t.ti = v;
    t.mo = false;
    t.kind = Kind::mt;
    t.cp = CpState::connected;
    t.rpdu_in = cp.user_data;
    txs_[key] = t;
    send_cp(static_cast<std::uint8_t>(8 | v), sms::CpType::ack);
    if (!rp || rp->mti != sms::RpMti::data_n_ms) {
        events_.emit("sms.discard", cfg_.id, {{"what", rp ? "not an RP-DATA" : rp.error().what}});
        finish(key);
        return;
    }
    on_mt_rp_data(txs_[key], *rp);
}

void Sms::on_rp_from_network(Tx& t, const sms::Rp& rp) {
    const std::uint8_t key = key_of(true, t.ti);
    if (t.rl) {
        ex_.stop_timer(*t.rl);
        t.rl.reset();
    }
    const bool smma = t.kind == Kind::smma;
    if (rp.mti == sms::RpMti::ack_n_ms) {
        events_.emit("sms.rp.ack", cfg_.id, {{"dir", "dl"}, {"mr", str(rp.mr)}, {"tp_mr", str(t.tp_mr)}});
        if (smma) {
            // TS 24.011 6.3.2: the network has it; EF.SMSS's flag back to "memory available".
            network_told_full_ = false;
            if (ports_.store_smss) {
                const Bytes s = ports_.smss ? ports_.smss() : Bytes{};
                ports_.store_smss(Bytes{s.empty() ? std::uint8_t{0} : s[0], 0xFF});
            }
        }
        events_.emit("sms.mo.done", cfg_.id, {{"result", "ack"}, {"tp_mr", str(t.tp_mr)}, {"kind", smma ? "smma" : "submit"}});
    } else if (rp.mti == sms::RpMti::error_n_ms) {
        const std::string cause = rp.cause.empty() ? "" : str(rp.cause[0] & 0x7F);
        events_.emit("sms.rp.error", cfg_.id, {{"dir", "dl"}, {"mr", str(rp.mr)}, {"cause", cause}});
        events_.emit("sms.mo.done", cfg_.id, {{"result", "error"}, {"cause", cause}, {"tp_mr", str(t.tp_mr)}});
    } else {
        events_.emit("sms.discard", cfg_.id, {{"what", "an RP message the MS does not expect on an MO transaction"}});
    }
    // 5.4: with another message queued its CP-DATA goes instead of the final CP-ACK.
    if (!queue_.empty()) {
        withheld_ack_ = key;
        finish(key);
        start_next_mo();
        return;
    }
    send_cp(t.ti, sms::CpType::ack);
    finish(key);
}

void Sms::on_mt_rp_data(Tx& t, const sms::Rp& rp) {
    sms::Rp out;
    out.mr = rp.mr;
    const auto tpdu = rp.user_data ? sms::decode_tpdu(*rp.user_data, sms::TpDir::sc_to_ms)
                                   : Result<sms::Tpdu>(make_error(Errc::truncated, 0, "no RP-User data"));
    const auto record = free_record();
    if (tpdu && tpdu->type == sms::TpduType::deliver && !full_ && record) {
        StoredSms s;
        s.record = *record;
        s.from = digits_of(tpdu->address.digits, tpdu->address.length);
        s.dcs = tpdu->dcs;
        s.ud = tpdu->ud;
        s.scts = tpdu->scts;
        std::size_t hdr = 0;
        if (tpdu->udhi() && !tpdu->ud.empty()) {
            hdr = std::min<std::size_t>(std::size_t{tpdu->ud[0]} + 1, tpdu->ud.size());
            // TS 23.040 9.2.3.24: the information elements; 00 is the 8-bit concatenation one.
            for (std::size_t i = 1; i + 1 < hdr;) {
                const std::uint8_t iei = tpdu->ud[i];
                const std::size_t len = tpdu->ud[i + 1];
                if (iei == 0x00 && len == 3 && i + 4 < hdr + 1) {
                    s.concat = std::array<std::uint8_t, 3>{tpdu->ud[i + 2], tpdu->ud[i + 3], tpdu->ud[i + 4]};
                }
                i += 2 + len;
            }
        }
        const ByteView body = ByteView(tpdu->ud).subspan(hdr);
        if (sms::dcs_is_ucs2(tpdu->dcs)) {
            s.text = sms::ucs2_to_utf8(body);
        } else if (sms::dcs_is_gsm7(tpdu->dcs)) {
            const std::size_t hdr_septets = (hdr * 8 + 6) / 7;
            const unsigned fill = static_cast<unsigned>(hdr_septets * 7 - hdr * 8);
            const std::size_t septets = tpdu->udl > hdr_septets ? tpdu->udl - hdr_septets : 0;
            s.text = sms::gsm7_to_utf8(body, septets, fill);
        } else {
            s.text = to_hex(body);
        }
        // TS 31.102 4.2.25: status 03 (received, unread), the service centre as RP-OA, the TPDU.
        Bytes rec;
        rec.reserve(176);   // the record's length; also keeps gcc's -Warray-bounds quiet on the inserts
        rec.push_back(0x03);
        rec.push_back(static_cast<std::uint8_t>(rp.originator.size()));
        rec.insert(rec.end(), rp.originator.begin(), rp.originator.end());
        if (rp.user_data) {   // decoded above, so present
            rec.insert(rec.end(), rp.user_data->begin(), rp.user_data->end());
        }
        rec.resize(std::max<std::size_t>(rec.size(), 176), 0xFF);
        rec.resize(176);
        if (ports_.store) {
            ports_.store(*record, rec);
        }
        stored_.push_back(s);
        events_.emit("sms.mt.deliver", cfg_.id,
                     {{"from", s.from},
                      {"record", str(s.record)},
                      {"dcs", str(s.dcs)},
                      {"ud", to_hex(s.ud)},
                      {"concat", s.concat ? str((*s.concat)[2]) + "/" + str((*s.concat)[1]) : ""},
                      {"text", s.text}});
        out.mti = sms::RpMti::ack_ms_n;   // TS 24.011 7.3.3
        events_.emit("sms.rp.ack", cfg_.id, {{"dir", "ul"}, {"mr", str(rp.mr)}});
    } else {
        // TS 24.011 7.3.4, 8.2.5.4: RP-ERROR; #22 memory capacity exceeded when there is no room.
        out.mti = sms::RpMti::error_ms_n;
        const bool no_room = full_ || !record;
        out.cause = Bytes{no_room ? kRpCauseMemoryExceeded : std::uint8_t{111}};
        if (no_room) {
            network_told_full_ = true;   // TS 31.102 4.2.28: the notification flag, memory exceeded
            if (ports_.store_smss) {
                const Bytes s = ports_.smss ? ports_.smss() : Bytes{};
                ports_.store_smss(Bytes{s.empty() ? std::uint8_t{0} : s[0], 0xFE});
            }
        }
        events_.emit("sms.rp.error", cfg_.id, {{"dir", "ul"}, {"mr", str(rp.mr)}, {"cause", str(out.cause[0])}});
    }
    answered_mt_[t.ti] = t.rpdu_in;
    send_cp_data(t, sms::encode_rp(out));
}

std::optional<std::uint8_t> Sms::free_record() const {
    for (std::size_t r = 1; r <= cfg_.records; ++r) {
        const bool used = std::any_of(stored_.begin(), stored_.end(), [r](const StoredSms& s) { return s.record == r; });
        if (!used) {
            return static_cast<std::uint8_t>(r);
        }
    }
    return std::nullopt;
}

void Sms::memory(bool full) {
    full_ = full;
    if (!network_told_full_ && ports_.smss) {
        // EF.SMSS may say so from before a power cycle (TS 31.102 4.2.28: bit 1 at 0).
        const Bytes s = ports_.smss();
        network_told_full_ = s.size() > 1 && (s[1] & 0x01) == 0;
    }
    events_.emit("sms.memory", cfg_.id, {{"full", full ? "1" : "0"}, {"network_told", network_told_full_ ? "1" : "0"}});
    if (full || !network_told_full_) {
        return;
    }
    // TS 24.011 6.3.2: memory available again: RP-SMMA (needs SMS over NAS allowed).
    if (ports_.allowed && !ports_.allowed()) {
        return;
    }
    sms::Rp rp;
    rp.mti = sms::RpMti::smma_ms_n;
    rp.mr = ++rp_mr_;
    queue_.push_back(Pending{Kind::smma, sms::encode_rp(rp), rp.mr, 0, ""});
    start_next_mo();
}

} // namespace ksim::proc::ue
