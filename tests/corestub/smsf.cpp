// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "smsf.hpp"

#include <algorithm>
#include <utility>

namespace ksim::corestub {

namespace {

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

std::uint8_t semi(unsigned v) { return static_cast<std::uint8_t>((v % 10) << 4 | (v / 10) % 10); }

} // namespace

Smsf::Smsf(Link link, std::string sc) : link_(std::move(link)), sc_(std::move(sc)) {}

void Smsf::check(bool ok, const char* clause, const char* what, std::string detail) {
    verdicts_.push_back(Verdict{clause, what, ok, std::move(detail)});
}

std::vector<Verdict> Smsf::failures() const {
    std::vector<Verdict> out;
    std::copy_if(verdicts_.begin(), verdicts_.end(), std::back_inserter(out), [](const Verdict& v) { return !v.ok; });
    return out;
}

std::size_t Smsf::pending(const std::string& supi) const {
    auto it = ues_.find(supi);
    return it == ues_.end() ? 0 : it->second.mt.size();
}

Bytes Smsf::sc_address() const {
    Bytes a{0x91};
    const Bytes d = bcd(sc_);
    a.insert(a.end(), d.begin(), d.end());
    return a;
}

Bytes Smsf::scts() const {
    // TS 23.040 9.2.3.11: a fixed date, the time of day from the stub's clock, GMT.
    const std::uint64_t s = (link_.now_ms ? link_.now_ms() : 0) / 1000;
    return {semi(26), semi(10), semi(15), semi(static_cast<unsigned>(s / 3600 % 24)),
            semi(static_cast<unsigned>(s / 60 % 60)), semi(static_cast<unsigned>(s % 60)), 0x00};
}

void Smsf::send(const std::string& supi, std::uint8_t ti_octet, sms::CpType type, Bytes data) {
    sms::Cp cp;
    cp.ti = ti_octet;
    cp.type = type;
    cp.user_data = std::move(data);
    if (link_.to_ue) {
        (void)link_.to_ue(supi, sms::encode_cp(cp));
    }
}

void Smsf::on_uplink(const std::string& supi, ByteView in) {
    auto cp = sms::decode_cp(in);
    check(cp.has_value(), "TS 24.011 7.2", "the UE's CP message decodes", cp ? "" : cp.error().what);
    if (!cp) {
        return;
    }
    const bool ue_ti = (cp->ti & 8) == 0;   // TI flag 0: a transaction the UE allocated (MO)
    const std::uint8_t v = cp->ti & 7;
    check(v != 7, "TS 24.007 11.2.3.1.3", "the TI value is 0 to 6");
    if (cp->type == sms::CpType::data) {
        // TS 24.011 5.3.2.2: every CP-DATA is acknowledged.
        send(supi, static_cast<std::uint8_t>(ue_ti ? 8 | v : v), sms::CpType::ack);
        auto rp = sms::decode_rp(cp->user_data);
        check(rp.has_value(), "TS 24.011 7.3", "the RPDU in CP-DATA decodes", rp ? "" : rp.error().what);
        if (!rp) {
            return;
        }
        if (ue_ti) {
            on_mo(supi, v, *rp);
        } else {
            on_mt_answer(supi, v, *rp);
        }
        return;
    }
    if (cp->type == sms::CpType::ack) {
        if (!ue_ti) {
            // The UE's CP-ACK for the CP-DATA carrying our RP-DATA.
            auto& u = ues_[supi];
            if (!u.mt.empty() && u.mt.front().sent && u.mt.front().ti == v) {
                u.mt.front().ue_acked = true;
            }
        }
        return;   // the UE's final CP-ACK of its MO transaction ends it
    }
    check(false, "TS 24.011 7.2.3", "the UE sends no CP-ERROR in the stub's flows", std::to_string(cp->cause));
}

void Smsf::on_mo(const std::string& supi, std::uint8_t ti, const sms::Rp& rp) {
    auto& u = ues_[supi];
    sms::Rp out;
    out.mr = rp.mr;
    if (rp.mti == sms::RpMti::smma_ms_n) {
        // TS 24.011 6.3.2: memory available: RP-ACK, then what waited.
        u.memory_full = false;
        out.mti = sms::RpMti::ack_n_ms;
        send(supi, static_cast<std::uint8_t>(8 | ti), sms::CpType::data, sms::encode_rp(out));
        flush(supi);
        return;
    }
    check(rp.mti == sms::RpMti::data_ms_n, "TS 24.011 7.3.1.2", "the UE's RPDU on its transaction is RP-DATA or RP-SMMA");
    if (rp.mti != sms::RpMti::data_ms_n || !rp.user_data) {
        return;
    }
    // L7: RP-DA names the service centre (TS 24.011 7.3.1.2; from EF.SMSP).
    const bool da_ok = rp.destination == sc_address();
    check(da_ok, "TS 24.011 7.3.1.2, 8.2.5.2", "RP-Destination Address is the service centre", to_hex(rp.destination));
    auto t = sms::decode_tpdu(*rp.user_data, sms::TpDir::ms_to_sc);
    check(t && t->type == sms::TpduType::submit, "TS 23.040 9.2.2.2", "the RP-DATA carries an SMS-SUBMIT");
    std::string dest_supi;
    if (t && link_.supi_of) {
        dest_supi = link_.supi_of(digits_of(t->address.digits, t->address.length));
    }
    if (!da_ok || !t || t->type != sms::TpduType::submit || dest_supi.empty()) {
        // TS 24.011 8.2.5.4: #21 short message transfer rejected, #1 unassigned number.
        out.mti = sms::RpMti::error_n_ms;
        out.cause = Bytes{static_cast<std::uint8_t>(!da_ok || !t ? 21 : 1)};
        send(supi, static_cast<std::uint8_t>(8 | ti), sms::CpType::data, sms::encode_rp(out));
        return;
    }
    ++submits_;
    // The SC's SMS-DELIVER: the submitter's MSISDN as TP-OA, TP-PID, TP-DCS and
    // TP-UD as submitted (TS 23.040 9.2.2.1), TP-MMS set (no more messages).
    sms::Tpdu d;
    d.type = sms::TpduType::deliver;
    d.first = static_cast<std::uint8_t>(0x04 | (t->udhi() ? 0x40 : 0x00));
    const std::string from = link_.msisdn_of ? link_.msisdn_of(supi) : std::string();
    d.address = sms::Address{static_cast<std::uint8_t>(from.size()), 0x91, bcd(from)};
    d.pid = t->pid;
    d.dcs = t->dcs;
    d.has_pid = d.has_dcs = d.has_ud = true;
    d.scts = scts();
    d.udl = t->udl;
    d.ud = t->ud;
    sms::Rp mt;
    mt.mti = sms::RpMti::data_n_ms;
    auto& dest = ues_[dest_supi];
    mt.mr = ++dest.mr;
    mt.originator = sc_address();
    mt.user_data = sms::encode_tpdu(d);
    dest.mt.push_back(Mt{sms::encode_rp(mt), 0, false, false});
    // The SC has it: RP-ACK to the submitter (TS 24.011 7.3.3).
    out.mti = sms::RpMti::ack_n_ms;
    send(supi, static_cast<std::uint8_t>(8 | ti), sms::CpType::data, sms::encode_rp(out));
    flush(dest_supi);
}

void Smsf::on_mt_answer(const std::string& supi, std::uint8_t ti, const sms::Rp& rp) {
    auto& u = ues_[supi];
    if (u.mt.empty() || !u.mt.front().sent || u.mt.front().ti != ti) {
        check(false, "TS 24.011 5.3.2.2", "the UE answers on the TI of the stub's RP-DATA");
        return;
    }
    check(u.mt.front().ue_acked, "TS 24.011 5.3.2.2", "the UE acknowledged the CP-DATA before answering on it");
    if (rp.mti == sms::RpMti::ack_ms_n) {
        ++delivered_;
        u.mt.pop_front();
        flush(supi);
        return;
    }
    check(rp.mti == sms::RpMti::error_ms_n, "TS 24.011 7.3.3, 7.3.4", "the UE answers RP-DATA with RP-ACK or RP-ERROR");
    if (rp.mti == sms::RpMti::error_ms_n && !rp.cause.empty() && (rp.cause[0] & 0x7F) == 22) {
        // Memory capacity exceeded: the message waits for RP-SMMA.
        u.memory_full = true;
        u.mt.front().sent = false;
        u.mt.front().ue_acked = false;
        return;
    }
    u.mt.pop_front();   // another error: the SC gives up on it
    flush(supi);
}

void Smsf::on_connected(const std::string& supi) { flush(supi); }

bool Smsf::deliver(const std::string& to_supi, const std::string& from, const std::string& text) {
    auto g = sms::utf8_to_gsm7(text);
    if (!g || g->second > 160) {
        return false;
    }
    sms::Tpdu d;
    d.type = sms::TpduType::deliver;
    d.first = 0x04;
    d.address = sms::Address{static_cast<std::uint8_t>(from.size()), 0x91, bcd(from)};
    d.has_pid = d.has_dcs = d.has_ud = true;
    d.scts = scts();
    d.udl = static_cast<std::uint8_t>(g->second);
    d.ud = g->first;
    auto& u = ues_[to_supi];
    sms::Rp mt;
    mt.mti = sms::RpMti::data_n_ms;
    mt.mr = ++u.mr;
    mt.originator = sc_address();
    mt.user_data = sms::encode_tpdu(d);
    u.mt.push_back(Mt{sms::encode_rp(mt), 0, false, false});
    flush(to_supi);
    return true;
}

void Smsf::flush(const std::string& supi) {
    auto it = ues_.find(supi);
    if (it == ues_.end() || it->second.mt.empty() || it->second.memory_full) {
        return;
    }
    Ue& u = it->second;
    Mt& m = u.mt.front();
    if (m.sent) {
        return;   // one MT transaction at a time
    }
    m.ti = u.next_ti;
    u.next_ti = static_cast<std::uint8_t>((u.next_ti + 1) % 7);
    sms::Cp cp;
    cp.ti = m.ti;   // TI flag 0: the network's transaction
    cp.type = sms::CpType::data;
    cp.user_data = m.rpdu;
    if (link_.to_ue && link_.to_ue(supi, sms::encode_cp(cp))) {
        m.sent = true;
        return;
    }
    if (link_.page) {
        link_.page(supi);   // idle: paged, then served from on_connected
    }
}

} // namespace ksim::corestub
