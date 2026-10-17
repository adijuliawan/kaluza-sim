// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/topology.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>

#include "platform/yaml.hpp"

namespace ksim::node {

namespace {

bool all_digits(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

} // namespace

const char* role_name(Role r) noexcept {
    switch (r) {
    case Role::cucp: return "cucp";
    case Role::cuup: return "cuup";
    case Role::du: return "du";
    case Role::ue: return "ue";
    case Role::all: break;
    }
    return "all";
}

std::optional<Role> parse_role(const std::string& s) {
    for (Role r : {Role::all, Role::cucp, Role::cuup, Role::du, Role::ue}) {
        if (s == role_name(r)) {
            return r;
        }
    }
    return std::nullopt;
}

std::string resolve_path(const std::string& p, const std::string& base_dir) {
    if (p.rfind("~/", 0) == 0) {
        const char* home = std::getenv("HOME");   // NOLINT(concurrency-mt-unsafe): read at start-up only
        return std::string(home != nullptr ? home : "") + p.substr(1);
    }
    if (!p.empty() && p.front() == '/') {
        return p;
    }
    return (std::filesystem::path(base_dir) / p).lexically_normal().string();
}

Result<Topology> load_topology(const std::string& file, std::string& why) {
    try {
        const Yaml y = Yaml::load_file(file);
        y.only({"plmn", "seed", "amf", "gnbs", "ues", "secrets", "peer", "security", "netd", "mode", "watchdog_ms", "farm",
                "capture", "link"});
        const std::string base = std::filesystem::path(file).parent_path().string();
        Topology t;
        t.file = file;
        const std::string plmn = y.at("plmn").as<std::string>();
        if (!all_digits(plmn) || (plmn.size() != 5 && plmn.size() != 6)) {
            y.at("plmn").fail("a PLMN is MCC and MNC digits, 5 or 6 of them");
        }
        t.mcc = plmn.substr(0, 3);
        t.mnc = plmn.substr(3);
        t.seed = y.get<std::uint64_t>("seed", 0);

        const Yaml amfs = y.at("amf");
        if (!amfs.is_seq() || amfs.size() != 1) {
            amfs.fail("P1 serves one AMF");
        }
        amfs.at(0).only({"addr", "port"});
        auto amf = Endpoint::parse(amfs.at(0).at("addr").as<std::string>(), amfs.at(0).get<std::uint16_t>("port", 38412));
        if (!amf) {
            amfs.at(0).at("addr").fail("not a numeric address");
        }
        t.amf = *amf;

        const Yaml gnbs = y.at("gnbs");
        if (!gnbs.is_seq() || gnbs.size() != 1) {
            gnbs.fail("P1 runs one gNB");
        }
        const Yaml g = gnbs.at(0);
        g.only({"id", "name", "cucp", "cuup", "dus", "split", "peers"});
        if (y.has("mode")) {
            const std::string m = y.at("mode").as<std::string>();
            if (m != "aio" && m != "split") {
                y.at("mode").fail("aio or split");
            }
            t.mode = m == "split" ? Mode::split : Mode::aio;
        }
        if (g.has("split")) {
            const Yaml sp = g.at("split");
            sp.only({"f1c", "e1", "du", "cuup", "cuup_e1", "streams"});
            auto addr = [&sp](const char* key, Endpoint& e) {
                if (!sp.has(key)) {
                    return;
                }
                auto a = Endpoint::parse(sp.at(key).as<std::string>(), e.port);
                if (!a || a->family != Endpoint::Family::v4) {
                    sp.at(key).fail("a numeric IPv4 address");
                }
                e = *a;
            };
            addr("f1c", t.split.f1c_listen);
            addr("e1", t.split.e1_listen);
            addr("du", t.split.du);
            addr("cuup", t.split.cuup_f1u);
            addr("cuup_e1", t.split.cuup_e1);
            t.split.streams = sp.get<std::uint16_t>("streams", t.split.streams);
            if (t.split.streams < 2) {
                sp.at("streams").fail("at least 2: stream 0 and one for the UEs");
            }
        }
        if (g.has("peers")) {
            const Yaml p = g.at("peers");
            p.only({"cucp", "cuup"});
            for (const auto& [key, out] : {std::pair<const char*, std::string*>{"cucp", &t.peer_cucp}, {"cuup", &t.peer_cuup}}) {
                if (p.has(key)) {
                    *out = p.at(key).as<std::string>();
                    if (*out != "ocudu") {
                        p.at(key).fail("ocudu (ADR 0012)");
                    }
                }
            }
            if (t.mode != Mode::split) {
                p.fail("peers run with mode: split");
            }
        }
        g.at("id").only({"value", "bits"});
        t.gnb_id = g.at("id").at("value").as<std::uint32_t>();
        t.gnb_id_bits = g.at("id").get<std::uint8_t>("bits", 22);
        if (t.gnb_id_bits < 22 || t.gnb_id_bits > 32 || (t.gnb_id_bits < 32 && (t.gnb_id >> t.gnb_id_bits) != 0)) {
            g.at("id").fail("a gNB ID is 22 to 32 bits and fits them");
        }
        t.gnb_name = g.get<std::string>("name", t.gnb_name);
        // A peer CU-CP (P2 Q4) has its own N2 and N3 addresses in its config, not here.
        if (t.peer_cucp.empty() || g.has("cucp")) {
            g.at("cucp").only({"ng_bind", "ng_streams", "ue_inactivity_s", "nea", "nia", "t_reordering_ms", "up_policy", "drb_map",
                                "gbr_budget_kbps"});
            t.gbr_budget_kbps = g.at("cucp").get<std::uint64_t>("gbr_budget_kbps", t.gbr_budget_kbps);   // P2 Q11 (KS-RRC-B7)
            if (g.at("cucp").has("drb_map")) {
                // P2 Q10: the QoS flow to DRB mapping (KS-RRC-B6): a DRB per 5QI, or one per session.
                const std::string m = g.at("cucp").at("drb_map").as<std::string>();
                if (m != "per-5qi" && m != "per-session") {
                    g.at("cucp").at("drb_map").fail("per-5qi or per-session");
                }
                t.drb_map = m == "per-session" ? proc::ran::DrbMap::per_session : proc::ran::DrbMap::per_5qi;
            }
            if (g.at("cucp").has("up_policy")) {
                // P2 Q9: the CU-CP's local UP security policy (proc/ran/up_security.hpp, KS-NGAP-B8).
                const Yaml u = g.at("cucp").at("up_policy");
                u.only({"preferred_integrity", "preferred_confidentiality", "absent_integrity", "absent_confidentiality",
                        "integrity_possible"});
                auto& p = t.up_policy;
                p.preferred_integrity = u.get<bool>("preferred_integrity", p.preferred_integrity);
                p.preferred_confidentiality = u.get<bool>("preferred_confidentiality", p.preferred_confidentiality);
                p.absent_integrity = u.get<bool>("absent_integrity", p.absent_integrity);
                p.absent_confidentiality = u.get<bool>("absent_confidentiality", p.absent_confidentiality);
                p.integrity_possible = u.get<bool>("integrity_possible", p.integrity_possible);
            }
            auto bind = Endpoint::parse(g.at("cucp").at("ng_bind").as<std::string>(), 0);
            if (!bind || bind->family != t.amf.family) {
                g.at("cucp").at("ng_bind").fail("a numeric address of the AMF's family");
            }
            t.ng_bind = *bind;
            t.ng_streams = g.at("cucp").get<std::uint16_t>("ng_streams", t.ng_streams);
            t.ue_inactivity_s = g.at("cucp").get<std::uint16_t>("ue_inactivity_s", t.ue_inactivity_s);
            if (t.ue_inactivity_s < 1 || t.ue_inactivity_s > 7200) {
                g.at("cucp").at("ue_inactivity_s").fail("1..7200 s (TS 37.483 9.3.1.54)");
            }
            // P2 Q8: the DRBs' t-Reordering (TS 38.331 PDCP-Config's values; absent: infinity).
            if (g.at("cucp").has("t_reordering_ms")) {
                static constexpr int kValues[] = {0,   1,   2,   4,   5,   8,   10,   15,   20,   30,   40,   50,
                                                  60,  80,  100, 120, 140, 160, 180,  200,  220,  240,  260,  280,
                                                  300, 500, 750, 1000, 1250, 1500, 1750, 2000, 2250, 2500, 2750, 3000};
                const int v = g.at("cucp").at("t_reordering_ms").as<int>();
                if (std::find(std::begin(kValues), std::end(kValues), v) == std::end(kValues)) {
                    g.at("cucp").at("t_reordering_ms").fail("one of PDCP-Config's t-Reordering values (0..3000 ms, TS 38.331)");
                }
                t.t_reordering_ms = v;
            }
            // P2 Q8: the AS algorithms the CU-CP prefers, first that the UE supports wins
            // (TS 33.501 6.7.3.1). 0 only with security: {allow_null: true}, checked below;
            // 3 (ZUC) is the declared gap KS-SEC-G1.
            for (const auto& [key, out] : {std::pair<const char*, std::vector<std::uint8_t>*>{"nea", &t.nea_pref},
                                           {"nia", &t.nia_pref}}) {
                if (!g.at("cucp").has(key)) {
                    continue;
                }
                const Yaml l = g.at("cucp").at(key);
                if (!l.is_seq() || l.size() == 0 || l.size() > 3) {
                    l.fail("a list of 1 to 3 algorithms, e.g. [1, 2]");
                }
                out->clear();
                t.alg_pref_given = true;
                for (std::size_t i = 0; i < l.size(); ++i) {
                    const auto a = l.at(i).as<std::uint8_t>();
                    if (a > 2) {
                        l.at(i).fail("0, 1 or 2 (3, ZUC, is the declared gap KS-SEC-G1)");
                    }
                    if (std::find(out->begin(), out->end(), a) != out->end()) {
                        l.at(i).fail("each algorithm once");
                    }
                    out->push_back(a);
                }
            }
        }
        // N3 (P1 N10): the CU-UP's address, GTP-U's port; by default the CU-CP's address.
        t.n3_bind = Endpoint::v4(t.ng_bind.addr[0], t.ng_bind.addr[1], t.ng_bind.addr[2], t.ng_bind.addr[3], 2152);
        if (g.has("cuup")) {
            g.at("cuup").only({"n3_bind"});
            auto n3 = Endpoint::parse(g.at("cuup").at("n3_bind").as<std::string>(), 2152);
            if (!n3 || n3->family != Endpoint::Family::v4) {
                g.at("cuup").at("n3_bind").fail("a numeric IPv4 address (P1 N3 is IPv4)");
            }
            t.n3_bind = *n3;
        }
        // P3 R4 (ADR 0013 point 1, D7): one or more DUs, one cell each.
        const Yaml dus = g.at("dus");
        if (!dus.is_seq() || dus.size() < 1 || dus.size() > 8) {
            dus.fail("a gNB has 1 to 8 DUs");
        }
        t.dus.clear();
        for (std::size_t i = 0; i < dus.size(); ++i) {
            const Yaml d = dus.at(i);
            d.only({"id", "cells", "split"});
            if (d.at("cells").size() != 1) {
                d.fail("a DU serves one cell (D7: a multi-cell site is several DUs)");
            }
            DuCell c;
            c.id = d.get<std::uint64_t>("id", i + 1);
            c.nci_cell = static_cast<std::uint32_t>(i + 1);
            c.split_du = i == 0 ? t.split.du : Endpoint::v4(127, 0, 10, static_cast<std::uint8_t>(9 + i + 1), 2152);
            const Yaml cell = d.at("cells").at(0);
            cell.only({"pci", "tac", "arfcn", "ssb_arfcn", "nci_cell", "power_dbm"});
            c.pci = cell.get<std::uint16_t>("pci", static_cast<std::uint16_t>(101 + i));
            c.tac = cell.get<std::uint32_t>("tac", c.tac);
            c.arfcn = cell.get<std::uint32_t>("arfcn", c.arfcn);
            c.ssb_arfcn = cell.get<std::uint32_t>("ssb_arfcn", c.ssb_arfcn);
            c.nci_cell = cell.get<std::uint32_t>("nci_cell", c.nci_cell);
            const int power = cell.get<int>("power_dbm", c.power_dbm);
            if (c.pci > 1007 || c.tac > 0xFFFFFF || power < -156 || power > -31) {
                cell.fail("PCI 0..1007, TAC 24 bits, power_dbm -156..-31 (TS 38.133's SS-RSRP range)");
            }
            c.power_dbm = static_cast<std::int16_t>(power);
            if (c.nci_cell == 0 || (std::uint64_t{c.nci_cell} >> (36U - t.gnb_id_bits)) != 0) {
                cell.fail("nci_cell is 1.. and fits the NCI's bits past the gNB ID's");
            }
            if (d.has("split")) {
                d.at("split").only({"du"});
                auto a = Endpoint::parse(d.at("split").at("du").as<std::string>(), 2152);
                if (!a || a->family != Endpoint::Family::v4) {
                    d.at("split").at("du").fail("a numeric IPv4 address");
                }
                c.split_du = *a;
            }
            for (const DuCell& o : t.dus) {
                if (o.id == c.id || o.pci == c.pci || o.nci_cell == c.nci_cell || o.split_du == c.split_du) {
                    d.fail("each DU has its own id, PCI, nci_cell and split address");
                }
            }
            t.dus.push_back(c);
        }

        const Yaml ues = y.at("ues");
        for (std::size_t i = 0; i < ues.size(); ++i) {
            const Yaml u = ues.at(i);
            u.only({"group", "count", "range", "card", "nssai", "imeisv_tac", "persona", "hears"});
            UeGroup grp;
            grp.group = u.get<std::string>("group", "ues");
            grp.count = u.get<unsigned>("count", 1);
            grp.first_imsi = u.at("range").as<std::string>();
            if (!all_digits(grp.first_imsi) || grp.first_imsi.size() != 15 || grp.count == 0 || grp.count > 1000) {
                u.fail("a range is a 15-digit first IMSI, and a count 1..1000");
            }
            const Yaml card = u.at("card");
            card.only({"template", "pcsc", "bridge"});
            if (card.has("template") + card.has("pcsc") + card.has("bridge") != 1) {
                card.fail("a card is one of template, pcsc or bridge");
            }
            if (card.has("template")) {
                grp.card_template = resolve_path(card.at("template").as<std::string>(), base);
            } else {
                // P2 Q1: a card outside the process is one card, so its group holds one UE.
                if (grp.count != 1) {
                    card.fail("a pcsc or bridge card serves one UE (count: 1)");
                }
                if (card.has("pcsc")) {
                    card.at("pcsc").only({"reader"});
                    grp.card_pcsc = card.at("pcsc").at("reader").as<std::string>();
                } else {
                    grp.card_bridge = card.at("bridge").as<std::string>();
                    if (!Endpoint::parse(grp.card_bridge)) {
                        card.fail("a bridge is host:port");
                    }
                }
            }
            if (u.has("persona")) {
                grp.persona = resolve_path(u.at("persona").as<std::string>(), base);   // N15
            }
            if (u.has("nssai")) {
                grp.nssai.clear();
                for (std::size_t k = 0; k < u.at("nssai").size(); ++k) {
                    const Yaml e = u.at("nssai").at(k);
                    const std::string s = e.as<std::string>();
                    const auto dash = s.find('-');
                    const std::string sst = s.substr(0, dash);
                    const std::string sd = dash == std::string::npos ? "" : s.substr(dash + 1);
                    if (!all_digits(sst) || sst.size() > 3 || std::stoul(sst) > 255 ||
                        (dash != std::string::npos && (sd.size() != 6 || sd.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos))) {
                        e.fail("an S-NSSAI is an SST (0..255) or SST-SD with six hex digits");
                    }
                    Slice sl;
                    sl.sst = static_cast<std::uint8_t>(std::stoul(sst));
                    if (!sd.empty()) {
                        sl.sd = static_cast<std::uint32_t>(std::stoul(sd, nullptr, 16));
                    }
                    grp.nssai.push_back(sl);
                }
            }
            if (u.has("hears")) {
                // P3 R4: the group's levels in the static view, by DU id ("off": not heard).
                const Yaml h = u.at("hears");
                for (const std::string& k : h.keys()) {
                    if (!all_digits(k) || std::none_of(t.dus.begin(), t.dus.end(),
                                                       [&](const DuCell& c) { return std::to_string(c.id) == k; })) {
                        h.fail("hears is keyed by the gNB's DU ids");
                    }
                    const std::string v = h.at(k).as<std::string>();
                    if (v == "off") {
                        grp.hears[std::stoull(k)] = std::nullopt;
                        continue;
                    }
                    const int dbm = h.at(k).as<int>();
                    if (dbm < -156 || dbm > -31) {
                        h.at(k).fail("a level is -156..-31 dBm, or off");
                    }
                    grp.hears[std::stoull(k)] = static_cast<std::int16_t>(dbm);
                }
            }
            grp.imeisv_tac = u.get<std::string>("imeisv_tac", grp.imeisv_tac);
            if (!all_digits(grp.imeisv_tac) || grp.imeisv_tac.size() != 8) {
                u.fail("imeisv_tac is 8 digits");
            }
            t.ues.push_back(std::move(grp));
        }

        const Yaml sec = y.at("secrets");
        sec.only({"sealed", "kek"});
        t.sealed_dir = resolve_path(sec.at("sealed").as<std::string>(), base);
        t.kek_file = resolve_path(sec.at("kek").as<std::string>(), base);
        if (y.has("peer")) {
            for (const auto& k : y.at("peer").keys()) {
                t.peer[k] = y.at("peer").at(k).as<std::string>();
            }
        }
        if (y.has("netd")) {
            const Yaml n = y.at("netd");
            n.only({"socket", "netns", "cuup_netns", "parent", "prefix", "nodes", "ues", "du_netns", "mid", "mid_prefix"});
            t.netd.enabled = true;
            t.netd.socket = n.get<std::string>("socket", t.netd.socket);
            t.netd.netns = n.get<std::string>("netns", t.netd.netns);
            t.netd.cuup_netns = n.get<std::string>("cuup_netns", t.netd.cuup_netns);
            t.netd.nodes = n.get<bool>("nodes", true);
            t.netd.ues = n.get<bool>("ues", true);
            t.netd.parent = n.get<std::string>("parent", "");
            t.netd.prefix = n.get<std::uint8_t>("prefix", 24);
            t.netd.du_netns = n.get<std::string>("du_netns", t.netd.du_netns);
            t.netd.mid = n.get<bool>("mid", false);
            t.netd.mid_prefix = n.get<std::uint8_t>("mid_prefix", 24);
            if (t.netd.netns.rfind("ksim-", 0) != 0 || t.netd.cuup_netns.rfind("ksim-", 0) != 0 ||
                t.netd.cuup_netns == t.netd.netns || (t.peer_cucp.empty() && t.ng_bind.family != Endpoint::Family::v4) ||
                t.netd.prefix > 32) {
                // A peer CU-CP (P2 Q7, LW2) has its N2 address in its own config.
                n.fail("netd needs a ksim- namespace, an IPv4 ng_bind and a prefix up to 32");
            }
            // P2 Q6: split roles in namespaces of their own reach each other over ksim-mid only.
            if (t.mode == Mode::split && t.netd.nodes) {
                const auto same = [](const Endpoint& a, const Endpoint& b) {
                    return std::equal(a.addr.begin(), a.addr.begin() + 4, b.addr.begin());
                };
                if (!t.netd.mid) {
                    n.fail("split with node namespaces needs mid: true (ksim-mid, kaluza-uesim); "
                           "on the dev PC the roles stay in the root namespace (nodes: false)");
                }
                if (t.netd.du_netns.rfind("ksim-", 0) != 0 || t.netd.du_netns == t.netd.netns ||
                    t.netd.du_netns == t.netd.cuup_netns || t.netd.mid_prefix < 8 || t.netd.mid_prefix > 30 ||
                    !same(t.split.f1c_listen, t.split.e1_listen) || !same(t.split.cuup_f1u, t.split.cuup_e1)) {
                    n.fail("with mid, a ksim- DU namespace of its own, a mid prefix 8..30, the CU-CP's F1-C and E1 "
                           "on one address (its leg) and the CU-UP's F1-U and E1 on one (its leg)");
                }
            }
        }
        t.watchdog_ms = y.get<std::uint32_t>("watchdog_ms", t.watchdog_ms);
        if (y.has("capture")) {
            // P2 Q8 (ADR 0011): the user plane's capture, full for the gates, headers for
            // performance runs, or off.
            y.at("capture").only({"user_plane"});
            const auto up = y.at("capture").get<std::string>("user_plane", "full");
            if (up == "full") {
                t.capture_up = UserPlaneCapture::full;
            } else if (up == "headers") {
                t.capture_up = UserPlaneCapture::headers;
            } else if (up == "off") {
                t.capture_up = UserPlaneCapture::off;
            } else {
                y.at("capture").at("user_plane").fail("full, headers or off");
            }
        }
        if (y.has("link")) {
            // P2 Q12 (architecture §5): the ideal link's in-memory hops, 1 ms each by default
            // plus a seeded jitter; the performance runs set 0 (§3.5 excludes it).
            y.at("link").only({"delay_ms", "jitter_ms"});
            t.link_delay_ms = y.at("link").get<int>("delay_ms", t.link_delay_ms);
            t.link_jitter_ms = y.at("link").get<int>("jitter_ms", t.link_jitter_ms);
            if (t.link_delay_ms < 0 || t.link_delay_ms > 1000 || t.link_jitter_ms < 0 || t.link_jitter_ms > 1000) {
                y.at("link").fail("delay_ms and jitter_ms 0..1000");
            }
        }
        if (y.has("farm")) {
            y.at("farm").only({"shards"});
            t.farm_shards = y.at("farm").get<unsigned>("shards", 1);
            const bool readers = std::any_of(t.ues.begin(), t.ues.end(), [](const UeGroup& ug) {
                return !ug.card_pcsc.empty() || !ug.card_bridge.empty();
            });
            if (t.farm_shards < 1 || t.farm_shards > 8 || (t.farm_shards > 1 && (t.mode != Mode::split || readers))) {
                y.at("farm").fail("1..8 shards; more than one in a split run only, and none with a pcsc: or bridge: card");
            }
        }
        if (y.has("security")) {
            y.at("security").only({"allow_null"});
            t.allow_null = y.at("security").get<bool>("allow_null", false);
        }
        const auto has_null = [](const std::vector<std::uint8_t>& l) { return std::find(l.begin(), l.end(), 0) != l.end(); };
        if (t.alg_pref_given && !t.allow_null && (has_null(t.nea_pref) || has_null(t.nia_pref))) {
            y.at("gnbs").at(0).at("cucp").fail("NEA0 or NIA0 needs security: {allow_null: true} (the bisect switch, D1)");
        }
        return t;
    } catch (const YamlError& e) {
        why = e.what();
        return make_error(Errc::invalid_argument, 0, "the topology is not valid");
    }
}

} // namespace ksim::node
