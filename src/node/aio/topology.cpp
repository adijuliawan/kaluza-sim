// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/topology.hpp"

#include <cstdlib>
#include <filesystem>

#include "platform/yaml.hpp"

namespace ksim::node {

namespace {

bool all_digits(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

} // namespace

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
        y.only({"plmn", "seed", "amf", "gnbs", "ues", "secrets", "peer", "security", "netd"});
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
        g.only({"id", "name", "cucp", "cuup", "dus"});
        g.at("id").only({"value", "bits"});
        t.gnb_id = g.at("id").at("value").as<std::uint32_t>();
        t.gnb_id_bits = g.at("id").get<std::uint8_t>("bits", 22);
        if (t.gnb_id_bits < 22 || t.gnb_id_bits > 32 || (t.gnb_id_bits < 32 && (t.gnb_id >> t.gnb_id_bits) != 0)) {
            g.at("id").fail("a gNB ID is 22 to 32 bits and fits them");
        }
        t.gnb_name = g.get<std::string>("name", t.gnb_name);
        g.at("cucp").only({"ng_bind", "ng_streams"});
        auto bind = Endpoint::parse(g.at("cucp").at("ng_bind").as<std::string>(), 0);
        if (!bind || bind->family != t.amf.family) {
            g.at("cucp").at("ng_bind").fail("a numeric address of the AMF's family");
        }
        t.ng_bind = *bind;
        t.ng_streams = g.at("cucp").get<std::uint16_t>("ng_streams", 2);
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
        const Yaml dus = g.at("dus");
        if (!dus.is_seq() || dus.size() != 1 || dus.at(0).at("cells").size() != 1) {
            dus.fail("P1 runs one DU with one cell");
        }
        dus.at(0).only({"id", "cells"});
        t.du_id = dus.at(0).get<std::uint64_t>("id", 1);
        const Yaml cell = dus.at(0).at("cells").at(0);
        cell.only({"pci", "tac", "arfcn"});
        t.pci = cell.get<std::uint16_t>("pci", t.pci);
        t.tac = cell.get<std::uint32_t>("tac", t.tac);
        t.arfcn = cell.get<std::uint32_t>("arfcn", t.arfcn);
        if (t.pci > 1007 || t.tac > 0xFFFFFF) {
            cell.fail("PCI 0..1007, TAC 24 bits");
        }

        const Yaml ues = y.at("ues");
        for (std::size_t i = 0; i < ues.size(); ++i) {
            const Yaml u = ues.at(i);
            u.only({"group", "count", "range", "card", "nssai", "imeisv_tac", "persona"});
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
            n.only({"socket", "netns", "cuup_netns", "parent", "prefix", "nodes", "ues"});
            t.netd.enabled = true;
            t.netd.socket = n.get<std::string>("socket", t.netd.socket);
            t.netd.netns = n.get<std::string>("netns", t.netd.netns);
            t.netd.cuup_netns = n.get<std::string>("cuup_netns", t.netd.cuup_netns);
            t.netd.nodes = n.get<bool>("nodes", true);
            t.netd.ues = n.get<bool>("ues", true);
            t.netd.parent = n.get<std::string>("parent", "");
            t.netd.prefix = n.get<std::uint8_t>("prefix", 24);
            if (t.netd.netns.rfind("ksim-", 0) != 0 || t.netd.cuup_netns.rfind("ksim-", 0) != 0 ||
                t.netd.cuup_netns == t.netd.netns || t.ng_bind.family != Endpoint::Family::v4 || t.netd.prefix > 32) {
                n.fail("netd needs a ksim- namespace, an IPv4 ng_bind and a prefix up to 32");
            }
        }
        if (y.has("security")) {
            y.at("security").only({"allow_null"});
            t.allow_null = y.at("security").get<bool>("allow_null", false);
        }
        return t;
    } catch (const YamlError& e) {
        why = e.what();
        return make_error(Errc::invalid_argument, 0, "the topology is not valid");
    }
}

} // namespace ksim::node
