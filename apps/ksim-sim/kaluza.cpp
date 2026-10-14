// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "kaluza.hpp"

#include <sys/stat.h>

#include <httplib.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>

#include "bundle.hpp"
#include "crypto/aead.hpp"
#include "platform/secret.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"

namespace ksim::sim {

namespace {

void wipe(std::string& s) noexcept {
    secure_zero(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size()));   // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    s.clear();
}

std::string imsi_at(const std::string& first, unsigned i) {
    std::string s = std::to_string(std::stoull(first) + i);
    return std::string(15 - s.size(), '0') + s;
}

struct Url {
    std::string host;
    int port = 443;
    std::string path;
};

std::optional<Url> parse_url(const std::string& u) {
    if (u.rfind("https://", 0) != 0) {
        return std::nullopt;
    }
    std::string rest = u.substr(8);
    Url out;
    const auto slash = rest.find('/');
    out.path = slash == std::string::npos ? "" : rest.substr(slash);
    rest = rest.substr(0, slash);
    const auto colon = rest.rfind(':');
    if (colon != std::string::npos) {
        out.port = std::stoi(rest.substr(colon + 1));
        rest = rest.substr(0, colon);
    }
    out.host = rest;
    return out.host.empty() ? std::nullopt : std::optional<Url>(out);
}

/// An owner-only credential file's contents (a trailing newline is dropped).
std::optional<std::string> read_secret_file(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0 || (st.st_mode & 077) != 0) {
        return std::nullopt;
    }
    std::ifstream in(path, std::ios::binary);
    std::string s{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
        s.pop_back();
    }
    return s;
}

std::string form_encode(const std::string& v) {
    std::string out;
    for (const char ch : v) {
        const auto c = static_cast<unsigned char>(ch);
        if (std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.' || c == '~') {
            out += ch;
        } else {
            static const char* hex = "0123456789ABCDEF";
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0xF];
        }
    }
    return out;
}

std::unique_ptr<httplib::SSLClient> client(const Url& u, const KaluzaApi& api, bool mtls) {
    std::unique_ptr<httplib::SSLClient> c;
    if (mtls) {
        c = std::make_unique<httplib::SSLClient>(u.host, u.port, api.cred_dir + "/tls-chain.pem", api.cred_dir + "/tls.key");
    } else {
        c = std::make_unique<httplib::SSLClient>(u.host, u.port);
    }
    c->set_ca_cert_path(api.cred_dir + "/root.pem");
    c->enable_server_certificate_verification(true);
    c->enable_server_hostname_verification(true);
    c->set_hostname_addr_map(api.resolve);
    c->set_connection_timeout(std::chrono::seconds(10));
    c->set_read_timeout(std::chrono::seconds(20));
    return c;
}

/// A bearer token, or nullopt (the reason on stderr, never the secret).
std::optional<std::string> token(const KaluzaApi& api) {
    auto u = parse_url(api.token_url);
    if (!u) {
        std::cerr << "ksim-sim: --token-url is https://host[:port]/path\n";
        return std::nullopt;
    }
    auto secret = read_secret_file(api.cred_dir + "/client-secret");
    if (!secret) {
        std::cerr << "ksim-sim: the client secret is missing or readable by others\n";
        return std::nullopt;
    }
    std::string body = "grant_type=client_credentials&client_id=" + form_encode(api.client_id) +
                       "&client_secret=" + form_encode(*secret);
    wipe(*secret);
    auto c = client(*u, api, api.token_mtls);
    auto res = c->Post(u->path, body, "application/x-www-form-urlencoded");
    wipe(body);
    if (!res || res->status != 200) {
        std::cerr << "ksim-sim: no token (HTTP " << (res ? res->status : 0) << ")\n";
        return std::nullopt;
    }
    auto j = nlohmann::json::parse(res->body, nullptr, false);
    std::string tok = j.is_object() && j.contains("access_token") && j["access_token"].is_string()
                          ? j["access_token"].get<std::string>()
                          : std::string();
    wipe(res->body);
    if (tok.empty()) {
        std::cerr << "ksim-sim: the token response has no access_token\n";
        return std::nullopt;
    }
    return tok;
}

} // namespace

int kaluza_provision(const std::string& first, unsigned count, const std::string& master_file, const KaluzaApi& api,
                     bool dry_run, bool replace) {
    auto master = uicc::secrets::load_kek(master_file);
    if (!master) {
        std::cerr << "ksim-sim: the range master: " << master.error().what << "\n";
        return 1;
    }
    if (dry_run) {
        for (unsigned i = 0; i < count; ++i) {
            const std::string imsi = imsi_at(first, i);
            auto sub = uicc::image::range_subscriber(imsi);
            std::cout << bundle(imsi, sub->msisdn, "<K>", "<OPc>", profile_for(imsi)).dump(2) << "\n";
        }
        return 0;
    }
    auto u = parse_url(api.udr_url);
    if (!u) {
        std::cerr << "ksim-sim: --udr-url is https://host:port\n";
        return 2;
    }
    auto tok = token(api);
    if (!tok) {
        return 1;
    }
    auto salt = crypto::aead::random_bytes(16);
    if (!salt) {
        return 1;
    }
    std::cout << "BATCH_SALT=" << to_hex(*salt) << "\n";
    auto c = client(*u, api, true);
    httplib::Headers h{{"Authorization", "Bearer " + *tok}};
    if (!replace) {
        h.emplace("If-None-Match", "*");
    }
    int failed = 0;
    for (unsigned i = 0; i < count; ++i) {
        const std::string imsi = imsi_at(first, i);
        auto sub = uicc::image::range_subscriber(imsi);
        const auto k = uicc::secrets::derive(*master, "K", imsi);
        const auto opc = uicc::secrets::derive(*master, "OPc", imsi);
        std::string kh = to_hex(k.expose());
        std::string oh = to_hex(opc.expose());
        std::string body = bundle(imsi, sub->msisdn, kh, oh, profile_for(imsi)).dump();
        wipe(kh);
        wipe(oh);
        auto res = c->Put(u->path + "/provisioning/v1/subscribers/imsi-" + imsi, h, body, "application/json");
        wipe(body);
        const int status = res ? res->status : 0;
        failed += status == 200 || status == 201 || status == 204 ? 0 : 1;
        std::cout << "UE_ID=imsi-" << imsi << " STATUS=" << status << " PROFILE=" << profile_for(imsi).name
                  << " K_FPR=" << uicc::secrets::key_fingerprint(*salt, k) << "\n";
    }
    for (auto& [name, v] : h) {
        wipe(v);
    }
    wipe(*tok);
    std::cout << "PROVISIONED=" << (count - static_cast<unsigned>(failed)) << "/" << count << "\n";
    return failed == 0 ? 0 : 1;
}

int kaluza_deprovision(const std::string& first, unsigned count, const KaluzaApi& api) {
    auto u = parse_url(api.udr_url);
    if (!u) {
        std::cerr << "ksim-sim: --udr-url is https://host:port\n";
        return 2;
    }
    auto tok = token(api);
    if (!tok) {
        return 1;
    }
    auto c = client(*u, api, true);
    httplib::Headers h{{"Authorization", "Bearer " + *tok}};
    int failed = 0;
    for (unsigned i = 0; i < count; ++i) {
        const std::string imsi = imsi_at(first, i);
        auto res = c->Delete(u->path + "/provisioning/v1/subscribers/imsi-" + imsi, h);
        const int status = res ? res->status : 0;
        failed += status == 204 || status == 404 ? 0 : 1;
        std::cout << "UE_ID=imsi-" << imsi << " STATUS=" << status << "\n";
    }
    for (auto& [name, v] : h) {
        wipe(v);
    }
    wipe(*tok);
    std::cout << "DEPROVISIONED=" << (count - static_cast<unsigned>(failed)) << "/" << count << "\n";
    return failed == 0 ? 0 : 1;
}

} // namespace ksim::sim
